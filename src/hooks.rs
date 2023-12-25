use log::{debug, error, warn};
use pocket_ark_client_shared::servers::has_server_tasks;
use std::{ffi::CStr, mem::size_of, ptr::null_mut};
use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, FALSE},
        Networking::WinSock::{getaddrinfo, ADDRINFOA, AF_INET, SOCKADDR},
        System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
    },
};

/// Address to start matching from
const HOST_LOOKUP_START_OFFSET: usize = 0x0000000140100000;
/// Address to end matching at
const HOST_LOOKUP_END_OFFSET: usize = 0x0000000200000000;
/// Mask to use while matching the opcodes below
const HOST_LOOKUP_MASK: &str = "xx????xxxxxxxxxxxxxxxxx";
/// Op codes to match against
const HOST_LOOKUP_OP_CODES: &[u8] = &[
    0xFF, 0x15, 0x10, 0x09, 0xE9, 0x01, // call   QWORD PTR [rip+0x1e90910]
    0x85, 0xC0, // test eax,eax
    0x75, 0x52, // jne  0x5c
    0x48, 0x8B, 0x44, 0x24, 0x68, // mov rax,QWORD PTR [rsp+0x68]
    0x48, 0x8D, 0x53, 0x18, // lea rdx, [rbx+0x18]
    0x4C, 0x8B, 0x40, 0x20, // mov r8, QWORD PTR [rax+0x20]
];

/// Allocates the provided object on the heap, leaking it
/// immedately. Used by `fake_getaddrinfo` since the `freeaddrinfo`
/// function takes care of cleaning up the allocated memory
#[inline]
fn heap_alloc<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

#[no_mangle]
pub unsafe extern "system" fn fake_getaddrinfo(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    // Derive the safe name from the str bytes
    let nodename = CStr::from_ptr(pnodename.cast());
    debug!("Host lookup: {:?}", nodename);

    if nodename.to_bytes() == b"winter15.gosredirector.ea.com" && has_server_tasks() {
        debug!("Responding with localhost redirect");

        let hinits = &*phints;

        // Create the socket address
        let addr = heap_alloc(SOCKADDR {
            sa_family: AF_INET,
            sa_data: [0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        });

        // Create the address info response
        let addr_info = heap_alloc(ADDRINFOA {
            ai_flags: 0,
            ai_family: AF_INET as i32,
            ai_socktype: hinits.ai_socktype,
            ai_protocol: hinits.ai_protocol,
            ai_addrlen: std::mem::size_of::<SOCKADDR>(),
            ai_canonname: null_mut(),
            ai_addr: addr,
            ai_next: null_mut(),
        });

        // Set the result
        *ppresult = addr_info;

        return 0;
    }

    // Fallback to default implementation
    getaddrinfo(pnodename, pservicename, phints, ppresult)
}

/// Hooks the `getaddrinfo` function to handle replacing host
/// lookups with localhost for hijacking requests.
///
/// Last known address (In decrypted copy): 00 00 7F FE B6 5C 3C E0
pub unsafe fn hook_host_lookup() {
    // Attempt to find the calling pattern
    let Some(addr) = find_pattern(
        HOST_LOOKUP_START_OFFSET,
        HOST_LOOKUP_END_OFFSET,
        HOST_LOOKUP_MASK,
        HOST_LOOKUP_OP_CODES,
    ) else {
        warn!("Failed to find getaddrinfo call hook position");
        return;
    };

    debug!("Found getaddrinfo call @ {:#016x}", addr as usize);

    // Find the relative jump distance
    let distance = *(addr.add(2 /* Skip call opcode */) as *const u32);

    // Get a pointer to the value in the thunk table (Points to the actual function address)
    let thunk_addr = addr.add(6 /* Skip call opcode + address */ + distance as usize);

    use_memory(thunk_addr, size_of::<usize>(), |addr| {
        // Replace the address with our faker function
        let ptr: *mut usize = addr as *mut usize;
        *ptr = fake_getaddrinfo as usize;
    });
}

/// Compares the opcodes after the provided address using the provided
/// opcode and pattern
///
/// ## Safety
///
/// Reading program memory is *NOT* safe but its required for pattern matching
///
/// ## Arguments
/// * addr     - The address to start matching from
/// * mask     - The mask to use when matching opcodes
/// * op_codes - The op codes to match against
unsafe fn compare_mask(addr: *const u8, mask: &'static str, op_codes: &'static [u8]) -> bool {
    mask.chars()
        .enumerate()
        // Merge the iterator with the opcodes for matching
        .zip(op_codes.iter().copied())
        // Compare the mask and memory at the address with the op codes
        .all(|((offset, mask), op)| mask == '?' || *addr.add(offset) == op)
}

/// Attempts to find a matching pattern anywhere between the start and
/// end offsets
///
/// ## Safety
///
/// Reading program memory is *NOT* safe but its required for pattern matching
///
/// ## Arguments
/// * start_offset - The address to start matching from
/// * end_offset   - The address to stop matching at
/// * mask         - The mask to use when matching opcodes
/// * op_codes     - The op codes to match against
unsafe fn find_pattern(
    start_offset: usize,
    end_offset: usize,
    mask: &'static str,
    op_codes: &'static [u8],
) -> Option<*const u8> {
    // Iterate between the offsets
    (start_offset..=end_offset)
        // Cast the address to a pointer type
        .map(|addr| addr as *const u8)
        // Compre the mask at the provided address
        .find(|addr| compare_mask(*addr, mask, op_codes))
}

/// Attempts to apply virtual protect READ/WRITE access
/// over the memory at the provided address for the length
/// provided. Restores the original flags after the action
/// is complete
///
/// ## Safety
///
/// This function acquires the proper write permissions over
/// `addr` for the required `length` but it is unsound if
/// memory past `length` is accessed
///
/// ## Arguments
/// * addr - The address to protect
/// * length - The protected region
/// * action - The aciton to execute on the memory
#[inline]
unsafe fn use_memory<F, P>(addr: *const P, length: usize, action: F)
where
    F: FnOnce(*mut P),
{
    // Tmp variable to store the old state
    let mut old_protect: PAGE_PROTECTION_FLAGS = 0;

    // Apply the new read write flags
    if VirtualProtect(addr.cast(), length, PAGE_READWRITE, &mut old_protect) == FALSE {
        let error = GetLastError();

        error!(
            "Failed to protect memory region @ {:#016x} length {} error: {:#4x}",
            addr as usize, length, error
        );
        return;
    }

    // Apply the action on the now mutable memory area
    action(addr.cast_mut());

    // Restore the original flags
    VirtualProtect(addr.cast(), length, old_protect, &mut old_protect);
}
