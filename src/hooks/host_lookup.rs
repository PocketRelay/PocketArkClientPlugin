use log::{debug, warn};
use pocket_ark_client_shared::servers::has_server_tasks;
use retour::GenericDetour;
use std::{ffi::CStr, mem::size_of, ptr::null_mut, sync::LazyLock};
use windows_sys::{
    core::PCSTR,
    Win32::{
        Networking::WinSock::{getaddrinfo, ADDRINFOA, AF_INET, SOCKADDR},
        System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

use crate::hooks::mem::{find_pattern, use_memory};

type GetAddrInfoFn =
    unsafe extern "system" fn(PCSTR, PCSTR, *const ADDRINFOA, *mut *mut ADDRINFOA) -> i32;

static HOOK_GET_ADDR_INFO: LazyLock<GenericDetour<GetAddrInfoFn>> = LazyLock::new(|| {
    let ws2_32 = unsafe { GetModuleHandleA(b"ws2_32.dll\0".as_ptr()) };
    if ws2_32 == 0 {
        panic!("Failed to obtain handle for ws2_32.dll");
    }

    let target_addr = unsafe { GetProcAddress(ws2_32, b"getaddrinfo\0".as_ptr()) };
    let Some(target_fn) = target_addr else {
        panic!("Failed to locate address of getaddrinfo() inside ws2_32.dll");
    };

    let ori: GetAddrInfoFn = unsafe { std::mem::transmute(target_addr) };
    return unsafe { GenericDetour::new(ori, fake_getaddrinfo).unwrap() };
});

/// Allocates the provided object on the heap, leaking it
/// immediately. Used by `fake_getaddrinfo` since the `freeaddrinfo`
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
    HOOK_GET_ADDR_INFO.call(pnodename, pservicename, phints, ppresult)
}

pub unsafe fn hook_host_lookup() {
    HOOK_GET_ADDR_INFO.enable();
}
