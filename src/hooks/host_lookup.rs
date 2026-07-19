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

/// Static localhost hostname to use for faking
static LOCALHOST_NODE_NAME: &'static CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"localhost\0") };

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

        // Call the underlying implementation but using localhost instead of the requested address
        // this is better than leaking memory ourselves since it ensures the correct response always
        // and prevents unbounded memory growth
        return HOOK_GET_ADDR_INFO.call(
            LOCALHOST_NODE_NAME.as_ptr().cast(),
            pservicename,
            phints,
            ppresult,
        );
    }

    // Fallback to default implementation
    HOOK_GET_ADDR_INFO.call(pnodename, pservicename, phints, ppresult)
}

pub unsafe fn hook_host_lookup() {
    HOOK_GET_ADDR_INFO.enable();
}
