use log::{debug, error, warn};
use pocket_ark_client_shared::servers::HTTP_PORT;
use retour::GenericDetour;
use std::mem::size_of;
use std::{ffi::CStr, sync::LazyLock};
use windows_sys::Win32::{
    Networking::WinSock::{connect, AF_INET, SOCKADDR, SOCKADDR_IN, SOCKET},
    System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
};

type ConnectFn = unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;

static HOOK_CONNECT: LazyLock<GenericDetour<ConnectFn>> = LazyLock::new(|| {
    let ws2_32 = unsafe { GetModuleHandleA(b"ws2_32.dll\0".as_ptr()) };
    if ws2_32 == 0 {
        panic!("Failed to obtain handle for ws2_32.dll");
    }

    let target_addr = unsafe { GetProcAddress(ws2_32, b"connect\0".as_ptr()) };
    let Some(target_fn) = target_addr else {
        panic!("Failed to locate address of connect() inside ws2_32.dll");
    };

    let ori: ConnectFn = unsafe { std::mem::transmute(target_addr) };
    return unsafe { GenericDetour::new(ori, fake_connect).unwrap() };
});

#[no_mangle]
pub unsafe extern "system" fn fake_connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    if !name.is_null() && namelen as usize >= size_of::<SOCKADDR_IN>() {
        let name = name as *mut SOCKADDR_IN;
        let sockaddr_in = name.as_mut_unchecked();

        if sockaddr_in.sin_family == AF_INET {
            let bytes = sockaddr_in.sin_addr.S_un.S_un_b;
            let port = u16::from_be(sockaddr_in.sin_port);
            if bytes.s_b1 == 127
                && bytes.s_b2 == 0
                && bytes.s_b3 == 0
                && bytes.s_b4 == 1
                && port == 443
            {
                let port: u16 = HTTP_PORT;
                sockaddr_in.sin_port = port.to_be();
            }
        }
    }

    HOOK_CONNECT.call(s, name, namelen)
}

/// Hooks the connect() function from ws2_32.dll to override the port that
/// clients connect to, this is a fix for linux clients who cannot bind
/// port 443 due to security restrictions. This hook redirects
/// connections from 127.0.0.1:443 to 127.0.0.1:8443
pub unsafe fn hook() {
    HOOK_CONNECT.enable();
}
