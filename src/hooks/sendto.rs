use log::{debug, error, warn};
use pocket_ark_client_shared::servers::HTTP_PORT;
use pocket_ark_client_shared::virtual_peer::{get_virtual_peer_address, is_virtual_peer_address};
use retour::GenericDetour;
use std::mem::size_of;
use std::{ffi::CStr, sync::LazyLock};
use windows_sys::Win32::Networking::WinSock::IN_ADDR_0_0;
use windows_sys::Win32::{
    Networking::WinSock::{connect, AF_INET, SOCKADDR, SOCKADDR_IN, SOCKET},
    System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
};

use crate::virtual_peer::tunnel_port_by_slot;

type SendToFn = unsafe extern "system" fn(SOCKET, *const u8, i32, i32, *const SOCKADDR, i32) -> i32;

static HOOK_SENDTO: LazyLock<GenericDetour<SendToFn>> = LazyLock::new(|| {
    let ws2_32 = unsafe { GetModuleHandleA(b"ws2_32.dll\0".as_ptr()) };
    if ws2_32 == 0 {
        panic!("Failed to obtain handle for ws2_32.dll");
    }

    let target_addr = unsafe { GetProcAddress(ws2_32, b"sendto\0".as_ptr()) };
    let Some(target_fn) = target_addr else {
        panic!("Failed to locate address of connect() inside ws2_32.dll");
    };

    let ori: SendToFn = unsafe { std::mem::transmute(target_addr) };
    return unsafe { GenericDetour::new(ori, fake_sendto).unwrap() };
});

#[no_mangle]
pub unsafe extern "system" fn fake_sendto(
    s: SOCKET,
    buf: *const u8,
    len: i32,
    flags: i32,
    name: *const SOCKADDR,
    namelen: i32,
) -> i32 {
    if !name.is_null() && namelen as usize >= size_of::<SOCKADDR_IN>() {
        let name = name as *mut SOCKADDR_IN;
        let sockaddr_in = name.as_mut_unchecked();

        if sockaddr_in.sin_family == AF_INET {
            let bytes = &mut sockaddr_in.sin_addr.S_un.S_un_b;
            let port = u16::from_be(sockaddr_in.sin_port);

            // debug!(
            //     "sendto attempt to {}.{}.{}.{}:{}",
            //     bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4, port
            // );

            // Virtual peer addresses are routed based on slot to the correct tunnel port
            if is_virtual_peer_address(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4, port) {
                let slot = get_virtual_peer_address(bytes.s_b4);
                let tunnel_port = tunnel_port_by_slot(slot);
                // debug!(
                //     "tunnel port for {}.{}.{}.{}:{} slot = {} port = {:?}",
                //     bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4, port, slot, tunnel_port
                // );
                if let Some(tunnel_port) = tunnel_port {
                    bytes.s_b1 = 127;
                    bytes.s_b2 = 0;
                    bytes.s_b3 = 0;
                    bytes.s_b4 = 1;
                    sockaddr_in.sin_port = tunnel_port.to_be();
                }
            }
        }
    }

    HOOK_SENDTO.call(s, buf, len, flags, name, namelen)
}

/// Hooks the sendto() function from ws2_32.dll to override the port that
/// clients send udp traffic to, this is a fix for tunneling udp connections
/// since MEA doesn't support dedicated server mode
pub unsafe fn hook() {
    HOOK_SENDTO.enable();
}
