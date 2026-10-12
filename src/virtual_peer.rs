use parking_lot::Mutex;

/// Currently active UDP ports for the tunneling sockets
static TUNNEL_UDP_PORTS: Mutex<Option<[u16; 4]>> = Mutex::new(None);

/// Callback invoked when the tunnel ports are allocated
pub fn tunnel_ports_callback(ports: [u16; 4]) {
    let mut state = TUNNEL_UDP_PORTS.lock();
    *state = Some(ports);
}

/// Request the tunnel port for a specific player `slot` if
/// one is available
pub fn tunnel_port_by_slot(slot: u8) -> Option<u16> {
    if slot > 3 {
        return None;
    }

    let index = slot as usize;
    let ports = TUNNEL_UDP_PORTS.lock();
    let ports = ports.as_ref()?;
    ports.get(index).copied()
}
