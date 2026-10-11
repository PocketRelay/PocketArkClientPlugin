use parking_lot::Mutex;

static TUNNEL_UDP_PORTS: Mutex<Option<[u16; 4]>> = Mutex::new(None);

pub fn tunnel_ports_callback(ports: [u16; 4]) {
    let mut state = TUNNEL_UDP_PORTS.lock();
    *state = Some(ports);
}

pub fn tunnel_port_by_slot(slot: u8) -> Option<u16> {
    if slot > 3 {
        return None;
    }

    let index = slot as usize;
    let ports = TUNNEL_UDP_PORTS.lock();
    let ports = ports.as_ref()?;
    ports.get(index).copied()
}
