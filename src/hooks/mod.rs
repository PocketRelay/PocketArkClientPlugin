use log::debug;

pub mod connect;
pub mod host_lookup;
pub mod mem;
pub mod sendto;

/// Applies all hooks
#[allow(clippy::missing_safety_doc)]
pub unsafe fn apply_hooks() {
    debug!("apply host lookup");
    host_lookup::hook_host_lookup();
    debug!("apply connect");
    connect::hook();
    debug!("apply sendto");
    sendto::hook();
    debug!("all hooks applied");
}
