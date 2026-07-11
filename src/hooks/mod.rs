use log::debug;

pub mod connect;
pub mod host_lookup;
pub mod mem;

/// Applies all hooks
#[allow(clippy::missing_safety_doc)]
pub unsafe fn apply_hooks() {
    debug!("apply host lookup");
    host_lookup::hook_host_lookup();
    debug!("apply connect");
    connect::hook();
    debug!("all hooks applied");
}
