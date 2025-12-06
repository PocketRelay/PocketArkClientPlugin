use log::debug;

pub mod host_lookup;
pub mod mem;

/// Applies all hooks
#[allow(clippy::missing_safety_doc)]
pub unsafe fn apply_hooks() {
    debug!("apply host lookup");
    host_lookup::hook_host_lookup();
    debug!("all hooks applied")
}
