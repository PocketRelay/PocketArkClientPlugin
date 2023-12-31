#![allow(clippy::missing_safety_doc)]

use config::read_config_file;
use core::{
    api::create_http_client,
    api::read_client_identity,
    reqwest::{self, Client},
};
use log::error;
use pocket_ark_client_shared as core;
use std::path::Path;
use ui::{confirm_message, error_message};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

pub mod config;
pub mod hooks;
pub mod servers;
pub mod ui;

/// Constant storing the application version
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Handles the plugin being attached to the game
fn attach() {
    // Debug allocates a console window to display output
    #[cfg(debug_assertions)]
    {
        unsafe { windows_sys::Win32::System::Console::AllocConsole() };
    }

    // Initialize logging
    env_logger::builder()
        .filter_module("pocket_ark_client_plugin", log::LevelFilter::Debug)
        .init();

    // Apply the host lookup hook
    unsafe { hooks::hook_host_lookup() };

    // Load the config file
    let config = read_config_file();

    // Load the client identity if one is present
    let identity = load_identity();

    // Create the internal HTTP client
    let client: Client = create_http_client(identity).expect("Failed to create HTTP client");

    // Start the UI in a new thread
    std::thread::spawn(move || {
        // Initialize the UI
        ui::init(config, client);
    });
}

/// Handles the plugin being deta   ched from the game, this handles
/// cleaning up any extra allocated resources
fn detach() {
    // Debug console must be freed on detatch
    #[cfg(debug_assertions)]
    {
        unsafe {
            windows_sys::Win32::System::Console::FreeConsole();
        }
    }
}

/// Attempts to load an identity file if one is present
pub fn load_identity() -> Option<reqwest::Identity> {
    // Load the client identity
    let identity_file = Path::new("pocket-ark-identity.p12");

    // Handle no identity or user declining identity
    if !identity_file.exists() || !confirm_message(
        "Found client identity",
        "Detected client identity pocket-ark-identity.p12, would you like to use this identity?",
    ) {
        return None;
    }

    // Read the client identity
    match read_client_identity(identity_file) {
        Ok(value) => Some(value),
        Err(err) => {
            error!("Failed to set client identity: {}", err);
            error_message("Failed to set client identity", &err.to_string());
            None
        }
    }
}

/// Windows DLL entrypoint for the plugin
#[no_mangle]
extern "stdcall" fn DllMain(_hmodule: isize, reason: u32, _: *mut ()) -> bool {
    match reason {
        // Handle attaching
        DLL_PROCESS_ATTACH => attach(),
        // Handle detaching
        DLL_PROCESS_DETACH => detach(),
        _ => {}
    }

    true
}
