use core::{api::create_http_client, reqwest::Client};
use pocket_ark_client_shared as core;

pub mod config;
pub mod hooks;
pub mod servers;
pub mod ui;

/// Testing startup entry pointer for fast UI debugging
fn main() {
    // Initialize logging
    env_logger::builder()
        .filter_module("pocket_ark_client_plugin", log::LevelFilter::Debug)
        .init();

    // Create the internal HTTP client
    let client: Client = create_http_client(None).expect("Failed to create HTTP client");

    // Initialize the UI
    ui::init(None, client);
}
