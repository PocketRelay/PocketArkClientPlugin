use crate::{
    core::{servers::*, ssl::create_ssl_context},
    ui::error_message,
};
use log::error;
use pocket_ark_client_shared::ctx::ClientContext;
use std::{future::Future, sync::Arc};

/// Starts all the servers in their own tasks
///
/// ## Arguments
/// * `ctx` - The client context
pub fn start_all_servers(ctx: Arc<ClientContext>) {
    // Stop existing servers and tasks if they are running
    stop_server_tasks();

    let ssl_context = create_ssl_context().expect("Failed to create ssl context");

    // Spawn redirector server
    let redirector = redirector::start_redirector_server(ssl_context.clone());
    run_server(redirector, "redirector");

    // Spawn the Blaze server
    let blaze = blaze::start_blaze_server(ctx.clone());

    run_server(blaze, "blaze");

    // Spawn HTTP server
    let http = http::start_http_server(ctx.clone(), ssl_context);
    run_server(http, "http");

    // Spawn the QoS server
    let qos = qos::start_qos_server();
    run_server(qos, "qos");

    // Spawn the tunneling server
    let tunnel = start_tunnel_server(ctx);
    run_server(tunnel, "tunnel");
}

/// Runs the tunnel server, if a tunnel port is available a UDP tunnel will be
/// attempted, if that fails or a tunnel port is unavailable an HTTP tunnel
/// will be attempted instead
async fn start_tunnel_server(ctx: Arc<ClientContext>) -> std::io::Result<()> {
    // Spawn tunnel server
    match ctx.tunnel_port {
        // When UDP tunnel server port is available use the faster UDP tunnel server
        Some(tunnel_port) => {
            let err = match udp_tunnel::start_udp_tunnel_server(ctx.clone(), tunnel_port).await {
                // Encountered error with UDP tunnel
                Err(err) => err,
                // Server exited normally
                Ok(_) => return Ok(()),
            };

            error!(
                "error using UDP tunnel, falling back to HTTP tunnel: {}",
                err
            );

            // Error while connecting UDP tunnel, fallback to HTTP upgrade tunnel
            tunnel::start_tunnel_server(ctx).await
        }
        // When unavailable fallback to the HTTP upgrade tunnel
        None => tunnel::start_tunnel_server(ctx).await,
    }
}

/// Runs the provided server `future` in a background task displaying
/// and logging any errors if they occur
#[inline]
pub fn run_server<F>(future: F, name: &'static str)
where
    F: Future<Output = std::io::Result<()>> + Send + 'static,
{
    spawn_server_task(async move {
        if let Err(err) = future.await {
            error_message(&format!("Failed to start {name} server"), &err.to_string());
            error!("Failed to start {name} server: {err}");
        }
    });
}
