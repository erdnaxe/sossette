// SPDX-FileCopyrightText: 2023-2025 erdnaxe
// SPDX-License-Identifier: MIT

mod handler;
mod pow;

use anyhow::{Context, Result};
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use log::{error, info, warn};

use tokio::net::TcpListener;

/// Online CTF challenge wrapper
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None, trailing_var_arg = true)]
struct Args {
    /// Listen on this address
    #[arg(short, long, value_name = "IP:PORT", env = "WRAPPER_LISTEN")]
    listen: String,

    /// Kill COMMAND if still running after DURATION seconds
    #[arg(short, long, value_name = "DURATION", env = "WRAPPER_TIMEOUT")]
    timeout: Option<u64>,

    /// Print MESSAGE before running COMMAND
    #[arg(short, long, value_name = "MESSAGE", env = "WRAPPER_MOTD")]
    motd: Option<String>,

    /// Proof-of-work length, zero disables it
    #[arg(long, value_name = "LEN", env = "WRAPPER_POW", default_value_t = 0)]
    pow: u32,

    /// Proof-of-work backdoor, to let staff skip proof-of-work computation
    #[arg(long, value_name = "STRING", env = "WRAPPER_POW_BACKDOOR")]
    pow_backdoor: Option<String>,

    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    /// Command to run
    command: String,

    /// Arguments to pass to command
    arguments: Vec<String>,
}

/// Listen for incoming TCP connections
async fn serve(args: Args) -> Result<()> {
    let listener = TcpListener::bind(&args.listen)
        .await
        .context("Failed to bind TCP listener")?;
    info!("Listening on {}", args.listen);
    loop {
        // See https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html#errors
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                info!("Client {:?} connected", peer_addr);

                // Spawn task to handle this client
                let my_args = args.clone();
                tokio::spawn(async move {
                    match handler::handle_client(socket, my_args).await {
                        Ok(()) => {
                            info!("Client {:?} disconnected", peer_addr)
                        }
                        Err(e) => {
                            warn!("Handling client {:?} failed: {:?}", peer_addr, e)
                        }
                    }
                });
            }
            Err(e) => warn!("Unable to accept client: {:?}", e),
        }
    }
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();
    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    // Spawn TCP server
    tokio::spawn(async move {
        match serve(args).await {
            Ok(()) => info!("Server stopped gracefully"),
            Err(e) => error!("Server stopped due to an error: {:?}", e),
        }
    });

    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(err) => {
            warn!("Unable to listen for shutdown signal: {}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        crate::Args::command().debug_assert()
    }
}
