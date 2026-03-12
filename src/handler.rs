// SPDX-FileCopyrightText: 2023-2025 erdnaxe
// SPDX-License-Identifier: MIT

use crate::Args;
use crate::pow;
use crate::proxy;

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use command_group::AsyncCommandGroup;
use log::{debug, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::time::sleep;

/// Handle message exchange from TCP socket to process stdin
async fn process_stdin<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut socket: R,
    mut child_stdin: W,
) -> Result<()> {
    let mut in_buf = [0; 1024];
    loop {
        let n = socket.read(&mut in_buf).await?;
        if n == 0 {
            return Ok(()); // socket closed
        }
        let data = in_buf.get(..n).context("stdin read index out of bounds")?;
        debug!("Writting to stdin: {data:?}");
        child_stdin
            .write_all(data)
            .await
            .context("Failed to write to stdin")?;
    }
}

/// Handle message exchange from process stdout to TCP socket
async fn process_stdout<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut socket: W,
    mut child_stdout: R,
) -> Result<()> {
    let mut out_buf = [0; 1024];
    loop {
        let n = child_stdout.read(&mut out_buf).await?;
        if n == 0 {
            return Ok(()); // process closed
        }
        let data = out_buf
            .get(..n)
            .context("stdout read index out of bounds")?;
        debug!("Reading from stdout: {data:?}");
        socket
            .write_all(data)
            .await
            .context("Failed to write to socket")?;
    }
}

/// Handle one incoming client
///
/// Spawn one process and then spawn 3 tasks to manage input, output and
/// timeout. If one of these tasks reach its end, kill the process.
pub async fn handle_client(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    args: Args,
) -> Result<Option<proxy::ProxyInfo>> {
    // Parse PROXY protocol header if enabled
    let proxy_info = if args.proxy_protocol {
        match proxy::parse_proxy_v2_header(&mut socket).await {
            Ok(proxy::ProxyHeader::Proxied(info)) => {
                info!(
                    "Client: {}:{} (via proxy {}) connected",
                    info.src_addr, info.src_port, peer_addr
                );
                Some(info)
            }
            Ok(proxy::ProxyHeader::Local) => {
                debug!("PROXY protocol LOCAL command");
                None
            }
            Err(e) => {
                warn!("Rejecting connection from {peer_addr} due to PROXY protocol error: {e:?}");
                return Err(e);
            }
        }
    } else {
        None
    };

    // MOTD
    if let Some(motd) = &args.motd {
        socket.write_all(motd.as_bytes()).await?;
        socket.write_all(b"\r\n").await?;
    }

    // Proof-of-work
    if args.pow > 0 {
        let valid =
            pow::proof_of_work_prompt(&mut socket, args.pow, args.pow_backdoor.as_ref()).await?;
        if !valid {
            return Ok(proxy_info);
        }
    }

    // Start command
    let mut command = Command::new(&args.command);
    command.args(&args.arguments);
    command.stdin(Stdio::piped()).stdout(Stdio::piped());

    if let Some(ref proxy_info) = proxy_info {
        command.env("CLIENT_IP", proxy_info.src_addr.to_string());
        command.env("CLIENT_PORT", proxy_info.src_port.to_string());
        command.env("PROXY_DEST_IP", proxy_info.dst_addr.to_string());
        command.env("PROXY_DEST_PORT", proxy_info.dst_port.to_string());
    }

    let mut child = command.group_spawn().context("Failed to run command")?;

    let child_stdin = child.inner().stdin.take().context("Failed to open stdin")?;
    let child_stdout = child
        .inner()
        .stdout
        .take()
        .context("Failed to open stdout")?;

    // Split socket
    let (read_half, write_half) = socket.into_split();

    let mut set = JoinSet::new();

    set.spawn(async move { process_stdin(read_half, child_stdin).await });

    set.spawn(async move { process_stdout(write_half, child_stdout).await });

    let session_timeout = args.timeout.map(Duration::from_secs);

    if let Some(timeout) = session_timeout {
        set.spawn(async move {
            sleep(timeout).await;
            debug!("Timeout reached");
            Ok(())
        });
    }

    // Wait for first task to finish
    let res = set.join_next().await;

    // Cancel remaining tasks immediately
    set.abort_all();

    // Kill the process group
    child.kill().await.context("Failed to kill process group")?;

    // Await child to avoid zombie process
    let _ = child.wait().await;

    res.unwrap_or(Ok(Ok(())))??;
    Ok(proxy_info)
}
