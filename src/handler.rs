// SPDX-FileCopyrightText: 2023-2025 erdnaxe
// SPDX-License-Identifier: MIT

use crate::pow;
use crate::Args;

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use command_group::AsyncCommandGroup;
use log::debug;
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
        if in_buf[0] == 3 {
            debug!("Client sent Ctrl-C");
            return Ok(());
        }
        debug!("Writting to stdin: {:?}", &in_buf[0..n]);
        child_stdin
            .write_all(&in_buf[0..n])
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
        socket
            .write_all(&out_buf[0..n])
            .await
            .context("Failed to write to socket")?;
    }
}

/// Handle one incoming client
///
/// Spawn one process and then spawn 3 tasks to manage input, output and
/// timeout. If one of these tasks reach its end, kill the process.
pub async fn handle_client(mut socket: TcpStream, args: Args) -> Result<()> {
    // Send message of the day
    if let Some(motd) = &args.motd {
        socket.write_all(motd.as_bytes()).await?;
        socket.write_all(b"\r\n").await?;
    }

    // Proof-of-work prompt
    if args.pow > 0 {
        let valid = pow::proof_of_work_prompt(&mut socket, args.pow, &args.pow_backdoor).await?;
        if !valid {
            return Ok(());
        }
    }

    // Start command
    let mut command = Command::new(&args.command);
    command.args(&args.arguments);
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = command.group_spawn().context("Failed to run command")?;
    let child_stdin = child.inner().stdin.take().context("Failed to open stdin")?;
    let child_stdout = child
        .inner()
        .stdout
        .take()
        .context("Failed to open stdout")?;

    // Start tasks
    let mut set = JoinSet::new();
    let (read_half, write_half) = socket.into_split();
    set.spawn(async move { process_stdin(read_half, child_stdin).await });
    set.spawn(async move { process_stdout(write_half, child_stdout).await });
    if let Some(timeout) = args.timeout {
        set.spawn(async move {
            sleep(Duration::from_secs(timeout)).await;
            debug!("Timeout reached");
            Ok(())
        });
    }

    // If one task exits, drop the others
    // Child group should always be killed before dropping child handle.
    let res = set.join_next().await;
    child.kill().await.context("Failed to kill process group")?;
    res.unwrap_or(Ok(Ok(())))?
}
