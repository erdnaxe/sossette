// SPDX-FileCopyrightText: 2023-2025 erdnaxe
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POW_HEADER_MESSAGE: &[u8] = b"= Proof of Work protection =\r\n\
To launch this challenge, you need to solve a proof-of-work.\r\n\
More details can be found on <https://fcsc.fr/pow>.\r\n";

/// Proof-of-Work prompt
///
/// Ask client to solve a hard challenge. This is used as anti-DDoS protection.
pub async fn proof_of_work_prompt<S: AsyncReadExt + AsyncWriteExt + std::marker::Unpin>(
    socket: &mut S,
    difficulty: u32,
    backdoor: Option<&String>,
) -> Result<bool> {
    // Generate prefix using OS random
    let prefix: [u8; 16] = thread_rng()
        .sample_iter(Alphanumeric)
        .take(16)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .context("Failed to generate random prefix")?;

    // Prompt user
    socket.write_all(POW_HEADER_MESSAGE).await?;
    let prompt = format!("Please provide an ASCII printable string S such that SHA256({} || S) starts with {} bits equal to 0 (the string concatenation is denoted ||): ", String::from_utf8(prefix.into())?, difficulty);
    socket.write_all(prompt.as_bytes()).await?;
    let mut buf = [0u8; 256];
    let mut buf_n: usize = 0;
    while buf_n < 256 {
        let byte = buf
            .get_mut(buf_n..=buf_n)
            .context("read index out of bounds")?;
        let n = socket.read(byte).await?;
        if n == 0 {
            return Ok(false); // socket closed
        }
        let current = *buf.get(buf_n).context("index out of bounds")?;
        if current == b'\x03' {
            return Ok(false); // Ctrl-C
        }
        if current == b'\0' || current == b'\n' {
            break; // telnet uses \r\0, netcat \r\n
        }
        if !(32..127).contains(&current) {
            continue; // ignore non ascii printable
        }
        buf_n = buf_n.checked_add(n).context("buffer index overflow")?;
    }

    // Trim trailing carriage return
    if buf_n > 0 {
        let last = *buf.get(buf_n.checked_sub(1).context("underflow")?).context("index out of bounds")?;
        if last == b'\r' {
            buf_n = buf_n.checked_sub(1).context("underflow")?;
        }
    }

    // Get the user input as a slice
    let suffix = buf.get(..buf_n).context("slice out of bounds")?;

    // Check backdoor
    if let Some(bd) = backdoor && suffix == bd.as_bytes() {
            return Ok(true);
    }

    // Verify proof of work
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(suffix);
    let hash = hasher.finalize();
    Ok(check_leading_zeros(&hash, difficulty))
}

/// Check that the hash starts with at least `difficulty` zero bits
fn check_leading_zeros(hash: &[u8], difficulty: u32) -> bool {
    let mut remaining = difficulty;
    for &byte in hash {
        if remaining == 0 {
            return true;
        }
        if remaining >= 8 {
            if byte != 0 {
                return false;
            }
            remaining = remaining.saturating_sub(8);
        } else {
            // Check the top `remaining` bits of this byte
            let mask = 0xFF_u8
                .checked_shl(8_u32.saturating_sub(remaining))
                .unwrap_or(0);
            return byte & mask == 0;
        }
    }
    remaining == 0
}
