// SPDX-FileCopyrightText: 2023-2025 erdnaxe
// SPDX-License-Identifier: MIT

use anyhow::Result;
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
    backdoor: &Option<String>,
) -> Result<bool> {
    // Generate prefix using OS random
    let prefix: [u8; 16] = thread_rng()
        .sample_iter(Alphanumeric)
        .take(16)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();

    // Prompt user
    socket.write_all(POW_HEADER_MESSAGE).await?;
    let prompt = format!("Please provide an ASCII printable string S such that SHA256({} || S) starts with {} bits equal to 0 (the string concatenation is denoted ||): ", String::from_utf8(prefix.into())?, difficulty);
    socket.write_all(prompt.as_bytes()).await?;
    let mut buf = [0; 256];
    let mut buf_n = 0;
    while buf_n < 256 {
        let n = socket.read(&mut buf[buf_n..buf_n + 1]).await?;
        if n == 0 || buf[buf_n] == b'\x03' {
            return Ok(false); // socket closed or Ctrl-C
        }
        if buf[buf_n] == b'\0' || buf[buf_n] == b'\n' {
            break; // telnet uses \r\0, netcat \r\n
        }
        if buf[buf_n] >= 127 || buf[buf_n] < 32 {
            continue; // ignore non ascii printable
        }
        buf_n += n;
    }
    while buf_n > 0
        && (buf[buf_n - 1] == b'\n' || buf[buf_n - 1] == b'\r' || buf[buf_n - 1] == b'\0')
    {
        buf_n -= 1; // trim input
    }

    // Backdoor for staff testing
    if let Some(backdoor_str) = backdoor {
        if backdoor_str.as_bytes() == &buf[..buf_n] {
            return Ok(true);
        }
    }

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(&buf[..buf_n]);
    let hash: [u8; 32] = hasher.finalize().into();

    // Count zeros
    let mut measured_difficulty = 0;
    for hash_byte in hash.iter() {
        if *hash_byte == 0 {
            measured_difficulty += 8;
        } else {
            measured_difficulty += hash_byte.leading_zeros();
            break;
        }
    }

    if measured_difficulty < difficulty {
        let message = format!(
            "Wrong proof-of-work, hash starts with only {measured_difficulty} bits equal to 0.\r\n"
        );
        socket.write_all(message.as_bytes()).await?;
        Ok(false)
    } else {
        socket.write_all(b"Thank you for solving our proof-of-work, we hope you had a great time! Launching challenge...\r\n\r\n").await?;
        Ok(true)
    }
}
