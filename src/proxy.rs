// SPDX-FileCopyrightText: 2023-2026 erdnaxe
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

/// PROXY protocol v2 signature (12 bytes)
const PROXY_V2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

const VERSION_MASK: u8 = 0xF0;
const COMMAND_MASK: u8 = 0x0F;
const VERSION_2: u8 = 0x20;
const CMD_LOCAL: u8 = 0x00;
const CMD_PROXY: u8 = 0x01;

const AF_UNSPEC: u8 = 0x00;
const AF_INET: u8 = 0x10;
const AF_INET6: u8 = 0x20;
const AF_UNIX: u8 = 0x30;

// const PROTO_UNSPEC: u8 = 0x00;
const PROTO_STREAM: u8 = 0x01;

const MAX_PROXY_ADDR_LEN: usize = 512;
const READ_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

impl ProxyInfo {
    pub fn new(src_addr: IpAddr, src_port: u16, dst_addr: IpAddr, dst_port: u16) -> Self {
        Self {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        }
    }
}

/// Parse PROXY protocol v2 header
pub async fn parse_proxy_v2_header<R: AsyncReadExt + Unpin>(
    stream: &mut R,
) -> Result<Option<ProxyInfo>> {
    let mut header = [0u8; 16];
    timeout(READ_TIMEOUT, stream.read_exact(&mut header)).await??;

    // Signature check
    if &header[0..12] != PROXY_V2_SIGNATURE {
        return Err(anyhow!("Invalid PROXY protocol v2 signature"));
    }

    let version_command = header[12];
    let family_protocol = header[13];
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    if (version_command & VERSION_MASK) != VERSION_2 {
        return Err(anyhow!("Unsupported PROXY protocol version"));
    }

    let command = version_command & COMMAND_MASK;

    if addr_len > MAX_PROXY_ADDR_LEN {
        return Err(anyhow!("PROXY header too large: {}", addr_len));
    }

    // Handle LOCAL command
    if command == CMD_LOCAL {
        if addr_len > 0 {
            let mut discard = vec![0u8; addr_len];
            timeout(READ_TIMEOUT, stream.read_exact(&mut discard)).await??;
        }
        return Ok(None);
    }

    if command != CMD_PROXY {
        return Err(anyhow!("Unsupported PROXY command: {}", command));
    }

    let family = family_protocol & 0xF0;
    let protocol = family_protocol & 0x0F;

    if protocol != PROTO_STREAM {
        return Err(anyhow!("Unsupported transport protocol: {}", protocol));
    }

    match family {
        AF_INET => parse_ipv4(stream, addr_len).await,
        AF_INET6 => parse_ipv6(stream, addr_len).await,
        AF_UNSPEC => {
            if addr_len > 0 {
                let mut discard = vec![0u8; addr_len];
                timeout(READ_TIMEOUT, stream.read_exact(&mut discard)).await??;
            }
            Ok(None)
        }
        AF_UNIX => Err(anyhow!("UNIX addresses not supported")),
        _ => Err(anyhow!("Unknown address family: {}", family)),
    }
}

/// Parse IPv4 address block (12 bytes) + skip TLVs
async fn parse_ipv4<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    addr_len: usize,
) -> Result<Option<ProxyInfo>> {
    if addr_len < 12 {
        return Err(anyhow!("IPv4 address block too short: {}", addr_len));
    }

    let mut addr = [0u8; 12];
    timeout(READ_TIMEOUT, stream.read_exact(&mut addr)).await??;

    // Skip extra TLV bytes if any
    if addr_len > 12 {
        let mut discard = vec![0u8; addr_len - 12];
        timeout(READ_TIMEOUT, stream.read_exact(&mut discard)).await??;
    }

    let src_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let dst_addr = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
    let src_port = u16::from_be_bytes([addr[8], addr[9]]);
    let dst_port = u16::from_be_bytes([addr[10], addr[11]]);

    Ok(Some(ProxyInfo::new(
        IpAddr::V4(src_addr),
        src_port,
        IpAddr::V4(dst_addr),
        dst_port,
    )))
}

/// Parse IPv6 address block (36 bytes) + skip TLVs
async fn parse_ipv6<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    addr_len: usize,
) -> Result<Option<ProxyInfo>> {
    if addr_len < 36 {
        return Err(anyhow!("IPv6 address block too short: {}", addr_len));
    }

    let mut addr = [0u8; 36];
    timeout(READ_TIMEOUT, stream.read_exact(&mut addr)).await??;

    if addr_len > 36 {
        let mut discard = vec![0u8; addr_len - 36];
        timeout(READ_TIMEOUT, stream.read_exact(&mut discard)).await??;
    }

    let src_addr = Ipv6Addr::new(
        u16::from_be_bytes([addr[0], addr[1]]),
        u16::from_be_bytes([addr[2], addr[3]]),
        u16::from_be_bytes([addr[4], addr[5]]),
        u16::from_be_bytes([addr[6], addr[7]]),
        u16::from_be_bytes([addr[8], addr[9]]),
        u16::from_be_bytes([addr[10], addr[11]]),
        u16::from_be_bytes([addr[12], addr[13]]),
        u16::from_be_bytes([addr[14], addr[15]]),
    );

    let dst_addr = Ipv6Addr::new(
        u16::from_be_bytes([addr[16], addr[17]]),
        u16::from_be_bytes([addr[18], addr[19]]),
        u16::from_be_bytes([addr[20], addr[21]]),
        u16::from_be_bytes([addr[22], addr[23]]),
        u16::from_be_bytes([addr[24], addr[25]]),
        u16::from_be_bytes([addr[26], addr[27]]),
        u16::from_be_bytes([addr[28], addr[29]]),
        u16::from_be_bytes([addr[30], addr[31]]),
    );

    let src_port = u16::from_be_bytes([addr[32], addr[33]]);
    let dst_port = u16::from_be_bytes([addr[34], addr[35]]);

    Ok(Some(ProxyInfo::new(
        IpAddr::V6(src_addr),
        src_port,
        IpAddr::V6(dst_addr),
        dst_port,
    )))
}
