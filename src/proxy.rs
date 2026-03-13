// SPDX-FileCopyrightText: 2023-2026 erdnaxe
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Duration, timeout};

/// PROXY protocol v2 signature (12 bytes)
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

const VERSION_MASK: u8 = 0xF0;
const VERSION_2: u8 = 0x20;
const LOW_NIBBLE_MASK: u8 = 0x0F;
const HIGH_NIBBLE_MASK: u8 = 0xF0;

const PROXY_V2_HEADER_LEN: usize = 16;
const IPV4_BLOCK_LEN: usize = 12;
const IPV6_BLOCK_LEN: usize = 36;

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
    pub const fn new(src_addr: IpAddr, src_port: u16, dst_addr: IpAddr, dst_port: u16) -> Self {
        Self {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProxyHeader {
    Local,
    Proxied(ProxyInfo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Local,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportProtocol {
    Unspec,
    Stream,
    Datagram,
}

fn parse_command(version_command: u8) -> Result<Command> {
    if version_command & VERSION_MASK != VERSION_2 {
        return Err(anyhow!("Unsupported PROXY protocol version"));
    }

    match version_command & LOW_NIBBLE_MASK {
        0x00 => Ok(Command::Local),
        0x01 => Ok(Command::Proxy),
        command => Err(anyhow!("Unsupported PROXY command: {command}")),
    }
}

fn parse_family_protocol(family_protocol: u8) -> Result<(AddressFamily, TransportProtocol)> {
    let family = match family_protocol & HIGH_NIBBLE_MASK {
        0x00 => AddressFamily::Unspec,
        0x10 => AddressFamily::Inet,
        0x20 => AddressFamily::Inet6,
        0x30 => AddressFamily::Unix,
        family => return Err(anyhow!("Unknown address family: {family}")),
    };

    let protocol = match family_protocol & LOW_NIBBLE_MASK {
        0x00 => TransportProtocol::Unspec,
        0x01 => TransportProtocol::Stream,
        0x02 => TransportProtocol::Datagram,
        protocol => return Err(anyhow!("Unknown transport protocol: {protocol}")),
    };

    Ok((family, protocol))
}

async fn read_exact_with_timeout<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
) -> Result<()> {
    timeout(READ_TIMEOUT, stream.read_exact(buf)).await??;
    Ok(())
}

async fn drain_bytes<R: AsyncRead + Unpin>(stream: &mut R, mut len: usize) -> Result<()> {
    let mut scratch = [0u8; 256];

    while len > 0 {
        let chunk_len = len.min(scratch.len());
        let chunk = scratch
            .get_mut(..chunk_len)
            .ok_or_else(|| anyhow!("Read chunk length out of bounds"))?;
        read_exact_with_timeout(stream, chunk).await?;
        len = len
            .checked_sub(chunk_len)
            .ok_or_else(|| anyhow!("Drained length underflow"))?;
    }

    Ok(())
}

/// Parse PROXY protocol v2 header
pub async fn parse_proxy_v2_header<R: AsyncRead + Unpin>(stream: &mut R) -> Result<ProxyHeader> {
    let mut header = [0u8; PROXY_V2_HEADER_LEN];
    read_exact_with_timeout(stream, &mut header).await?;

    // Signature check
    if header[..12] != PROXY_V2_SIGNATURE {
        return Err(anyhow!("Invalid PROXY protocol v2 signature"));
    }

    let command = parse_command(header[12])?;
    let addr_len = usize::from(u16::from_be_bytes([header[14], header[15]]));

    if addr_len > MAX_PROXY_ADDR_LEN {
        return Err(anyhow!("PROXY header too large: {addr_len}"));
    }

    // Handle LOCAL command
    if command == Command::Local {
        if addr_len > 0 {
            drain_bytes(stream, addr_len).await?;
        }
        return Ok(ProxyHeader::Local);
    }

    let (family, protocol) = parse_family_protocol(header[13])?;

    if protocol != TransportProtocol::Stream {
        return Err(anyhow!("Unsupported transport protocol: {protocol:?}"));
    }

    match family {
        AddressFamily::Inet => parse_ipv4(stream, addr_len).await,
        AddressFamily::Inet6 => parse_ipv6(stream, addr_len).await,
        AddressFamily::Unspec => {
            if addr_len > 0 {
                drain_bytes(stream, addr_len).await?;
            }
            Ok(ProxyHeader::Local)
        }
        AddressFamily::Unix => Err(anyhow!("UNIX addresses not supported")),
    }
}

/// Parse IPv4 address block (12 bytes) + skip TLVs
async fn parse_ipv4<R: AsyncRead + Unpin>(stream: &mut R, addr_len: usize) -> Result<ProxyHeader> {
    if addr_len < IPV4_BLOCK_LEN {
        return Err(anyhow!("IPv4 address block too short: {addr_len}"));
    }

    let mut addr = [0u8; IPV4_BLOCK_LEN];
    read_exact_with_timeout(stream, &mut addr).await?;

    let tlv_len = addr_len
        .checked_sub(IPV4_BLOCK_LEN)
        .ok_or_else(|| anyhow!("IPv4 TLV length underflow"))?;
    if tlv_len > 0 {
        drain_bytes(stream, tlv_len).await?;
    }

    let src_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let dst_addr = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
    let src_port = u16::from_be_bytes([addr[8], addr[9]]);
    let dst_port = u16::from_be_bytes([addr[10], addr[11]]);

    Ok(ProxyHeader::Proxied(ProxyInfo::new(
        IpAddr::V4(src_addr),
        src_port,
        IpAddr::V4(dst_addr),
        dst_port,
    )))
}

/// Parse IPv6 address block (36 bytes) + skip TLVs
async fn parse_ipv6<R: AsyncRead + Unpin>(stream: &mut R, addr_len: usize) -> Result<ProxyHeader> {
    if addr_len < IPV6_BLOCK_LEN {
        return Err(anyhow!("IPv6 address block too short: {addr_len}"));
    }

    let mut addr = [0u8; IPV6_BLOCK_LEN];
    read_exact_with_timeout(stream, &mut addr).await?;

    let tlv_len = addr_len
        .checked_sub(IPV6_BLOCK_LEN)
        .ok_or_else(|| anyhow!("IPv6 TLV length underflow"))?;
    if tlv_len > 0 {
        drain_bytes(stream, tlv_len).await?;
    }

    let mut src_addr_bytes = [0u8; 16];
    src_addr_bytes.copy_from_slice(&addr[..16]);
    let src_addr = Ipv6Addr::from(src_addr_bytes);

    let mut dst_addr_bytes = [0u8; 16];
    dst_addr_bytes.copy_from_slice(&addr[16..32]);
    let dst_addr = Ipv6Addr::from(dst_addr_bytes);

    let src_port = u16::from_be_bytes([addr[32], addr[33]]);
    let dst_port = u16::from_be_bytes([addr[34], addr[35]]);

    Ok(ProxyHeader::Proxied(ProxyInfo::new(
        IpAddr::V6(src_addr),
        src_port,
        IpAddr::V6(dst_addr),
        dst_port,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const IPV4_BLOCK_LEN_U16: u16 = 12;
    const IPV6_BLOCK_WITH_TLV_LEN_U16: u16 = 38;

    async fn parse_from_bytes(data: &[u8]) -> Result<(Result<ProxyHeader>, Vec<u8>)> {
        let (mut writer, mut reader) = tokio::io::duplex(2048);
        writer.write_all(data).await?;
        drop(writer);

        let header = parse_proxy_v2_header(&mut reader).await;
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).await?;

        Ok((header, remaining))
    }

    fn build_header(version_command: u8, family_protocol: u8, addr_len: u16) -> Vec<u8> {
        let mut data = Vec::with_capacity(PROXY_V2_HEADER_LEN);
        data.extend_from_slice(&PROXY_V2_SIGNATURE);
        data.push(version_command);
        data.push(family_protocol);
        data.extend_from_slice(&addr_len.to_be_bytes());
        data
    }

    #[tokio::test]
    async fn parses_local_header_and_discards_payload() -> Result<()> {
        let mut data = build_header(0x20, 0x00, 3);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let (header, remaining) = parse_from_bytes(&data).await?;

        assert!(matches!(header, Ok(ProxyHeader::Local)));
        assert!(remaining.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn parses_local_header_with_unknown_family_and_protocol() -> Result<()> {
        let mut data = build_header(0x20, 0xFF, 1);
        data.push(0xAA);

        let (header, remaining) = parse_from_bytes(&data).await?;

        assert!(matches!(header, Ok(ProxyHeader::Local)));
        assert!(remaining.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn parses_ipv4_proxy_header() -> Result<()> {
        let mut data = build_header(0x21, 0x11, IPV4_BLOCK_LEN_U16);
        data.extend_from_slice(&[
            192, 0, 2, 10, // source IPv4
            198, 51, 100, 7, // destination IPv4
            0x30, 0x39, // source port 12345
            0x00, 0x50, // destination port 80
        ]);

        let (header, remaining) = parse_from_bytes(&data).await?;
        let header = match header {
            Ok(header) => header,
            Err(error) => panic!("header should parse: {error}"),
        };
        assert!(remaining.is_empty());

        match header {
            ProxyHeader::Proxied(info) => {
                assert_eq!(info.src_addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
                assert_eq!(info.dst_addr, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
                assert_eq!(info.src_port, 12345);
                assert_eq!(info.dst_port, 80);
            }
            ProxyHeader::Local => panic!("expected proxied header"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn parses_ipv6_proxy_header_and_discards_tlv() -> Result<()> {
        let mut data = build_header(0x21, 0x21, IPV6_BLOCK_WITH_TLV_LEN_U16);
        data.extend_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // source IPv6
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // destination IPv6
            0x01, 0xBB, // source port 443
            0x82, 0x35, // destination port 33333
            0xEE, 0xFF, // TLV payload to skip
        ]);

        let (header, remaining) = parse_from_bytes(&data).await?;
        let header = match header {
            Ok(header) => header,
            Err(error) => panic!("header should parse: {error}"),
        };
        assert!(remaining.is_empty());

        match header {
            ProxyHeader::Proxied(info) => {
                assert_eq!(
                    info.src_addr,
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1))
                );
                assert_eq!(
                    info.dst_addr,
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 2))
                );
                assert_eq!(info.src_port, 443);
                assert_eq!(info.dst_port, 33333);
            }
            ProxyHeader::Local => panic!("expected proxied header"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unknown_command() -> Result<()> {
        let data = build_header(0x22, 0x11, 0);
        let (header, _) = parse_from_bytes(&data).await?;
        let Err(error) = header else {
            panic!("header should fail");
        };

        assert!(error.to_string().contains("Unsupported PROXY command"));
        Ok(())
    }
}
