use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112A442;

pub fn build_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out[8..20].copy_from_slice(txid);
    out
}

fn decode_xor_addr(value: &[u8], txid: &[u8; 12]) -> Result<SocketAddr> {
    anyhow::ensure!(value.len() >= 8, "attr too short");
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    if family == 0x01 {
        anyhow::ensure!(value.len() >= 8, "v4 too short");
        let mut ip = [0u8; 4];
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (i, b) in ip.iter_mut().enumerate() {
            *b = value[4 + i] ^ cookie[i];
        }
        Ok(SocketAddr::from(([ip[0], ip[1], ip[2], ip[3]], xport)))
    } else if family == 0x02 {
        anyhow::ensure!(value.len() >= 20, "v6 too short");
        let mut ip = [0u8; 16];
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(txid);
        for (i, b) in ip.iter_mut().enumerate() {
            *b = value[4 + i] ^ key[i];
        }
        Ok(SocketAddr::from((ip, xport)))
    } else {
        anyhow::bail!("unknown family {family}");
    }
}

pub fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr> {
    anyhow::ensure!(buf.len() >= 20, "stun too short");
    anyhow::ensure!(u16::from_be_bytes([buf[0], buf[1]]) == 0x0101, "not success");
    anyhow::ensure!(&buf[8..20] == txid, "txid mismatch");
    let mut off = 20;
    while off + 4 <= buf.len() {
        let typ = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        anyhow::ensure!(off + 4 + len <= buf.len(), "attr overrun");
        if typ == 0x0020 || typ == 0x0001 {
            if let Ok(a) = decode_xor_addr(&buf[off + 4..off + 4 + len], txid) {
                return Ok(a);
            }
        }
        off += 4 + len;
        if !len.is_multiple_of(4) {
            off += 4 - len % 4;
        }
    }
    anyhow::bail!("no mapped address")
}

pub async fn discover_with_port(bind_ip: &str, server: &str) -> Result<(SocketAddr, u16)> {
    discover_with_port_on(bind_ip, 0, server).await
}

#[allow(dead_code)]
pub async fn discover(bind_ip: &str, server: &str) -> Result<SocketAddr> {
    Ok(discover_with_port(bind_ip, server).await?.0)
}

pub async fn discover_with_port_on(
    bind_ip: &str,
    port: u16,
    server: &str,
) -> Result<(SocketAddr, u16)> {
    let sock = UdpSocket::bind(format!("{bind_ip}:{port}")).await?;
    let local = sock.local_addr()?.port();
    sock.connect(server).await.context("stun connect")?;
    let mut txid = [0u8; 12];
    for b in txid.iter_mut() {
        *b = rand_byte();
    }
    let req = build_request(&txid);
    let mut buf = [0u8; 1024];
    for _ in 0..3 {
        sock.send(&req).await?;
        match tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => return Ok((parse_response(&buf[..n], &txid)?, local)),
            _ => continue,
        }
    }
    anyhow::bail!("STUN timeout to {server}")
}

fn rand_byte() -> u8 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    (h.finish() & 0xff) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response(txid: &[u8; 12]) -> Vec<u8> {
        let mut out = vec![0u8; 0];
        out.extend_from_slice(&0x0101u16.to_be_bytes());
        out.extend_from_slice(&12u16.to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(txid);
        out.extend_from_slice(&0x0020u16.to_be_bytes());
        out.extend_from_slice(&8u16.to_be_bytes());
        out.push(0);
        out.push(0x01);
        let port = 54321u16 ^ (MAGIC_COOKIE >> 16) as u16;
        out.extend_from_slice(&port.to_be_bytes());
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let ip = [93u8, 184, 216, 34];
        for (i, b) in ip.iter().enumerate() {
            out.push(b ^ cookie[i]);
        }
        out
    }

    #[test]
    fn request_shape() {
        let req = build_request(&[7u8; 12]);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), 0x0001);
        assert_eq!(&req[8..20], &[7u8; 12]);
    }

    #[test]
    fn parses_xor_mapped_v4() {
        let txid = [9u8; 12];
        let buf = sample_response(&txid);
        let addr = parse_response(&buf, &txid).unwrap();
        assert_eq!(addr.to_string(), "93.184.216.34:54321");
    }

    #[test]
    fn rejects_wrong_txid() {
        let buf = sample_response(&[1u8; 12]);
        assert!(parse_response(&buf, &[2u8; 12]).is_err());
    }
}
