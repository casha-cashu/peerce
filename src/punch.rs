use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const PROBE: &[u8] = b"PEERCE-PING";
const PROBE_REPLY: &[u8] = b"PEERCE-PONG";

pub async fn punch(sock: &UdpSocket, peer: SocketAddr, secs: u64) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut buf = [0u8; 64];
    let mut answered = false;
    while tokio::time::Instant::now() < deadline {
        let _ = sock.send_to(PROBE, peer).await;
        match tokio::time::timeout(std::time::Duration::from_millis(200), sock.recv_from(&mut buf))
            .await
        {
            Ok(Ok((n, from))) if &buf[..n] == PROBE && from.ip() == peer.ip() => {
                let _ = sock.send_to(PROBE_REPLY, from).await;
            }
            Ok(Ok((n, _))) if &buf[..n] == PROBE_REPLY => {
                answered = true;
                break;
            }
            _ => continue,
        }
    }
    if answered {
        return Ok(true);
    }
    if tokio::time::Instant::now() >= deadline {
        return Ok(false);
    }
    Ok(false)
}

pub async fn punch_on_port(bind_ip: &str, port: u16, peer: SocketAddr, secs: u64) -> Result<bool> {
    let sock = UdpSocket::bind(format!("{bind_ip}:{port}")).await?;
    punch(&sock, peer, secs).await
}
