mod cert;
mod code;
mod compress;
mod net_bypass;
mod proto;
mod punch;
mod rendezvous;
mod signal;
mod stun;
mod transfer;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "peerce", about = "Direct P2P file transfer, no clouds")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Send {
        path: PathBuf,
        #[arg(long)]
        direct: Option<SocketAddr>,
        #[arg(long, default_value = "http://127.0.0.1:9500")]
        signal: String,
        #[arg(long, default_value = "stun.l.google.com:19302")]
        stun: String,
        #[arg(long, default_value_t = false)]
        no_compress: bool,
        #[arg(long)]
        no_stun: bool,
        #[arg(long)]
        raw_v1: bool,
        #[arg(long)]
        bind_ip: Option<String>,
        #[arg(long)]
        peer_fp: Option<String>,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, default_value_t = false)]
        via_vpn: bool,
    },
    Get {
        code: String,
        #[arg(long, default_value = "http://127.0.0.1:9500")]
        signal: String,
        #[arg(long, default_value = "stun.l.google.com:19302")]
        stun: String,
        #[arg(long, default_value = ".")]
        out: PathBuf,
        #[arg(long)]
        no_stun: bool,
        #[arg(long)]
        bind_ip: Option<String>,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, default_value_t = false)]
        via_vpn: bool,
    },
    Recv {
        #[arg(long, default_value = "0.0.0.0:4000")]
        bind: SocketAddr,
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    Rendezvous {
        #[arg(long, default_value = "127.0.0.1:9500")]
        bind: SocketAddr,
    },
    Route {
        ip: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Send {
            path,
            direct,
            signal,
            stun,
            no_compress,
            no_stun,
            raw_v1,
            bind_ip,
            peer_fp,
            port,
            via_vpn,
        } => {
            let opt = SendOpt {
                path,
                direct,
                signal,
                stun,
                compress: !no_compress,
                no_stun,
                raw_v1,
                bind_ip,
                peer_fp,
                port,
                via_vpn,
            };
            cmd_send(opt).await
        }
        Cmd::Get {
            code,
            signal,
            stun,
            out,
            no_stun,
            bind_ip,
            port,
            via_vpn,
        } => {
            let opt = GetOpt {
                raw_code: code,
                signal,
                stun_server: stun,
                out,
                no_stun,
                bind_ip_flag: bind_ip,
                fixed_port: port,
                via_vpn,
            };
            cmd_get(opt).await
        }
        Cmd::Recv { bind, out } => cmd_recv(bind, &out).await,
        Cmd::Rendezvous { bind } => rendezvous::serve(bind).await,
        Cmd::Route { ip } => cmd_route(&ip),
    }
}

pub fn transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_concurrent_uni_streams(4u32.into());
    t
}

struct SendOpt {
    path: PathBuf,
    direct: Option<SocketAddr>,
    signal: String,
    stun: String,
    compress: bool,
    no_stun: bool,
    raw_v1: bool,
    bind_ip: Option<String>,
    peer_fp: Option<String>,
    port: u16,
    via_vpn: bool,
}

fn resolve_bind_ip(flag: &Option<String>) -> Result<String> {
    match flag {
        Some(ip) => Ok(ip.clone()),
        None => net_bypass::physical_ip(),
    }
}

fn parse_fp(hex: &str) -> Result<[u8; 32]> {
    let clean = hex.trim();
    anyhow::ensure!(clean.len() == 64, "fp must be 64 hex chars");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).context("bad fp hex")?;
    }
    Ok(out)
}

fn ensure_direct_path(peer: SocketAddr, via_vpn: bool) -> Result<()> {
    if via_vpn {
        return Ok(());
    }
    if is_lan(&peer.ip()) || peer.ip().is_loopback() {
        return Ok(());
    }
    match net_bypass::check_direct(&peer.ip().to_string()) {
        Ok(true) => Ok(()),
        _ => {
            let hint = net_bypass::bypass_command(&peer.ip().to_string())
                .unwrap_or_else(|_| "sudo ip route add <peer>/32 via <gw>".to_string());
            anyhow::bail!("peer route goes via VPN tunnel. refusing.\nrun: {hint}\nor retry with --via-vpn to override")
        }
    }
}

fn is_lan(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            v.is_private() || v.is_link_local() || v.is_loopback()
        }
        std::net::IpAddr::V6(v) => v.is_loopback() || v.is_unique_local(),
    }
}

async fn reflexive_addr(
    bind_ip: &str,
    stun_server: &str,
    no_stun: bool,
    port: u16,
) -> Result<(SocketAddr, u16)> {
    if no_stun {
        let sock = tokio::net::UdpSocket::bind(format!("{bind_ip}:{port}")).await?;
        let local = sock.local_addr()?;
        return Ok((local, local.port()));
    }
    if port != 0 {
        let sock = tokio::net::UdpSocket::bind(format!("{bind_ip}:{port}")).await?;
        let local_port = sock.local_addr()?.port();
        drop(sock);
        let (reflexive, _) = stun::discover_with_port_on(bind_ip, local_port, stun_server).await?;
        return Ok((reflexive, local_port));
    }
    stun::discover_with_port(bind_ip, stun_server).await
}

async fn cmd_send(o: SendOpt) -> Result<()> {
    let bind_ip = resolve_bind_ip(&o.bind_ip)?;
    println!("bind: {bind_ip} (direct)");
    if let Some(addr) = o.direct {
        return direct_send(&o.path, addr, &bind_ip, o.peer_fp, o.raw_v1, o.compress).await;
    }
    let (cert_der, _) = cert::generate()?;
    let fp_hex = cert::fingerprint_hex(&cert_der);
    let (reflexive, port) = reflexive_addr(&bind_ip, &o.stun, o.no_stun, o.port).await?;
    println!("reflexive: {reflexive}");
    let code = code::generate();
    signal::register(&o.signal, &code, &reflexive.to_string(), &fp_hex).await?;
    println!("Pairing code: {code}");
    println!("Waiting for peer... (120s)");
    let peer = signal::wait_for_peer(&o.signal, &code, 120).await?;
    println!("Connected! peer {}", peer.peer_addr);
    let peer_addr: SocketAddr = peer.peer_addr.parse().context("bad peer addr")?;
    ensure_direct_path(peer_addr, o.via_vpn)?;
    let peer_fp = parse_fp(&peer.peer_fp)?;
    punch::punch_on_port(&bind_ip, port, peer_addr, 2).await?;
    quic_send_v2(peer_addr, &bind_ip, port, peer_fp, &o.path, o.compress).await
}

async fn direct_send(
    path: &Path,
    addr: SocketAddr,
    bind_ip: &str,
    peer_fp: Option<String>,
    raw_v1: bool,
    compress: bool,
) -> Result<()> {
    ensure_direct_path(addr, true)?;
    let mut ep = quinn::Endpoint::client(format!("{bind_ip}:0").parse()?)?;
    match peer_fp {
        Some(hex) => ep.set_default_client_config(cert::client_config_fingerprint(parse_fp(&hex)?)?),
        None => {
            eprintln!("warning: no --peer-fp, TLS unauthenticated (LAN test only)");
            ep.set_default_client_config(insecure_client_config()?);
        }
    }
    let conn = ep.connect(addr, "peerce")?.await.context("connect")?;
    println!("Connected!");
    let mut stream = conn.open_uni().await.context("open stream")?;
    if raw_v1 {
        anyhow::ensure!(!path.is_dir(), "v1 sends files only");
        transfer::send_v1_file(path, &mut stream).await?;
        stream.finish()?;
    } else {
        transfer::send_v2(path, &mut stream, compress).await?;
        stream.finish()?;
    }
    conn.closed().await;
    ep.wait_idle().await;
    Ok(())
}

async fn quic_send_v2(
    peer: SocketAddr,
    bind_ip: &str,
    port: u16,
    peer_fp: [u8; 32],
    path: &Path,
    compress: bool,
) -> Result<()> {
    let mut ep = quinn::Endpoint::client(format!("{bind_ip}:{port}").parse()?)?;
    ep.set_default_client_config(cert::client_config_fingerprint(peer_fp)?);
    let conn = ep
        .connect(peer, "peerce")?
        .await
        .context("Direct P2P impossible: QUIC handshake failed (both behind Symmetric NAT?)")?;
    println!("Connected!");
    let mut stream = conn.open_uni().await.context("open stream")?;
    transfer::send_v2(path, &mut stream, compress).await?;
    stream.finish()?;
    conn.closed().await;
    ep.wait_idle().await;
    Ok(())
}

struct GetOpt {
    raw_code: String,
    signal: String,
    stun_server: String,
    out: PathBuf,
    no_stun: bool,
    bind_ip_flag: Option<String>,
    fixed_port: u16,
    via_vpn: bool,
}

async fn cmd_get(o: GetOpt) -> Result<()> {
    let code = code::normalize(&o.raw_code)?;
    let bind_ip = resolve_bind_ip(&o.bind_ip_flag)?;
    println!("bind: {bind_ip} (direct)");
    let (cert_der, key_der) = cert::generate()?;
    let fp_hex = cert::fingerprint_hex(&cert_der);
    let (reflexive, port) = reflexive_addr(&bind_ip, &o.stun_server, o.no_stun, o.fixed_port).await?;
    println!("reflexive: {reflexive}");
    println!("Connecting to peer...");
    let peer = signal::join(&o.signal, &code, &reflexive.to_string(), &fp_hex).await?;
    let peer_addr: SocketAddr = peer.peer_addr.parse().context("bad peer addr")?;
    println!("peer: {peer_addr}");
    ensure_direct_path(peer_addr, o.via_vpn)?;
    punch::punch_on_port(&bind_ip, port, peer_addr, 3).await?;
    quic_serve_once(&bind_ip, port, cert_der, key_der, &o.out).await
}

async fn quic_serve_once(
    bind_ip: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    out: &Path,
) -> Result<()> {
    let ep = quinn::Endpoint::server(
        cert::server_config(cert_der, key_der)?,
        format!("{bind_ip}:{port}").parse()?,
    )?;
    let conn = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        ep.accept().await.context("no incoming")?.await.context("handshake")
    })
    .await
    .context("peer did not connect (NAT?)")??;
    let mut stream = conn.accept_uni().await.context("accept stream")?;
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).await.context("read magic")?;
    if &magic == b"PRC1" {
        transfer::recv_v1_after_magic(&mut stream, out).await?;
    } else if &magic[..3] == b"PRC" {
        transfer::recv_v2_after_magic(&mut stream, &magic, out).await?;
    } else {
        anyhow::bail!("bad magic");
    }
    conn.close(0u32.into(), b"ok");
    ep.wait_idle().await;
    Ok(())
}

async fn cmd_recv(bind: SocketAddr, out: &Path) -> Result<()> {
    let (cert_der, key_der) = cert::generate()?;
    let ep = quinn::Endpoint::server(cert::server_config(cert_der, key_der)?, bind)?;
    println!("listening on {}", ep.local_addr()?);
    let conn = ep
        .accept()
        .await
        .context("no incoming")?
        .await
        .context("handshake")?;
    let mut stream = conn.accept_uni().await.context("accept stream")?;
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).await.context("read magic")?;
    if &magic == b"PRC1" {
        transfer::recv_v1_after_magic(&mut stream, out).await?;
    } else if &magic[..3] == b"PRC" {
        transfer::recv_v2_after_magic(&mut stream, &magic, out).await?;
    } else {
        anyhow::bail!("bad magic");
    }
    conn.close(0u32.into(), b"ok");
    ep.wait_idle().await;
    Ok(())
}

fn cmd_route(ip: &str) -> Result<()> {
    let out = net_bypass::route_egress(ip)?;
    println!("{out}");
    if net_bypass::goes_via_tunnel(&out) {
        println!("via VPN. bypass:");
        println!("  {}", net_bypass::bypass_command(ip)?);
    } else {
        println!("direct, no VPN.");
    }
    Ok(())
}

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end: &rustls::pki_types::CertificateDer,
        _inter: &[rustls::pki_types::CertificateDer],
        _name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn insecure_client_config() -> Result<quinn::ClientConfig> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    cfg.transport_config(Arc::new(transport_config()));
    Ok(cfg)
}
