use anyhow::{Context, Result};
use std::net::IpAddr;
use std::process::Command;

const TUN_PREFIXES: &[&str] = &["tun_", "tailscale", "wg", "tunincy"];
const TUN_NETS: &[&str] = &["198.18.", "100.64.", "10.255.", "127."];

pub fn is_tunnel_iface(name: &str, ip: &str) -> bool {
    let lower = name.to_lowercase();
    if TUN_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    if TUN_NETS.iter().any(|n| ip.starts_with(n)) {
        return true;
    }
    name == "lo"
}

pub fn parse_ip_addr_output(out: &str) -> Vec<(String, String)> {
    let mut res = Vec::new();
    let mut iface = String::new();
    for line in out.lines() {
        let t = line.trim();
        if let Some(inet_pos) = t.find(" inet ") {
            let head = &t[..inet_pos];
            if let Some(colon) = head.find(':') {
                let name = head[colon + 1..].split_whitespace().next().unwrap_or("");
                if !name.is_empty() && !name.starts_with('-') {
                    iface = name.trim_end_matches(':').to_string();
                }
            }
            let tail = &t[inet_pos + 6..];
            if let Some(ip) = tail.split_whitespace().next() {
                let ip = ip.split('/').next().unwrap_or(ip).to_string();
                if !iface.is_empty() {
                    res.push((iface.clone(), ip));
                }
            }
            continue;
        }
        if t.starts_with("inet ") {
            if let Some(ip) = t.split_whitespace().nth(1) {
                let ip = ip.split('/').next().unwrap_or(ip).to_string();
                if !iface.is_empty() {
                    res.push((iface.clone(), ip));
                }
            }
            continue;
        }
        if let Some(colon) = t.find(':') {
            let rest = t[colon + 1..].trim();
            if let Some(name) = rest.split_whitespace().next() {
                if !name.starts_with('-') && !name.contains('/') {
                    iface = name.trim_end_matches(':').to_string();
                }
            }
        }
    }
    res
}

pub fn pick_physical_ip(addrs: &[(String, String)]) -> Option<String> {
    addrs
        .iter()
        .filter(|(iface, ip)| ip.contains('.') && !is_tunnel_iface(iface, ip))
        .map(|(_, ip)| ip.clone())
        .next()
}

pub fn parse_default_route(out: &str) -> Option<(String, String)> {
    for line in out.lines() {
        let t = line.trim();
        if t.starts_with("default via ") {
            let mut gw = String::new();
            let mut dev = String::new();
            let parts: Vec<&str> = t.split_whitespace().collect();
            for (i, p) in parts.iter().enumerate() {
                if *p == "via" {
                    gw = parts.get(i + 1).unwrap_or(&"").to_string();
                }
                if *p == "dev" {
                    dev = parts.get(i + 1).unwrap_or(&"").to_string();
                }
            }
            if !gw.is_empty() && !dev.is_empty() {
                return Some((gw, dev));
            }
        }
    }
    None
}

fn run_ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip").args(args).output().context("run ip")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn physical_ip() -> Result<String> {
    let out = run_ip(&["-o", "-4", "addr", "show"])?;
    let addrs = parse_ip_addr_output(&out);
    pick_physical_ip(&addrs).context("no physical IPv4 found")
}

pub fn default_gateway() -> Result<(String, String)> {
    let out = run_ip(&["route", "show", "default"])?;
    parse_default_route(&out).context("no default route")
}

pub fn route_egress(ip: &str) -> Result<String> {
    run_ip(&["route", "get", ip])
}

pub fn goes_via_tunnel(route_get_out: &str) -> bool {
    route_get_out.contains("tun_incy")
        || route_get_out.contains("tailscale")
        || route_get_out.contains("tun]")
        || route_get_out.contains("198.18.0.1")
}

pub fn check_direct(ip: &str) -> Result<bool> {
    Ok(!goes_via_tunnel(&route_egress(ip)?))
}

pub fn bypass_command(ip: &str) -> Result<String> {
    let (gw, dev) = default_gateway()?;
    let host: IpAddr = ip.parse().context("bad ip")?;
    Ok(format!("sudo ip route add {host}/32 via {gw} dev {dev}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ADDR: &str = "1: lo    inet 127.0.0.1/8 scope host lo\n\
        2: enp59s0u1u1    inet 192.168.1.189/24 brd 192.168.1.255 scope global dynamic noprefixroute enp59s0u1u1\n\
        8: tun_incy    inet 198.18.0.1/16 brd 198.18.255.255 scope global tun_incy\n";

    #[test]
    fn picks_physical_not_tunnel() {
        let addrs = parse_ip_addr_output(SAMPLE_ADDR);
        assert_eq!(pick_physical_ip(&addrs).as_deref(), Some("192.168.1.189"));
    }

    #[test]
    fn parses_default_route() {
        let out =
            "default via 192.168.1.1 dev enp59s0u1u1 proto dhcp src 192.168.1.189 metric 100\n";
        assert_eq!(
            parse_default_route(out),
            Some(("192.168.1.1".to_string(), "enp59s0u1u1".to_string()))
        );
    }

    #[test]
    fn detects_tunnel_egress() {
        assert!(goes_via_tunnel(
            "8.8.8.8 dev tun_incy table 100 src 198.18.0.1"
        ));
        assert!(!goes_via_tunnel(
            "192.168.0.108 via 192.168.1.1 dev enp59s0u1u1 src 192.168.1.189"
        ));
    }

    #[test]
    fn tunnel_iface_filter() {
        assert!(is_tunnel_iface("tun_incy", "198.18.0.1"));
        assert!(is_tunnel_iface("tailscale0", "100.100.1.2"));
        assert!(is_tunnel_iface("lo", "127.0.0.1"));
        assert!(!is_tunnel_iface("enp59s0u1u1", "192.168.1.189"));
    }
}
