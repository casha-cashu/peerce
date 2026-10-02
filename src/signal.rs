use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct Join {
    pub addr: String,
    pub fp: String,
}

#[derive(Deserialize, Debug)]
pub struct PeerInfo {
    pub peer_addr: String,
    pub peer_fp: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct PollResponse {
    pub peer_addr: Option<String>,
    pub peer_fp: Option<String>,
    pub waiting: Option<bool>,
}

pub fn base(signal: &str) -> String {
    signal.trim_end_matches('/').to_string()
}

pub async fn register(signal: &str, code: &str, addr: &str, fp: &str) -> Result<()> {
    let url = format!("{}/v1/rooms", base(signal));
    let body = serde_json::json!({"code": code, "addr": addr, "fp": fp});
    let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
    anyhow::ensure!(resp.status().is_success(), "register failed: {}", resp.status());
    Ok(())
}

pub async fn join(signal: &str, code: &str, addr: &str, fp: &str) -> Result<PeerInfo> {
    let url = format!("{}/v1/rooms/{code}/join", base(signal));
    let body = Join {
        addr: addr.to_string(),
        fp: fp.to_string(),
    };
    let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
    anyhow::ensure!(resp.status().is_success(), "join failed: {}", resp.status());
    resp.json::<PeerInfo>().await.context("bad join body")
}

pub async fn poll(signal: &str, code: &str) -> Result<Option<PeerInfo>> {
    let url = format!("{}/v1/rooms/{code}", base(signal));
    let resp = reqwest::Client::new().get(&url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    anyhow::ensure!(resp.status().is_success(), "poll failed: {}", resp.status());
    let p = resp.json::<PollResponse>().await?;
    match (p.peer_addr, p.peer_fp) {
        (Some(a), Some(f)) => Ok(Some(PeerInfo {
            peer_addr: a,
            peer_fp: f,
        })),
        _ => Ok(None),
    }
}

pub async fn wait_for_peer(signal: &str, code: &str, secs: u64) -> Result<PeerInfo> {
    let mut waited = 0;
    loop {
        if let Some(p) = poll(signal, code).await? {
            return Ok(p);
        }
        if waited >= secs {
            anyhow::bail!("peer did not join within {secs}s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        waited += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_trims_slash() {
        assert_eq!(base("http://x:8080/"), "http://x:8080");
    }
}
