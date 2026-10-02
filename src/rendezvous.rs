use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Default)]
struct Room {
    a_addr: String,
    a_fp: String,
    b_addr: Option<String>,
    b_fp: Option<String>,
}

#[derive(Default)]
pub struct Store {
    rooms: HashMap<String, Room>,
}

impl Store {
    fn create(&mut self, code: &str, addr: &str, fp: &str) {
        self.rooms.insert(
            code.to_string(),
            Room {
                a_addr: addr.to_string(),
                a_fp: fp.to_string(),
                b_addr: None,
                b_fp: None,
            },
        );
    }

    fn join(&mut self, code: &str, addr: &str, fp: &str) -> Option<(String, String)> {
        let r = self.rooms.get_mut(code)?;
        if r.b_addr.is_some() {
            return None;
        }
        r.b_addr = Some(addr.to_string());
        r.b_fp = Some(fp.to_string());
        Some((r.a_addr.clone(), r.a_fp.clone()))
    }

    fn poll(&mut self, code: &str) -> Option<(String, String)> {
        let r = self.rooms.get(code)?;
        let (b, f) = (r.b_addr.clone()?, r.b_fp.clone()?);
        self.rooms.remove(code);
        Some((b, f))
    }
}

fn reply(status: &str, json: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    )
    .into_bytes()
}

async fn handle(
    store: Arc<Mutex<Store>>,
    mut stream: tokio::net::TcpStream,
) -> Result<()> {
    let mut head = vec![0u8; 8192];
    let n = stream.read(&mut head).await?;
    let text = String::from_utf8_lossy(&head[..n]).into_owned();
    let mut lines = text.lines();
    let request = lines.next().unwrap_or("");
    let parts: Vec<&str> = request.split_whitespace().collect();
    if parts.len() < 2 {
        stream.write_all(&reply("400 Bad Request", "{}")).await?;
        return Ok(());
    }
    let (method, path) = (parts[0], parts[1]);
    let clen = text
        .lines()
        .find_map(|l| {
            let low = l.to_lowercase();
            low.strip_prefix("content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let header_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
    let mut body = head[header_end.min(n)..n].to_vec();
    while body.len() < clen {
        let mut tmp = vec![0u8; (clen - body.len()).min(8192)];
        let m = stream.read(&mut tmp).await?;
        if m == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..m]);
    }
    let json: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let mut store = store.lock().await;
    let out = route(&mut store, method, path, &json);
    stream.write_all(&out).await?;
    Ok(())
}

fn route(store: &mut Store, method: &str, path: &str, json: &serde_json::Value) -> Vec<u8> {
    let get = |k: &str| json.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if method == "POST" && path == "/v1/rooms" {
        store.create(&get("code"), &get("addr"), &get("fp"));
        return reply("200 OK", r#"{"ok":true}"#);
    }
    if method == "POST" && path.strip_suffix("/join").is_some() {
        let code = path.trim_start_matches("/v1/rooms/").trim_end_matches("/join");
        match store.join(code, &get("addr"), &get("fp")) {
            Some((a, f)) => {
                let j = serde_json::json!({"peer_addr": a, "peer_fp": f}).to_string();
                return reply("200 OK", &j);
            }
            None => return reply("404 Not Found", r#"{"error":"no room"}"#),
        }
    }
    if method == "GET" {
        if let Some(code) = path.strip_prefix("/v1/rooms/") {
            match store.poll(code) {
                Some((a, f)) => {
                    let j = serde_json::json!({"peer_addr": a, "peer_fp": f}).to_string();
                    return reply("200 OK", &j);
                }
                None => return reply("404 Not Found", r#"{"waiting":true}"#),
            }
        }
    }
    reply("404 Not Found", "{}")
}

pub async fn serve(bind: std::net::SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    println!("rendezvous on {bind}");
    let store = Arc::new(Mutex::new(Store::default()));
    loop {
        let (stream, _) = listener.accept().await?;
        let s = store.clone();
        tokio::spawn(async move {
            let _ = handle(s, stream).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_join_poll_flow() {
        let mut s = Store::default();
        s.create("a-b-c", "1.2.3.4:5", "fpA");
        let peer = s.join("a-b-c", "5.6.7.8:9", "fpB").unwrap();
        assert_eq!(peer.0, "1.2.3.4:5");
        let back = s.poll("a-b-c").unwrap();
        assert_eq!(back.0, "5.6.7.8:9");
        assert!(s.poll("a-b-c").is_none());
    }

    #[test]
    fn double_join_rejected() {
        let mut s = Store::default();
        s.create("x-y-z", "a", "f");
        assert!(s.join("x-y-z", "b", "g").is_some());
        assert!(s.join("x-y-z", "c", "h").is_none());
    }
}
