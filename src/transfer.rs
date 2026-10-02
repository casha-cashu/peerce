use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const CHUNK: usize = 128 * 1024;

pub fn progress_bar(total: u64) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::with_template(
            "[{bar:40}] {bytes}/{total_bytes} {binary_bytes_per_sec} eta {eta}",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    bar
}

pub fn spinner() -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template("{spinner} {bytes} {binary_bytes_per_sec}").unwrap(),
    );
    bar.enable_steady_tick(std::time::Duration::from_millis(100));
    bar
}

pub fn file_name_of(path: &Path) -> Result<String> {
    Ok(path
        .file_name()
        .context("no file name")?
        .to_string_lossy()
        .into_owned())
}

async fn write_frame(stream: &mut quinn::SendStream, payload: &[u8]) -> Result<()> {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
    Ok(())
}

async fn read_frame_len(stream: &mut quinn::RecvStream) -> Result<u32> {
    let mut lb = [0u8; 4];
    stream.read_exact(&mut lb).await.context("read frame")?;
    Ok(u32::from_be_bytes(lb))
}

async fn write_end_and_hash(stream: &mut quinn::SendStream, hash: &[u8; 32]) -> Result<()> {
    stream.write_all(&u32::MAX.to_be_bytes()).await?;
    stream.write_all(hash).await?;
    Ok(())
}

async fn read_trailer_hash(stream: &mut quinn::RecvStream) -> Result<[u8; 32]> {
    let mut t = [0u8; 32];
    stream.read_exact(&mut t).await.context("read hash")?;
    Ok(t)
}

pub async fn send_v1_file(path: &Path, stream: &mut quinn::SendStream) -> Result<(String, u64)> {
    use tokio::io::AsyncReadExt;
    let meta = tokio::fs::metadata(path).await?;
    let name = file_name_of(path)?;
    let size = meta.len();
    let header = crate::proto::encode_header_v1(&name, size)?;
    stream.write_all(&header).await?;
    let bar = progress_bar(size);
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        stream.write_all(&buf[..n]).await?;
        bar.inc(n as u64);
    }
    let hash = hasher.finalize();
    stream.write_all(hash.as_bytes()).await?;
    bar.finish_with_message(format!("sent {} hash={hash}", path.display()));
    Ok((name, size))
}

pub async fn recv_v1_after_magic(
    stream: &mut quinn::RecvStream,
    out_dir: &Path,
) -> Result<PathBuf> {
    use tokio::io::AsyncWriteExt;
    let mut lb = [0u8; 2];
    stream.read_exact(&mut lb).await?;
    let n = u16::from_be_bytes(lb) as usize;
    anyhow::ensure!(n > 0 && n < 4096, "bad name len");
    let mut nb = vec![0u8; n];
    stream.read_exact(&mut nb).await?;
    let name = String::from_utf8(nb).context("bad name")?;
    anyhow::ensure!(!name.contains('/') && name != "..", "unsafe name");
    let mut sb = [0u8; 8];
    stream.read_exact(&mut sb).await?;
    let size = u64::from_be_bytes(sb);
    println!("receiving: {name} [{size} B]");
    tokio::fs::create_dir_all(out_dir).await.ok();
    let dest = out_dir.join(&name);
    let mut file = tokio::fs::File::create(&dest).await?;
    let bar = progress_bar(size);
    let mut hasher = blake3::Hasher::new();
    let mut left = size;
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let want = (left as usize).min(CHUNK);
        stream.read_exact(&mut buf[..want]).await?;
        file.write_all(&buf[..want]).await?;
        hasher.update(&buf[..want]);
        left -= want as u64;
        bar.inc(want as u64);
    }
    let got = read_trailer_hash(stream).await?;
    anyhow::ensure!(*hasher.finalize().as_bytes() == got, "BLAKE3 mismatch");
    bar.finish_with_message(format!("saved to {} OK", dest.display()));
    Ok(dest)
}

pub async fn send_v2(
    path: &Path,
    stream: &mut quinn::SendStream,
    compress: bool,
) -> Result<String> {
    let name = file_name_of(path)?;
    let meta = tokio::fs::metadata(path).await?;
    if meta.is_dir() {
        send_v2_dir(path, &name, stream, compress).await?;
    } else {
        send_v2_file(path, &name, meta.len(), stream, compress).await?;
    }
    Ok(name)
}

async fn send_v2_file(
    path: &Path,
    name: &str,
    size: u64,
    stream: &mut quinn::SendStream,
    compress: bool,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let header = crate::proto::encode_header_v2(name, size, compress, false)?;
    stream.write_all(&header).await?;
    let bar = progress_bar(size);
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if compress {
            write_frame(stream, &crate::compress::compress_chunk(&buf[..n])?).await?;
        } else {
            write_frame(stream, &buf[..n]).await?;
        }
        bar.inc(n as u64);
    }
    write_end_and_hash(stream, hasher.finalize().as_bytes()).await?;
    bar.finish_with_message(format!("sent {name}"));
    Ok(())
}

struct TarChunker {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    hasher: blake3::Hasher,
}

impl Write for TarChunker {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.tx
            .blocking_send(buf.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn send_v2_dir(
    root: &Path,
    name: &str,
    stream: &mut quinn::SendStream,
    compress: bool,
) -> Result<()> {
    let header = crate::proto::encode_header_v2(name, 0, compress, true)?;
    stream.write_all(&header).await?;
    let bar = spinner();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let root_owned = root.to_path_buf();
    let producer = tokio::task::spawn_blocking(move || -> Result<[u8; 32]> {
        let chunker = TarChunker {
            tx,
            hasher: blake3::Hasher::new(),
        };
        let mut builder = tar::Builder::new(chunker);
        builder.append_dir_all(".", &root_owned)?;
        builder.finish()?;
        let chunker = builder.into_inner()?;
        Ok(*chunker.hasher.finalize().as_bytes())
    });
    let mut sent: u64 = 0;
    while let Some(raw) = rx.recv().await {
        sent += raw.len() as u64;
        bar.set_position(sent);
        if compress {
            write_frame(stream, &crate::compress::compress_chunk(&raw)?).await?;
        } else {
            write_frame(stream, &raw).await?;
        }
    }
    let hash = producer.await??;
    write_end_and_hash(stream, &hash).await?;
    bar.finish_with_message(format!("sent dir {name}"));
    Ok(())
}

pub async fn recv_v2_after_magic(
    stream: &mut quinn::RecvStream,
    magic4: &[u8; 4],
    out_dir: &Path,
) -> Result<PathBuf> {
    let ver = magic4[3];
    anyhow::ensure!(ver == 1 || ver == 2, "bad version");
    let mut fb = [0u8; 1];
    stream.read_exact(&mut fb).await?;
    let flags = fb[0];
    let compressed = flags & 0x01 != 0;
    let is_dir = flags & 0x02 != 0;
    let mut lb = [0u8; 2];
    stream.read_exact(&mut lb).await?;
    let n = u16::from_be_bytes(lb) as usize;
    anyhow::ensure!(n > 0 && n < 4096, "bad name len");
    let mut nb = vec![0u8; n];
    stream.read_exact(&mut nb).await?;
    let name = String::from_utf8(nb).context("bad name")?;
    anyhow::ensure!(!name.contains('/') && name != "..", "unsafe name");
    let mut sb = [0u8; 8];
    stream.read_exact(&mut sb).await?;
    let size = u64::from_be_bytes(sb);
    println!("receiving: {name} [{}]", if is_dir { "dir".to_string() } else { format!("{size} B") });
    tokio::fs::create_dir_all(out_dir).await.ok();
    if is_dir {
        recv_v2_dir_frames(stream, out_dir, &name, compressed).await?;
        Ok(out_dir.join(&name))
    } else {
        recv_v2_file_frames(stream, out_dir, &name, size, compressed).await?;
        Ok(out_dir.join(&name))
    }
}

async fn recv_v2_file_frames(
    stream: &mut quinn::RecvStream,
    out_dir: &Path,
    name: &str,
    size: u64,
    compressed: bool,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let dest = out_dir.join(name);
    let mut file = tokio::fs::File::create(&dest).await?;
    let bar = progress_bar(size);
    let mut hasher = blake3::Hasher::new();
    loop {
        let len = read_frame_len(stream).await?;
        if len == u32::MAX {
            break;
        }
        anyhow::ensure!(len as usize <= 8 * 1024 * 1024, "frame too big");
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            stream.read_exact(&mut payload).await?;
        }
        let plain = maybe_decompress(&payload, compressed)?;
        hasher.update(&plain);
        file.write_all(&plain).await?;
        bar.inc(plain.len() as u64);
    }
    let got = read_trailer_hash(stream).await?;
    anyhow::ensure!(*hasher.finalize().as_bytes() == got, "BLAKE3 mismatch");
    bar.finish_with_message(format!("saved to {} OK", dest.display()));
    Ok(())
}

fn maybe_decompress(payload: &[u8], compressed: bool) -> Result<Vec<u8>> {
    if compressed {
        crate::compress::decompress_chunk(payload, 8 * 1024 * 1024)
    } else {
        Ok(payload.to_vec())
    }
}

struct PipeReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    cur: Vec<u8>,
    pos: usize,
}

impl std::io::Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.cur.len() {
            match self.rx.blocking_recv() {
                Some(chunk) => {
                    self.cur = chunk;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = (self.cur.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

async fn recv_v2_dir_frames(
    stream: &mut quinn::RecvStream,
    out_dir: &Path,
    name: &str,
    compressed: bool,
) -> Result<()> {
    let dest = out_dir.join(name);
    tokio::fs::create_dir_all(&dest).await.ok();
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let dest_owned = dest.clone();
    let unpacker = tokio::task::spawn_blocking(move || -> Result<()> {
        let reader = PipeReader {
            rx,
            cur: Vec::new(),
            pos: 0,
        };
        let mut archive = tar::Archive::new(reader);
        archive.unpack(&dest_owned)?;
        Ok(())
    });
    let bar = spinner();
    let mut hasher = blake3::Hasher::new();
    loop {
        let len = read_frame_len(stream).await?;
        if len == u32::MAX {
            break;
        }
        anyhow::ensure!(len as usize <= 8 * 1024 * 1024, "frame too big");
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            stream.read_exact(&mut payload).await?;
        }
        let plain = maybe_decompress(&payload, compressed)?;
        hasher.update(&plain);
        bar.inc(plain.len() as u64);
        tx.send(plain).await.map_err(|_| anyhow::anyhow!("unpack lag"))?;
    }
    drop(tx);
    let got = read_trailer_hash(stream).await?;
    unpacker.await??;
    anyhow::ensure!(*hasher.finalize().as_bytes() == got, "BLAKE3 mismatch");
    bar.finish_with_message(format!("saved dir to {} OK", dest.display()));
    Ok(())
}
