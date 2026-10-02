use anyhow::{Context, Result};

pub const MAGIC_V1: &[u8; 4] = b"PRC1";
pub const MAGIC_V2: &[u8; 3] = b"PRC";
pub const VER_RAW: u8 = 1;
pub const VER_ZSTD: u8 = 2;

pub fn encode_header_v1(name: &str, size: u64) -> Result<Vec<u8>> {
    let nb = name.as_bytes();
    anyhow::ensure!(
        !nb.is_empty() && nb.len() <= u16::MAX as usize,
        "bad name len"
    );
    let mut out = Vec::with_capacity(4 + 2 + nb.len() + 8);
    out.extend_from_slice(MAGIC_V1);
    out.extend_from_slice(&(nb.len() as u16).to_be_bytes());
    out.extend_from_slice(nb);
    out.extend_from_slice(&size.to_be_bytes());
    Ok(out)
}

#[allow(dead_code)]
pub fn decode_header_v1(buf: &[u8]) -> Result<(String, u64, usize)> {
    anyhow::ensure!(buf.len() >= 6, "header too short");
    anyhow::ensure!(&buf[..4] == MAGIC_V1, "bad magic");
    let n = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    anyhow::ensure!(n > 0 && n < 4096, "bad name len");
    anyhow::ensure!(buf.len() >= 6 + n + 8, "header truncated");
    let name = String::from_utf8(buf[6..6 + n].to_vec()).context("bad name")?;
    anyhow::ensure!(!name.contains('/') && name != "..", "unsafe name");
    let mut sb = [0u8; 8];
    sb.copy_from_slice(&buf[6 + n..6 + n + 8]);
    Ok((name, u64::from_be_bytes(sb), 6 + n + 8))
}

pub fn encode_header_v2(
    name: &str,
    original_size: u64,
    compressed: bool,
    is_dir: bool,
) -> Result<Vec<u8>> {
    let nb = name.as_bytes();
    anyhow::ensure!(
        !nb.is_empty() && nb.len() <= u16::MAX as usize,
        "bad name len"
    );
    let ver = if compressed { VER_ZSTD } else { VER_RAW };
    let mut flags = 0u8;
    if compressed {
        flags |= 0x01;
    }
    if is_dir {
        flags |= 0x02;
    }
    let mut out = Vec::with_capacity(3 + 1 + 1 + 2 + nb.len() + 8);
    out.extend_from_slice(MAGIC_V2);
    out.push(ver);
    out.push(flags);
    out.extend_from_slice(&(nb.len() as u16).to_be_bytes());
    out.extend_from_slice(nb);
    out.extend_from_slice(&original_size.to_be_bytes());
    Ok(out)
}

#[allow(dead_code)]
pub fn decode_header_v2(buf: &[u8]) -> Result<(String, u64, bool, bool, usize)> {
    anyhow::ensure!(buf.len() >= 7, "header too short");
    anyhow::ensure!(&buf[..3] == MAGIC_V2, "bad magic");
    anyhow::ensure!(buf[3] == VER_RAW || buf[3] == VER_ZSTD, "bad version");
    let compressed = buf[4] & 0x01 != 0;
    let is_dir = buf[4] & 0x02 != 0;
    let n = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    anyhow::ensure!(n > 0 && n < 4096, "bad name len");
    anyhow::ensure!(buf.len() >= 7 + n + 8, "header truncated");
    let name = String::from_utf8(buf[7..7 + n].to_vec()).context("bad name")?;
    anyhow::ensure!(!name.contains('/') && name != "..", "unsafe name");
    let mut sb = [0u8; 8];
    sb.copy_from_slice(&buf[7 + n..7 + n + 8]);
    Ok((name, u64::from_be_bytes(sb), compressed, is_dir, 7 + n + 8))
}

#[allow(dead_code)]
pub fn encode_frame_header(len: u32) -> [u8; 4] {
    len.to_be_bytes()
}

#[allow(dead_code)]
pub fn is_end_frame(len: u32) -> bool {
    len == u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_roundtrip() {
        let buf = encode_header_v1("dataset.tar.gz", 12345678).unwrap();
        let (name, size, used) = decode_header_v1(&buf).unwrap();
        assert_eq!(name, "dataset.tar.gz");
        assert_eq!(size, 12345678);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn v1_rejects_bad_magic() {
        let mut buf = encode_header_v1("a.bin", 1).unwrap();
        buf[0] = b'X';
        assert!(decode_header_v1(&buf).is_err());
    }

    #[test]
    fn v1_rejects_path_traversal() {
        let buf = encode_header_v1("../evil", 1).unwrap();
        assert!(decode_header_v1(&buf).is_err());
    }

    #[test]
    fn v2_header_marks_compression() {
        let raw = encode_header_v2("f.bin", 100, false, false).unwrap();
        let z = encode_header_v2("f.bin", 100, true, false).unwrap();
        assert_eq!(raw[3], VER_RAW);
        assert_eq!(z[3], VER_ZSTD);
        let (_, _, c, d, _) = decode_header_v2(&z).unwrap();
        assert!(c && !d);
        let dir = encode_header_v2("mydir", 0, true, true).unwrap();
        let (_, _, _, is_dir, _) = decode_header_v2(&dir).unwrap();
        assert!(is_dir);
    }

    #[test]
    fn frame_end_marker() {
        assert!(is_end_frame(u32::MAX));
        assert!(!is_end_frame(128 * 1024));
    }
}
