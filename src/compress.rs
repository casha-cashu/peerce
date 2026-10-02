use anyhow::{Context, Result};

pub const LEVEL: i32 = 3;

pub fn compress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    zstd::bulk::compress(data, LEVEL).context("zstd compress")
}

pub fn decompress_chunk(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    zstd::bulk::decompress(data, cap).context("zstd decompress")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let data = vec![7u8; 10000];
        let c = compress_chunk(&data).unwrap();
        assert!(c.len() < data.len());
        let d = decompress_chunk(&c, 10000).unwrap();
        assert_eq!(d, data);
    }
}
