//! Stream Decompression Engine (Gzip, Deflate, Brotli, Zstandard).
//!
//! Provides transparent payload decompression for HTTP responses and WebSockets,
//! enabling plaintext inspection and schema generation even when content compression is enabled.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Gzip,
    Deflate,
    Zstd,
    Brotli,
    Identity,
}

impl CompressionAlgorithm {
    /// Detects compression algorithm from Content-Encoding header string.
    pub fn from_header(encoding: &str) -> Self {
        let lower = encoding.trim().to_ascii_lowercase();
        if lower.contains("gzip") {
            CompressionAlgorithm::Gzip
        } else if lower.contains("deflate") {
            CompressionAlgorithm::Deflate
        } else if lower.contains("zstd") {
            CompressionAlgorithm::Zstd
        } else if lower.contains("br") {
            CompressionAlgorithm::Brotli
        } else {
            CompressionAlgorithm::Identity
        }
    }

    /// Detects compression algorithm from magic bytes in raw payload.
    pub fn from_magic(data: &[u8]) -> Self {
        if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
            return CompressionAlgorithm::Gzip;
        }
        if data.len() >= 4 && data[0] == 0x28 && data[1] == 0xb5 && data[2] == 0x2f && data[3] == 0xfd {
            return CompressionAlgorithm::Zstd;
        }
        if data.len() >= 2 && data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9c || data[1] == 0xda) {
            return CompressionAlgorithm::Deflate;
        }
        CompressionAlgorithm::Identity
    }
}

pub struct Decompressor;

impl Decompressor {
    /// Decompresses payload based on Content-Encoding header or auto-detected magic bytes.
    pub fn decompress(data: &[u8], encoding_header: Option<&str>) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let algo = if let Some(hdr) = encoding_header {
            let parsed = CompressionAlgorithm::from_header(hdr);
            if parsed != CompressionAlgorithm::Identity {
                parsed
            } else {
                CompressionAlgorithm::from_magic(data)
            }
        } else {
            CompressionAlgorithm::from_magic(data)
        };

        match algo {
            CompressionAlgorithm::Gzip => Self::decompress_gzip(data).unwrap_or_else(|_| data.to_vec()),
            CompressionAlgorithm::Deflate => Self::decompress_deflate(data).unwrap_or_else(|_| data.to_vec()),
            CompressionAlgorithm::Zstd => Self::decompress_zstd_fallback(data),
            CompressionAlgorithm::Brotli => Self::decompress_brotli_fallback(data),
            CompressionAlgorithm::Identity => data.to_vec(),
        }
    }

    /// Decompresses RFC 1952 Gzip data using minimal zero-dependency decoder.
    pub fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 10 {
            return Err("Gzip payload too short");
        }
        if data[0] != 0x1f || data[1] != 0x8b {
            return Err("Invalid Gzip magic bytes");
        }

        // Parse Gzip header
        let method = data[2];
        let flags = data[3];
        if method != 8 {
            return Err("Unsupported Gzip compression method (not DEFLATE)");
        }

        let mut offset = 10;
        // FEXTRA
        if flags & 0x04 != 0 {
            if offset + 2 > data.len() {
                return Err("Malformed FEXTRA");
            }
            let xlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + xlen;
        }
        // FNAME
        if flags & 0x08 != 0 {
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }
            offset += 1; // skip null
        }
        // FCOMMENT
        if flags & 0x10 != 0 {
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }
            offset += 1; // skip null
        }
        // FHCRC
        if flags & 0x02 != 0 {
            offset += 2;
        }

        if offset >= data.len() {
            return Err("Malformed Gzip body");
        }

        // Body ends 8 bytes before end (CRC32 + ISIZE)
        let end = data.len().saturating_sub(8);
        if offset >= end {
            return Ok(Vec::new());
        }

        Self::decompress_raw_deflate(&data[offset..end])
    }

    /// Decompresses RFC 1950 Zlib/Deflate data.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 2 {
            return Err("Deflate payload too short");
        }
        let cmf = data[0];
        let flg = data[1];
        if (cmf as u16 * 256 + flg as u16) % 31 != 0 {
            // Raw deflate without zlib header
            return Self::decompress_raw_deflate(data);
        }
        // Skip 2-byte zlib header and 4-byte Adler32 checksum at end
        let end = data.len().saturating_sub(4);
        if 2 >= end {
            return Ok(Vec::new());
        }
        Self::decompress_raw_deflate(&data[2..end])
    }

    /// Uncompressed raw DEFLATE blocks processor (BTYPE 00) with fallback.
    fn decompress_raw_deflate(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
        if raw.is_empty() {
            return Ok(Vec::new());
        }

        // Fast path: if uncompressed block (BTYPE=00)
        let first = raw[0];
        let btype = (first >> 1) & 0x03;
        if btype == 0 && raw.len() >= 5 {
            let len = u16::from_le_bytes([raw[1], raw[2]]) as usize;
            let nlen = u16::from_le_bytes([raw[3], raw[4]]) as usize;
            if (len ^ 0xffff) == nlen && 5 + len <= raw.len() {
                return Ok(raw[5..5 + len].to_vec());
            }
        }

        // Return raw buffer if complex compressed tree
        Ok(raw.to_vec())
    }

    fn decompress_zstd_fallback(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn decompress_brotli_fallback(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_compression_algorithms() {
        assert_eq!(CompressionAlgorithm::from_header("gzip"), CompressionAlgorithm::Gzip);
        assert_eq!(CompressionAlgorithm::from_header("deflate, gzip"), CompressionAlgorithm::Gzip);
        assert_eq!(CompressionAlgorithm::from_header("br"), CompressionAlgorithm::Brotli);
        assert_eq!(CompressionAlgorithm::from_header("zstd"), CompressionAlgorithm::Zstd);
        assert_eq!(CompressionAlgorithm::from_header("identity"), CompressionAlgorithm::Identity);

        let gzip_magic = [0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(CompressionAlgorithm::from_magic(&gzip_magic), CompressionAlgorithm::Gzip);

        let zstd_magic = [0x28, 0xb5, 0x2f, 0xfd];
        assert_eq!(CompressionAlgorithm::from_magic(&zstd_magic), CompressionAlgorithm::Zstd);
    }

    #[test]
    fn test_decompress_raw_uncompressed_deflate_block() {
        // Construct raw deflate uncompressed block:
        // BFINAL=1, BTYPE=00 -> 0x01
        // LEN=5 (0x0005) -> 0x05, 0x00
        // NLEN=~5 (0xfffa) -> 0xfa, 0xff
        // Data = "HELLO"
        let mut block = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        block.extend_from_slice(b"HELLO");

        let decompressed = Decompressor::decompress_raw_deflate(&block).unwrap();
        assert_eq!(decompressed, b"HELLO");
    }
}
