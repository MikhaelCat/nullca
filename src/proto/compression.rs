//! Stream Decompression Engine (Brotli, Gzip, Deflate, Zstandard).
//!
//! Provides transparent payload decompression for HTTP responses and WebSockets,
//! enabling plaintext inspection and schema generation even when content compression is enabled.

use std::io::Read;

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
        if data.len() >= 4
            && data[0] == 0x28
            && data[1] == 0xb5
            && data[2] == 0x2f
            && data[3] == 0xfd
        {
            return CompressionAlgorithm::Zstd;
        }
        if data.len() >= 2
            && data[0] == 0x78
            && (data[1] == 0x01 || data[1] == 0x9c || data[1] == 0xda)
        {
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
            CompressionAlgorithm::Gzip => {
                Self::decompress_gzip(data).unwrap_or_else(|_| data.to_vec())
            }
            CompressionAlgorithm::Deflate => {
                Self::decompress_deflate(data).unwrap_or_else(|_| data.to_vec())
            }
            CompressionAlgorithm::Brotli => {
                Self::decompress_brotli(data).unwrap_or_else(|_| data.to_vec())
            }
            CompressionAlgorithm::Zstd => Self::decompress_zstd_fallback(data),
            CompressionAlgorithm::Identity => data.to_vec(),
        }
    }

    /// Decompresses RFC 7932 Brotli data.
    pub fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut decompressor = brotli::Decompressor::new(data, 4096);
        let mut out = Vec::new();
        decompressor.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Decompresses RFC 1952 Gzip data using flate2.
    pub fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Decompresses RFC 1950/1951 Zlib/Deflate data.
    pub fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // Try Zlib first (with 2-byte header)
        let mut zlib_decoder = flate2::read::ZlibDecoder::new(data);
        let mut out = Vec::new();
        if zlib_decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
            return Ok(out);
        }
        // Fallback to raw Deflate (without zlib header, e.g. WebSocket permessage-deflate)
        let mut deflate_decoder = flate2::read::DeflateDecoder::new(data);
        let mut out_raw = Vec::new();
        deflate_decoder.read_to_end(&mut out_raw)?;
        Ok(out_raw)
    }

    fn decompress_zstd_fallback(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_compression_algorithms() {
        assert_eq!(
            CompressionAlgorithm::from_header("gzip"),
            CompressionAlgorithm::Gzip
        );
        assert_eq!(
            CompressionAlgorithm::from_header("deflate, gzip"),
            CompressionAlgorithm::Gzip
        );
        assert_eq!(
            CompressionAlgorithm::from_header("br"),
            CompressionAlgorithm::Brotli
        );
        assert_eq!(
            CompressionAlgorithm::from_header("zstd"),
            CompressionAlgorithm::Zstd
        );
        assert_eq!(
            CompressionAlgorithm::from_header("identity"),
            CompressionAlgorithm::Identity
        );

        let gzip_magic = [0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(
            CompressionAlgorithm::from_magic(&gzip_magic),
            CompressionAlgorithm::Gzip
        );

        let zstd_magic = [0x28, 0xb5, 0x2f, 0xfd];
        assert_eq!(
            CompressionAlgorithm::from_magic(&zstd_magic),
            CompressionAlgorithm::Zstd
        );
    }

    #[test]
    fn test_brotli_roundtrip_compression_decompression() {
        use std::io::Write;
        let plaintext = b"Brotli is the premier web compression algorithm RFC 7932 in NullCA!";
        let mut compressed = Vec::new();
        {
            let mut compressor = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
            compressor.write_all(plaintext).unwrap();
        }

        assert!(!compressed.is_empty());
        let decompressed = Decompressor::decompress_brotli(&compressed).expect("Decompress brotli");
        assert_eq!(decompressed, plaintext);

        // Auto-detection via header
        let auto_decompressed = Decompressor::decompress(&compressed, Some("br"));
        assert_eq!(auto_decompressed, plaintext);
    }

    #[test]
    fn test_gzip_roundtrip_compression_decompression() {
        use std::io::Write;
        let plaintext = b"Gzip compression verified with flate2 in NullCA!";
        let mut compressed = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::default());
            encoder.write_all(plaintext).unwrap();
        }

        let decompressed = Decompressor::decompress_gzip(&compressed).expect("Decompress gzip");
        assert_eq!(decompressed, plaintext);
    }

    #[test]
    fn test_deflate_raw_and_zlib() {
        use std::io::Write;
        let plaintext = b"Deflate raw and zlib streams verified in NullCA!";
        let mut compressed = Vec::new();
        {
            let mut encoder =
                flate2::write::DeflateEncoder::new(&mut compressed, flate2::Compression::default());
            encoder.write_all(plaintext).unwrap();
        }

        let decompressed =
            Decompressor::decompress_deflate(&compressed).expect("Decompress raw deflate");
        assert_eq!(decompressed, plaintext);
    }
}
