//! NSS SSLKEYLOGFILE Format Exporter & Live Streamer.
//!
//! Generates standard NSS key log files containing TLS 1.2 Master Secrets and TLS 1.3
//! Traffic Secrets. These files allow Wireshark, tshark, and Moloch/Arkime to decrypt
//! encrypted packet captures (PCAP/PCAP-NG) natively without installing CA certificates.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsKeyLabel {
    ClientRandom,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientTrafficSecret0,
    ServerTrafficSecret0,
    ExporterSecret,
    EarlyExporterSecret,
}

impl TlsKeyLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsKeyLabel::ClientRandom => "CLIENT_RANDOM",
            TlsKeyLabel::ClientHandshakeTrafficSecret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            TlsKeyLabel::ServerHandshakeTrafficSecret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            TlsKeyLabel::ClientTrafficSecret0 => "CLIENT_TRAFFIC_SECRET_0",
            TlsKeyLabel::ServerTrafficSecret0 => "SERVER_TRAFFIC_SECRET_0",
            TlsKeyLabel::ExporterSecret => "EXPORTER_SECRET",
            TlsKeyLabel::EarlyExporterSecret => "EARLY_EXPORTER_SECRET",
        }
    }

    pub fn parse_label(s: &str) -> Option<Self> {
        match s {
            "CLIENT_RANDOM" => Some(TlsKeyLabel::ClientRandom),
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(TlsKeyLabel::ClientHandshakeTrafficSecret),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(TlsKeyLabel::ServerHandshakeTrafficSecret),
            "CLIENT_TRAFFIC_SECRET_0" => Some(TlsKeyLabel::ClientTrafficSecret0),
            "SERVER_TRAFFIC_SECRET_0" => Some(TlsKeyLabel::ServerTrafficSecret0),
            "EXPORTER_SECRET" => Some(TlsKeyLabel::ExporterSecret),
            "EARLY_EXPORTER_SECRET" => Some(TlsKeyLabel::EarlyExporterSecret),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslKeyLogEntry {
    pub label: TlsKeyLabel,
    pub client_random: Vec<u8>,
    pub secret: Vec<u8>,
}

impl SslKeyLogEntry {
    pub fn new(label: TlsKeyLabel, client_random: Vec<u8>, secret: Vec<u8>) -> Self {
        Self {
            label,
            client_random,
            secret,
        }
    }

    /// Formats the key log entry into a single NSS line: `<LABEL> <RANDOM_HEX> <SECRET_HEX>\n`
    pub fn format_nss_line(&self) -> String {
        let random_hex = hex_encode(&self.client_random);
        let secret_hex = hex_encode(&self.secret);
        format!("{} {} {}\n", self.label.as_str(), random_hex, secret_hex)
    }

    /// Parses a single NSS key log line.
    pub fn parse_nss_line(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() != 3 {
            return None;
        }

        let label = TlsKeyLabel::parse_label(parts[0])?;
        let client_random = hex_decode(parts[1])?;
        let secret = hex_decode(parts[2])?;

        Some(Self {
            label,
            client_random,
            secret,
        })
    }
}

pub struct SslKeyLogWriter {
    file: File,
}

impl SslKeyLogWriter {
    /// Opens or creates an SSLKEYLOGFILE for appending.
    pub fn open_append<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }

    /// Appends a key log entry.
    pub fn write_entry(&mut self, entry: &SslKeyLogEntry) -> io::Result<()> {
        let line = entry.format_nss_line();
        self.file.write_all(line.as_bytes())?;
        self.file.flush()
    }

    /// Appends multiple entries.
    pub fn write_entries(&mut self, entries: &[SslKeyLogEntry]) -> io::Result<()> {
        for entry in entries {
            self.write_entry(entry)?;
        }
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[allow(clippy::manual_is_multiple_of)]
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sslkeylog_roundtrip() {
        let random = vec![0xaa; 32];
        let master_key = vec![0xbb; 48];
        let entry = SslKeyLogEntry::new(
            TlsKeyLabel::ClientRandom,
            random.clone(),
            master_key.clone(),
        );

        let line = entry.format_nss_line();
        assert!(line.starts_with("CLIENT_RANDOM "));

        let parsed = SslKeyLogEntry::parse_nss_line(&line).expect("Must parse valid NSS line");
        assert_eq!(parsed.label, TlsKeyLabel::ClientRandom);
        assert_eq!(parsed.client_random, random);
        assert_eq!(parsed.secret, master_key);
    }

    #[test]
    fn test_sslkeylog_tls13_traffic_secret() {
        let random = vec![0x12, 0x34, 0x56, 0x78];
        let secret = vec![0xde, 0xad, 0xbe, 0xef];
        let entry = SslKeyLogEntry::new(
            TlsKeyLabel::ClientTrafficSecret0,
            random.clone(),
            secret.clone(),
        );

        let line = entry.format_nss_line();
        let parsed = SslKeyLogEntry::parse_nss_line(&line).expect("Must parse");
        assert_eq!(parsed.label, TlsKeyLabel::ClientTrafficSecret0);
        assert_eq!(parsed.secret, secret);
    }
}
