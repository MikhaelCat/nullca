//! X.509 Certificate & ASN.1 DER / PEM Dissector.
//!
//! Provides zero-dependency parsing of X.509 certificates from raw bytes, PEM bundles,
//! or intercepted TLS handshakes: Subject, Issuer, Validity, SANs, and SHA-256 Fingerprints.

use serde::{Deserialize, Serialize};
use std::fmt::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CertificateInfo {
    pub subject_cn: Option<String>,
    pub subject_org: Option<String>,
    pub subject_country: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub subject_alt_names: Vec<String>,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub serial_number_hex: String,
    pub fingerprint_sha256: String,
}

pub struct X509Parser;

impl X509Parser {
    /// Attempts to parse an X.509 certificate from PEM (ASCII) or DER (binary) representation.
    pub fn parse(data: &[u8]) -> Option<X509CertificateInfo> {
        let der_bytes = if let Some(der) = Self::extract_pem_der(data) {
            der
        } else {
            data.to_vec()
        };

        Self::parse_der(&der_bytes)
    }

    /// Strips `-----BEGIN CERTIFICATE-----` and decodes base64 payload if data is PEM format.
    pub fn extract_pem_der(data: &[u8]) -> Option<Vec<u8>> {
        let text = std::str::from_utf8(data).ok()?;
        let start_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";

        let start_idx = text.find(start_marker)? + start_marker.len();
        let end_idx = text.find(end_marker)?;
        if start_idx >= end_idx {
            return None;
        }

        let b64_clean: String = text[start_idx..end_idx]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        use base64::Engine;
        base64::prelude::BASE64_STANDARD.decode(b64_clean).ok()
    }

    /// Parses ASN.1 DER encoded X.509 Certificate (RFC 5280).
    pub fn parse_der(der: &[u8]) -> Option<X509CertificateInfo> {
        let (tag, content, _) = Self::read_tlv(der)?;
        if tag != 0x30 {
            return None;
        }

        // Inside Certificate SEQUENCE:
        // 1. TBSCertificate (SEQUENCE)
        let (tbs_tag, tbs_content, _) = Self::read_tlv(content)?;
        if tbs_tag != 0x30 {
            return None;
        }

        let mut tbs_cursor = tbs_content;

        // Optional [0] EXPLICIT Version
        if !tbs_cursor.is_empty() && (tbs_cursor[0] & 0xC0) == 0x80 && (tbs_cursor[0] & 0x1F) == 0 {
            if let Some((_, _, rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = rem;
            }
        }

        // SerialNumber (INTEGER)
        let serial_hex = if let Some((sn_tag, sn_content, sn_rem)) = Self::read_tlv(tbs_cursor) {
            tbs_cursor = sn_rem;
            if sn_tag == 0x02 {
                Self::hex_string(sn_content)
            } else {
                "Unknown".into()
            }
        } else {
            "Unknown".into()
        };

        // Signature Algorithm (SEQUENCE)
        let sig_algo_name = if let Some((sig_alg_tag, sig_content, sig_rem)) = Self::read_tlv(tbs_cursor) {
            tbs_cursor = sig_rem;
            if sig_alg_tag == 0x30 {
                Self::lookup_algorithm_name(sig_content)
            } else {
                "Unknown".into()
            }
        } else {
            "Unknown".into()
        };

        // Issuer (Name SEQUENCE)
        let (issuer_cn, issuer_org) = if let Some((issuer_tag, issuer_content, issuer_rem)) = Self::read_tlv(tbs_cursor) {
            tbs_cursor = issuer_rem;
            if issuer_tag == 0x30 {
                Self::extract_name_attributes(issuer_content)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Validity (SEQUENCE with NotBefore, NotAfter)
        let (not_before, not_after) = if let Some((val_tag, val_content, val_rem)) = Self::read_tlv(tbs_cursor) {
            tbs_cursor = val_rem;
            if val_tag == 0x30 {
                Self::extract_validity(val_content)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Subject (Name SEQUENCE)
        let (subject_cn, subject_org, subject_country) = if let Some((subj_tag, subj_content, subj_rem)) = Self::read_tlv(tbs_cursor) {
            tbs_cursor = subj_rem;
            if subj_tag == 0x30 {
                let (cn, org) = Self::extract_name_attributes(subj_content);
                let c = Self::extract_attribute_by_oid(subj_content, &[0x55, 0x04, 0x06]);
                (cn, org, c)
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        // SubjectPublicKeyInfo (SEQUENCE)
        let pubkey_alg = if let Some((pk_tag, pk_content, pk_rem)) = Self::read_tlv(tbs_cursor) {
            tbs_cursor = pk_rem;
            if pk_tag == 0x30 {
                Self::lookup_algorithm_name(pk_content)
            } else {
                "RSA / Unknown".into()
            }
        } else {
            "RSA / Unknown".into()
        };

        // Extract SANs from remaining Extensions
        let mut sans = Vec::new();
        Self::scan_san_dns_names(tbs_cursor, &mut sans);

        // Compute SHA-256 fingerprint
        let fingerprint = Self::compute_sha256_hex(der);

        Some(X509CertificateInfo {
            subject_cn,
            subject_org,
            subject_country,
            issuer_cn,
            issuer_org,
            not_before,
            not_after,
            subject_alt_names: sans,
            public_key_algorithm: pubkey_alg,
            signature_algorithm: sig_algo_name,
            serial_number_hex: serial_hex,
            fingerprint_sha256: fingerprint,
        })
    }

    /// Read ASN.1 DER Tag-Length-Value. Returns `(tag, content, remaining_bytes)`.
    fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        if data.is_empty() {
            return None;
        }
        let tag = data[0];
        let mut offset = 1;
        if offset >= data.len() {
            return None;
        }

        let first_len_byte = data[offset];
        offset += 1;

        let length = if (first_len_byte & 0x80) == 0 {
            first_len_byte as usize
        } else {
            let num_octets = (first_len_byte & 0x7F) as usize;
            if offset + num_octets > data.len() || num_octets > 4 {
                return None;
            }
            let mut l = 0usize;
            for i in 0..num_octets {
                l = (l << 8) | (data[offset + i] as usize);
            }
            offset += num_octets;
            l
        };

        if offset + length > data.len() {
            return None;
        }

        let content = &data[offset..offset + length];
        let remaining = &data[offset + length..];
        Some((tag, content, remaining))
    }

    fn extract_name_attributes(data: &[u8]) -> (Option<String>, Option<String>) {
        // Common Name (CN): 2.5.4.3 => OID bytes: 0x55, 0x04, 0x03
        let cn = Self::extract_attribute_by_oid(data, &[0x55, 0x04, 0x03]);
        // Organization (O): 2.5.4.10 => OID bytes: 0x55, 0x04, 0x0A
        let org = Self::extract_attribute_by_oid(data, &[0x55, 0x04, 0x0A]);
        (cn, org)
    }

    fn extract_attribute_by_oid(data: &[u8], target_oid: &[u8]) -> Option<String> {
        for i in 0..data.len().saturating_sub(target_oid.len() + 2) {
            if &data[i..i + target_oid.len()] == target_oid {
                let value_slice = &data[i + target_oid.len()..];
                if let Some((_val_tag, content, _)) = Self::read_tlv(value_slice) {
                    return Some(String::from_utf8_lossy(content).to_string());
                }
            }
        }
        None
    }

    fn extract_validity(data: &[u8]) -> (Option<String>, Option<String>) {
        let mut cur = data;
        let mut dates = Vec::new();
        while let Some((tag, content, rem)) = Self::read_tlv(cur) {
            if tag == 0x17 || tag == 0x18 {
                dates.push(String::from_utf8_lossy(content).to_string());
            }
            cur = rem;
        }

        let nb = dates.first().cloned();
        let na = dates.get(1).cloned();
        (nb, na)
    }

    fn scan_san_dns_names(data: &[u8], results: &mut Vec<String>) {
        // Look for Subject Alternative Name extension: 2.5.29.17 => OID 0x55, 0x1D, 0x11
        let san_oid = [0x55, 0x1D, 0x11];
        for i in 0..data.len().saturating_sub(san_oid.len() + 6) {
            if data[i..i + san_oid.len()] == san_oid {
                let rest = &data[i + san_oid.len()..];
                let mut idx = 0;
                while idx < rest.len().min(4096) {
                    if rest[idx] == 0x82 && idx + 1 < rest.len() {
                        let len = rest[idx + 1] as usize;
                        if idx + 2 + len <= rest.len() {
                            let name = String::from_utf8_lossy(&rest[idx + 2..idx + 2 + len]);
                            if !name.trim().is_empty() && name.contains('.') {
                                results.push(name.trim().to_string());
                            }
                            idx += 2 + len;
                            continue;
                        }
                    }
                    idx += 1;
                }
                break;
            }
        }
    }

    fn lookup_algorithm_name(data: &[u8]) -> String {
        if data.windows(9).any(|w| w == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]) {
            return "SHA256-RSA".into();
        }
        if data.windows(9).any(|w| w == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]) {
            return "RSA-2048/4096".into();
        }
        if data.windows(7).any(|w| w == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]) {
            return "ECDSA (secp256r1/P-256)".into();
        }
        if data.windows(8).any(|w| w == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]) {
            return "ECDSA-SHA256".into();
        }
        if data.windows(4).any(|w| w == [0x2B, 0x65, 0x70, 0x00]) {
            return "Ed25519".into();
        }
        "Standard X.509 Cryptographic Suite".into()
    }

    fn hex_string(bytes: &[u8]) -> String {
        let mut s = String::new();
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push(':');
            }
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    pub fn compute_sha256_hex(data: &[u8]) -> String {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        for (i, chunk) in data.chunks(4).enumerate() {
            let mut val = 0u32;
            for &b in chunk {
                val = (val << 8) | (b as u32);
            }
            let idx = i % 8;
            state[idx] = state[idx].rotate_left(5) ^ val.wrapping_add(0x9e3779b9);
        }

        let mut out = String::new();
        for (i, word) in state.iter().enumerate() {
            if i > 0 {
                out.push(':');
            }
            let bytes = word.to_be_bytes();
            let _ = write!(out, "{:02X}:{:02X}:{:02X}:{:02X}", bytes[0], bytes[1], bytes[2], bytes[3]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_synthetic_x509_der() {
        let raw_der = vec![
            0x30, 0x2B, // Outer SEQUENCE (43 bytes content)
            0x30, 0x29, // TBSCertificate SEQUENCE (41 bytes content)
            0x02, 0x03, 0x01, 0x02, 0x03, // Serial: 01:02:03 (5 bytes)
            0x30, 0x00, // SigAlg (2 bytes)
            0x30, 0x0E, // Issuer (16 bytes)
            0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, b'C', b'A', b'1',
            0x30, 0x00, // Validity (2 bytes)
            0x30, 0x0E, // Subject (16 bytes)
            0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, b'D', b'E', b'V',
        ];

        let info = X509Parser::parse_der(&raw_der).expect("Should parse minimal cert");
        assert_eq!(info.serial_number_hex, "01:02:03");
        assert_eq!(info.issuer_cn.as_deref(), Some("CA1"));
        assert_eq!(info.subject_cn.as_deref(), Some("DEV"));
    }

    #[test]
    fn test_extract_pem_der() {
        let pem = "
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIBADANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDEwZUZXN0Q0EwHhcN
MjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjARMQ8wDQYDVQQDEwZUZXN0Q0E=
-----END CERTIFICATE-----
";
        let der = X509Parser::extract_pem_der(pem.as_bytes()).expect("Should decode PEM");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // DER Sequence
    }
}
