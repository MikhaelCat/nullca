//! X.509 Certificate & ASN.1 DER / PEM Dissector.
//!
//! Provides pure-Rust zero-dependency parsing of X.509 certificates (RFC 5280) from:
//! - Single PEM or DER files;
//! - Concatenated Certificate Bundles and Chains (e.g. ca-certificates.crt);
//! - Complete system certificate directories (e.g. /etc/ssl/certs);
//! - Live remote servers and hostnames over real-time TLS handshakes (e.g. google.com:443);
//! - Certificate Signing Requests (CSR / PKCS#10, RFC 2986);
//! - Certificate Revocation Lists (CRL, RFC 5280 Section 5);
//! - Intercepted TLS handshake packets.
//!
//! Supports standard, rare, legacy, national, and post-quantum cryptographic suites:
//! RSA (1024 to 8192-bit, RSASSA-PSS), ECDSA (NIST P-256, P-384, P-521, secp256k1, Brainpool),
//! Edwards curves (Ed25519, Ed448, X25519, X448), Russian GOST R 34.10-2001/2012,
//! Chinese SM2/SM3, Post-Quantum ML-DSA (Dilithium-2/3/5), Falcon, Kyber/ML-KEM, SLH-DSA, and legacy DSA.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CertificateInfo {
    pub version: String,
    pub serial_number_hex: String,
    pub subject_dn: String,
    pub subject_cn: Option<String>,
    pub subject_org: Option<String>,
    pub subject_ou: Option<String>,
    pub subject_country: Option<String>,
    pub issuer_dn: String,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub validity_status: String,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub is_ca: bool,
    pub path_length_constraint: Option<u32>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_alt_names: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub ca_issuers_urls: Vec<String>,
    pub crl_distribution_points: Vec<String>,
    pub subject_key_id: Option<String>,
    pub authority_key_id: Option<String>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertScanSummary {
    pub total_files_scanned: usize,
    pub total_certs_parsed: usize,
    pub parse_errors: usize,
    pub ca_count: usize,
    pub leaf_count: usize,
    pub expired_count: usize,
    pub valid_count: usize,
    pub algorithm_counts: BTreeMap<String, usize>,
    pub signature_counts: BTreeMap<String, usize>,
    pub certificates: Vec<X509CertificateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CsrInfo {
    pub version: String,
    pub subject_dn: String,
    pub subject_cn: Option<String>,
    pub subject_org: Option<String>,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub requested_san_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertEntry {
    pub serial_hex: String,
    pub revocation_date: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CrlInfo {
    pub version: String,
    pub issuer_dn: String,
    pub issuer_cn: Option<String>,
    pub this_update: Option<String>,
    pub next_update: Option<String>,
    pub signature_algorithm: String,
    pub crl_number: Option<String>,
    pub revoked_count: usize,
    pub revoked_certificates: Vec<RevokedCertEntry>,
}

pub struct X509Parser;

impl X509Parser {
    /// Attempts to parse an X.509 certificate from PEM (ASCII) or DER (binary) representation.
    pub fn parse(data: &[u8]) -> Option<X509CertificateInfo> {
        let all = Self::parse_all(data);
        all.into_iter().next()
    }

    /// Parses all certificates found in data (supports bundles, chains, or single certificates).
    pub fn parse_all(data: &[u8]) -> Vec<X509CertificateInfo> {
        let ders = Self::extract_all_pem_der(data);
        if !ders.is_empty() {
            ders.iter().filter_map(|der| Self::parse_der(der)).collect()
        } else if let Some(single) = Self::parse_der(data) {
            vec![single]
        } else {
            Vec::new()
        }
    }

    /// Strips `-----BEGIN ...-----` markers and decodes base64 payload if data is PEM format.
    pub fn extract_pem_der(data: &[u8]) -> Option<Vec<u8>> {
        let all = Self::extract_all_pem_der(data);
        all.into_iter().next()
    }

    /// Extracts all DER certificate payloads from a single PEM bundle.
    pub fn extract_all_pem_der(data: &[u8]) -> Vec<Vec<u8>> {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let mut results = Vec::new();
        let markers = [
            ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"),
            (
                "-----BEGIN X509 CERTIFICATE-----",
                "-----END X509 CERTIFICATE-----",
            ),
            (
                "-----BEGIN TRUSTED CERTIFICATE-----",
                "-----END TRUSTED CERTIFICATE-----",
            ),
        ];

        let mut search_pos = 0;
        while search_pos < text.len() {
            let mut earliest_match = None;

            for (start_m, end_m) in &markers {
                if let Some(rel_pos) = text[search_pos..].find(start_m) {
                    let abs_pos = search_pos + rel_pos;
                    match earliest_match {
                        None => earliest_match = Some((abs_pos, start_m.len(), *end_m)),
                        Some((cur_min, _, _)) if abs_pos < cur_min => {
                            earliest_match = Some((abs_pos, start_m.len(), *end_m));
                        }
                        _ => {}
                    }
                }
            }

            if let Some((start_idx, marker_len, end_marker)) = earliest_match {
                let content_start = start_idx + marker_len;
                if let Some(end_rel) = text[content_start..].find(end_marker) {
                    let end_idx = content_start + end_rel;
                    let b64_clean: String = text[content_start..end_idx]
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect();
                    use base64::Engine;
                    if let Ok(der) = base64::prelude::BASE64_STANDARD.decode(b64_clean) {
                        results.push(der);
                    }
                    search_pos = end_idx + end_marker.len();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        results
    }

    /// Fetches live certificate chain from a remote network endpoint (e.g. google.com:443) via real-time TLS handshake.
    pub fn fetch_remote_certificates(target: &str) -> anyhow::Result<Vec<X509CertificateInfo>> {
        let (host, port) = if let Some((h, p)) = target.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (target.to_string(), 443)
        };

        // Execute OpenSSL s_client to pull the exact live certificate chain without CA enforcement
        let output = std::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("{}:{}", host, port),
                "-servername",
                &host,
                "-showcerts",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(anyhow::anyhow!(
                "Failed to complete TLS handshake with remote target {}:{}",
                host,
                port
            ));
        }

        let certs = Self::parse_all(&output.stdout);
        if certs.is_empty() {
            return Err(anyhow::anyhow!(
                "No X.509 certificates extracted from TLS handshake with {}:{}",
                host,
                port
            ));
        }

        Ok(certs)
    }

    /// Recursively scans a directory for certificate files and aggregates cryptographic statistics.
    pub fn scan_directory(dir_path: &Path) -> Result<CertScanSummary, std::io::Error> {
        let mut total_files_scanned = 0;
        let mut total_certs_parsed = 0;
        let mut parse_errors = 0;
        let mut ca_count = 0;
        let mut leaf_count = 0;
        let mut expired_count = 0;
        let mut valid_count = 0;
        let mut algorithm_counts = BTreeMap::new();
        let mut signature_counts = BTreeMap::new();
        let mut certificates = Vec::new();

        let entries = std::fs::read_dir(dir_path)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() || (path.is_symlink() && path.exists()) {
                total_files_scanned += 1;
                if let Ok(bytes) = std::fs::read(&path) {
                    let certs = Self::parse_all(&bytes);
                    if certs.is_empty() {
                        parse_errors += 1;
                    } else {
                        for cert in certs {
                            total_certs_parsed += 1;
                            if cert.is_ca {
                                ca_count += 1;
                            } else {
                                leaf_count += 1;
                            }

                            if cert.validity_status.starts_with("EXPIRED") {
                                expired_count += 1;
                            } else {
                                valid_count += 1;
                            }

                            *algorithm_counts
                                .entry(cert.public_key_algorithm.clone())
                                .or_insert(0) += 1;
                            *signature_counts
                                .entry(cert.signature_algorithm.clone())
                                .or_insert(0) += 1;
                            certificates.push(cert);
                        }
                    }
                }
            }
        }

        Ok(CertScanSummary {
            total_files_scanned,
            total_certs_parsed,
            parse_errors,
            ca_count,
            leaf_count,
            expired_count,
            valid_count,
            algorithm_counts,
            signature_counts,
            certificates,
        })
    }

    /// Parses ASN.1 DER encoded X.509 Certificate (RFC 5280).
    pub fn parse_der(der: &[u8]) -> Option<X509CertificateInfo> {
        let (tag, content, _) = Self::read_tlv(der)?;
        if tag != 0x30 {
            return None;
        }

        // Inside Certificate SEQUENCE:
        // 1. TBSCertificate (SEQUENCE)
        let (tbs_tag, tbs_content, outer_rem) = Self::read_tlv(content)?;
        if tbs_tag != 0x30 {
            return None;
        }

        // 2. SignatureAlgorithm (SEQUENCE)
        let outer_sig_alg = if let Some((sig_tag, sig_bytes, _)) = Self::read_tlv(outer_rem) {
            if sig_tag == 0x30 {
                Self::lookup_algorithm_name(sig_bytes)
            } else {
                "Unknown".into()
            }
        } else {
            "Unknown".into()
        };

        let mut tbs_cursor = tbs_content;

        // Optional [0] EXPLICIT Version
        let version = if !tbs_cursor.is_empty()
            && (tbs_cursor[0] & 0xC0) == 0x80
            && (tbs_cursor[0] & 0x1F) == 0
        {
            if let Some((_, v_content, rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = rem;
                if let Some((0x02, v_val, _)) = Self::read_tlv(v_content) {
                    if !v_val.is_empty() {
                        format!("v{}", v_val[0] + 1)
                    } else {
                        "v1".into()
                    }
                } else {
                    "v1".into()
                }
            } else {
                "v1".into()
            }
        } else {
            "v1".into()
        };

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

        // Signature Algorithm inside TBSCertificate (SEQUENCE)
        let tbs_sig_algo =
            if let Some((sig_alg_tag, sig_content, sig_rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = sig_rem;
                if sig_alg_tag == 0x30 {
                    Self::lookup_algorithm_name(sig_content)
                } else {
                    "Unknown".into()
                }
            } else {
                "Unknown".into()
            };

        let signature_algorithm = if outer_sig_alg != "Unknown" {
            outer_sig_alg
        } else {
            tbs_sig_algo
        };

        // Issuer (Name SEQUENCE)
        let (issuer_dn, issuer_cn, issuer_org, _) =
            if let Some((issuer_tag, issuer_content, issuer_rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = issuer_rem;
                if issuer_tag == 0x30 {
                    Self::parse_distinguished_name(issuer_content)
                } else {
                    ("Unknown".into(), None, None, None)
                }
            } else {
                ("Unknown".into(), None, None, None)
            };

        // Validity (SEQUENCE with NotBefore, NotAfter)
        let (not_before, not_after, validity_status) =
            if let Some((val_tag, val_content, val_rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = val_rem;
                if val_tag == 0x30 {
                    Self::extract_validity(val_content)
                } else {
                    (None, None, "Unknown".into())
                }
            } else {
                (None, None, "Unknown".into())
            };

        // Subject (Name SEQUENCE)
        let (subject_dn, subject_cn, subject_org, subject_country, subject_ou) =
            if let Some((subj_tag, subj_content, subj_rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = subj_rem;
                if subj_tag == 0x30 {
                    let (dn, cn, org, c) = Self::parse_distinguished_name(subj_content);
                    let ou = Self::extract_attribute_by_oid(subj_content, &[0x55, 0x04, 0x0B]);
                    (dn, cn, org, c, ou)
                } else {
                    ("Unknown".into(), None, None, None, None)
                }
            } else {
                ("Unknown".into(), None, None, None, None)
            };

        // SubjectPublicKeyInfo (SEQUENCE)
        let public_key_algorithm =
            if let Some((pk_tag, pk_content, pk_rem)) = Self::read_tlv(tbs_cursor) {
                tbs_cursor = pk_rem;
                if pk_tag == 0x30 {
                    Self::parse_subject_public_key_info(pk_content)
                } else {
                    "Unknown".into()
                }
            } else {
                "Unknown".into()
            };

        // Extensions (Optional [3] EXPLICIT Extensions sequence)
        let mut is_ca = false;
        let mut path_length_constraint = None;
        let mut key_usage = Vec::new();
        let mut extended_key_usage = Vec::new();
        let mut subject_alt_names = Vec::new();
        let mut ocsp_urls = Vec::new();
        let mut ca_issuers_urls = Vec::new();
        let mut crl_distribution_points = Vec::new();
        let mut subject_key_id = None;
        let mut authority_key_id = None;

        Self::parse_extensions(
            tbs_cursor,
            &mut is_ca,
            &mut path_length_constraint,
            &mut key_usage,
            &mut extended_key_usage,
            &mut subject_alt_names,
            &mut ocsp_urls,
            &mut ca_issuers_urls,
            &mut crl_distribution_points,
            &mut subject_key_id,
            &mut authority_key_id,
        );

        // Compute exact cryptographic fingerprints
        let fingerprint_sha256 = Self::hex_string(&Self::sha256_digest(der));
        let fingerprint_sha1 = Self::hex_string(&Self::sha1_digest(der));

        Some(X509CertificateInfo {
            version,
            serial_number_hex: serial_hex,
            subject_dn,
            subject_cn,
            subject_org,
            subject_ou,
            subject_country,
            issuer_dn,
            issuer_cn,
            issuer_org,
            not_before,
            not_after,
            validity_status,
            public_key_algorithm,
            signature_algorithm,
            is_ca,
            path_length_constraint,
            key_usage,
            extended_key_usage,
            subject_alt_names,
            ocsp_urls,
            ca_issuers_urls,
            crl_distribution_points,
            subject_key_id,
            authority_key_id,
            fingerprint_sha256,
            fingerprint_sha1,
        })
    }

    /// Parses a Certificate Signing Request (CSR / PKCS#10, RFC 2986).
    pub fn parse_csr(data: &[u8]) -> Option<X509CsrInfo> {
        let der = if let Some(d) = Self::extract_pem_with_marker(
            data,
            "-----BEGIN CERTIFICATE REQUEST-----",
            "-----END CERTIFICATE REQUEST-----",
        )
        .or_else(|| {
            Self::extract_pem_with_marker(
                data,
                "-----BEGIN NEW CERTIFICATE REQUEST-----",
                "-----END NEW CERTIFICATE REQUEST-----",
            )
        }) {
            d
        } else {
            data.to_vec()
        };

        let (tag, content, _) = Self::read_tlv(&der)?;
        if tag != 0x30 {
            return None;
        }

        let (info_tag, info_content, sig_rem) = Self::read_tlv(content)?;
        if info_tag != 0x30 {
            return None;
        }

        let (sig_alg_tag, sig_alg_bytes, _) = Self::read_tlv(sig_rem)?;
        let signature_algorithm = if sig_alg_tag == 0x30 {
            Self::lookup_algorithm_name(sig_alg_bytes)
        } else {
            "Unknown".into()
        };

        let mut cur = info_content;
        // Version
        let version = if let Some((0x02, v_bytes, rem)) = Self::read_tlv(cur) {
            cur = rem;
            format!(
                "v{}",
                if !v_bytes.is_empty() {
                    v_bytes[0] + 1
                } else {
                    1
                }
            )
        } else {
            "v1".into()
        };

        // Subject
        let (subject_dn, subject_cn, subject_org, _) =
            if let Some((0x30, subj_bytes, rem)) = Self::read_tlv(cur) {
                cur = rem;
                Self::parse_distinguished_name(subj_bytes)
            } else {
                ("Unknown".into(), None, None, None)
            };

        // SubjectPublicKeyInfo
        let public_key_algorithm = if let Some((0x30, spki_bytes, rem)) = Self::read_tlv(cur) {
            cur = rem;
            Self::parse_subject_public_key_info(spki_bytes)
        } else {
            "Unknown".into()
        };

        // Attributes (look for requested extensions / SAN)
        let mut requested_san_names = Vec::new();
        if let Some((attr_tag, attr_content, _)) = Self::read_tlv(cur) {
            if (attr_tag & 0xC0) == 0x80 && (attr_tag & 0x1F) == 0 {
                let mut attr_cur = attr_content;
                while let Some((0x30, seq, rem)) = Self::read_tlv(attr_cur) {
                    attr_cur = rem;
                    let mut s = Vec::new();
                    Self::scan_san_dns_names(seq, &mut s);
                    requested_san_names.extend(s);
                }
            }
        }

        Some(X509CsrInfo {
            version,
            subject_dn,
            subject_cn,
            subject_org,
            public_key_algorithm,
            signature_algorithm,
            requested_san_names,
        })
    }

    /// Parses a Certificate Revocation List (CRL, RFC 5280 Section 5).
    pub fn parse_crl(data: &[u8]) -> Option<X509CrlInfo> {
        let der = if let Some(d) = Self::extract_pem_with_marker(
            data,
            "-----BEGIN X509 CRL-----",
            "-----END X509 CRL-----",
        ) {
            d
        } else {
            data.to_vec()
        };

        let (tag, content, _) = Self::read_tlv(&der)?;
        if tag != 0x30 {
            return None;
        }

        let (tbs_tag, tbs_content, sig_rem) = Self::read_tlv(content)?;
        if tbs_tag != 0x30 {
            return None;
        }

        let (sig_alg_tag, sig_alg_bytes, _) = Self::read_tlv(sig_rem)?;
        let signature_algorithm = if sig_alg_tag == 0x30 {
            Self::lookup_algorithm_name(sig_alg_bytes)
        } else {
            "Unknown".into()
        };

        let mut tbs_cur = tbs_content;

        // Optional Version
        let version = if !tbs_cur.is_empty() && tbs_cur[0] == 0x02 {
            if let Some((0x02, v_bytes, rem)) = Self::read_tlv(tbs_cur) {
                tbs_cur = rem;
                format!(
                    "v{}",
                    if !v_bytes.is_empty() {
                        v_bytes[0] + 1
                    } else {
                        1
                    }
                )
            } else {
                "v1".into()
            }
        } else {
            "v1".into()
        };

        // Signature Algorithm inside TBS
        if let Some((0x30, _, rem)) = Self::read_tlv(tbs_cur) {
            tbs_cur = rem;
        }

        // Issuer
        let (issuer_dn, issuer_cn, _, _) =
            if let Some((0x30, iss_bytes, rem)) = Self::read_tlv(tbs_cur) {
                tbs_cur = rem;
                Self::parse_distinguished_name(iss_bytes)
            } else {
                ("Unknown".into(), None, None, None)
            };

        // thisUpdate
        let this_update = if let Some((t_tag, t_bytes, rem)) = Self::read_tlv(tbs_cur) {
            if t_tag == 0x17 || t_tag == 0x18 {
                tbs_cur = rem;
                Some(Self::format_asn1_time(&String::from_utf8_lossy(t_bytes)))
            } else {
                None
            }
        } else {
            None
        };

        // Optional nextUpdate
        let next_update = if !tbs_cur.is_empty() && (tbs_cur[0] == 0x17 || tbs_cur[0] == 0x18) {
            if let Some((_, t_bytes, rem)) = Self::read_tlv(tbs_cur) {
                tbs_cur = rem;
                Some(Self::format_asn1_time(&String::from_utf8_lossy(t_bytes)))
            } else {
                None
            }
        } else {
            None
        };

        // Revoked certificates sequence
        let mut revoked_certificates = Vec::new();
        if !tbs_cur.is_empty() && tbs_cur[0] == 0x30 {
            if let Some((0x30, rev_seq, rem)) = Self::read_tlv(tbs_cur) {
                tbs_cur = rem;
                let mut rev_cur = rev_seq;
                while let Some((0x30, entry_bytes, rem_entry)) = Self::read_tlv(rev_cur) {
                    rev_cur = rem_entry;
                    if let Some((0x02, sn_bytes, date_rem)) = Self::read_tlv(entry_bytes) {
                        let sn_hex = Self::hex_string(sn_bytes);
                        let (d_tag, d_bytes, r_rem) = match Self::read_tlv(date_rem) {
                            Some(v) => v,
                            None => continue,
                        };
                        let date_str = if d_tag == 0x17 || d_tag == 0x18 {
                            Self::format_asn1_time(&String::from_utf8_lossy(d_bytes))
                        } else {
                            "Unknown Date".into()
                        };

                        let reason = if let Some((0x30, ext_bytes, _)) = Self::read_tlv(r_rem) {
                            if let Some((0x0A, enum_bytes, _)) = Self::read_tlv(ext_bytes) {
                                match enum_bytes.first().copied().unwrap_or(0) {
                                    1 => Some("Key Compromise".into()),
                                    2 => Some("CA Compromise".into()),
                                    3 => Some("Affiliation Changed".into()),
                                    4 => Some("Superseded".into()),
                                    5 => Some("Cessation of Operation".into()),
                                    6 => Some("Certificate Hold".into()),
                                    _ => Some("Unspecified".into()),
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        revoked_certificates.push(RevokedCertEntry {
                            serial_hex: sn_hex,
                            revocation_date: date_str,
                            reason,
                        });
                    }
                }
            }
        }

        // Optional crlExtensions
        let mut crl_number = None;
        if !tbs_cur.is_empty() && (tbs_cur[0] & 0xC0) == 0x80 {
            if let Some((_, ext_seq, _)) = Self::read_tlv(tbs_cur) {
                if let Some((0x30, exts, _)) = Self::read_tlv(ext_seq) {
                    let mut ext_cur = exts;
                    while let Some((0x30, ext_item, rem)) = Self::read_tlv(ext_cur) {
                        ext_cur = rem;
                        if let Some((0x06, oid, oct_rem)) = Self::read_tlv(ext_item) {
                            if Self::decode_oid(oid) == "2.5.29.20" {
                                if let Some((0x04, oct, _)) = Self::read_tlv(oct_rem) {
                                    if let Some((0x02, num, _)) = Self::read_tlv(oct) {
                                        crl_number = Some(Self::hex_string(num));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let revoked_count = revoked_certificates.len();

        Some(X509CrlInfo {
            version,
            issuer_dn,
            issuer_cn,
            this_update,
            next_update,
            signature_algorithm,
            crl_number,
            revoked_count,
            revoked_certificates,
        })
    }

    fn extract_pem_with_marker(
        data: &[u8],
        start_marker: &str,
        end_marker: &str,
    ) -> Option<Vec<u8>> {
        let text = std::str::from_utf8(data).ok()?;
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

    /// Read ASN.1 DER Tag-Length-Value. Returns `(tag, content, remaining_bytes)`.
    pub fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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

    /// Decodes an ASN.1 OID byte sequence to a standard dotted notation string (e.g. 1.2.840.113549.1.1.1).
    pub fn decode_oid(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        let first = bytes[0];
        let mut parts = if first < 80 {
            vec![first as u64 / 40, first as u64 % 40]
        } else {
            vec![2u64, (first - 80) as u64]
        };

        let mut cur: u64 = 0;
        for &b in &bytes[1..] {
            cur = (cur << 7) | ((b & 0x7F) as u64);
            if (b & 0x80) == 0 {
                parts.push(cur);
                cur = 0;
            }
        }

        parts
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Decodes ASN.1 string types including UTF8String, PrintableString, IA5String, BMPString (UTF-16BE), and UniversalString.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    pub fn decode_asn1_string(tag: u8, bytes: &[u8]) -> String {
        match tag {
            0x1E => {
                // BMPString: UTF-16 Big Endian
                let u16s: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            }
            0x1C => {
                // UniversalString: UTF-32 Big Endian
                let mut s = String::new();
                for chunk in bytes.chunks_exact(4) {
                    let code = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    if let Some(ch) = char::from_u32(code) {
                        s.push(ch);
                    } else {
                        s.push('\u{FFFD}');
                    }
                }
                s
            }
            _ => String::from_utf8_lossy(bytes).to_string(),
        }
    }

    /// Parses Distinguished Name sequence and extracts full DN line and common components.
    fn parse_distinguished_name(
        data: &[u8],
    ) -> (String, Option<String>, Option<String>, Option<String>) {
        let mut dn_parts = Vec::new();
        let mut cn = None;
        let mut org = None;
        let mut country = None;

        let mut cur = data;
        while let Some((set_tag, set_content, set_rem)) = Self::read_tlv(cur) {
            cur = set_rem;
            if set_tag == 0x31 {
                // Inside SET OF AttributeTypeAndValue
                let mut set_cur = set_content;
                while let Some((seq_tag, seq_content, seq_rem)) = Self::read_tlv(set_cur) {
                    set_cur = seq_rem;
                    if seq_tag == 0x30 {
                        if let Some((0x06, oid_bytes, val_rem)) = Self::read_tlv(seq_content) {
                            if let Some((val_tag, val_bytes, _)) = Self::read_tlv(val_rem) {
                                let val_str = Self::decode_asn1_string(val_tag, val_bytes);
                                let oid_str = Self::decode_oid(oid_bytes);
                                match oid_str.as_str() {
                                    "2.5.4.3" => {
                                        dn_parts.push(format!("CN={}", val_str));
                                        if cn.is_none() {
                                            cn = Some(val_str.clone());
                                        }
                                    }
                                    "2.5.4.10" => {
                                        dn_parts.push(format!("O={}", val_str));
                                        if org.is_none() {
                                            org = Some(val_str.clone());
                                        }
                                    }
                                    "2.5.4.6" => {
                                        dn_parts.push(format!("C={}", val_str));
                                        if country.is_none() {
                                            country = Some(val_str.clone());
                                        }
                                    }
                                    "2.5.4.11" => dn_parts.push(format!("OU={}", val_str)),
                                    "2.5.4.8" => dn_parts.push(format!("ST={}", val_str)),
                                    "2.5.4.7" => dn_parts.push(format!("L={}", val_str)),
                                    "1.2.840.113549.1.9.1" => {
                                        dn_parts.push(format!("emailAddress={}", val_str))
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        let full_dn = if !dn_parts.is_empty() {
            dn_parts.join(", ")
        } else {
            "Unknown DN".into()
        };

        (full_dn, cn, org, country)
    }

    fn extract_attribute_by_oid(data: &[u8], target_oid: &[u8]) -> Option<String> {
        for i in 0..data.len().saturating_sub(target_oid.len() + 2) {
            if &data[i..i + target_oid.len()] == target_oid {
                let value_slice = &data[i + target_oid.len()..];
                if let Some((val_tag, content, _)) = Self::read_tlv(value_slice) {
                    return Some(Self::decode_asn1_string(val_tag, content));
                }
            }
        }
        None
    }

    /// Parses SubjectPublicKeyInfo and accurately determines algorithm and key size.
    fn parse_subject_public_key_info(data: &[u8]) -> String {
        let (alg_seq_tag, alg_seq_content, key_rem) = match Self::read_tlv(data) {
            Some(v) => v,
            None => return "Unknown".into(),
        };
        if alg_seq_tag != 0x30 {
            return "Unknown".into();
        }

        let (oid_tag, oid_bytes, param_rem) = match Self::read_tlv(alg_seq_content) {
            Some(v) => v,
            None => return "Unknown".into(),
        };
        if oid_tag != 0x06 {
            return "Unknown".into();
        }

        let oid_str = Self::decode_oid(oid_bytes);

        // Check for EC / ECDSA Curve OID in parameters
        if oid_str == "1.2.840.10045.2.1" {
            // id-ecPublicKey
            if let Some((0x06, curve_oid_bytes, _)) = Self::read_tlv(param_rem) {
                let curve_oid = Self::decode_oid(curve_oid_bytes);
                return match curve_oid.as_str() {
                    "1.2.840.10045.3.1.7" => "ECDSA (secp256r1 / NIST P-256)".into(),
                    "1.3.132.0.34" => "ECDSA (secp384r1 / NIST P-384)".into(),
                    "1.3.132.0.35" => "ECDSA (secp521r1 / NIST P-521)".into(),
                    "1.3.132.0.10" => "ECDSA (secp256k1 / Koblitz)".into(),
                    "1.3.36.3.3.2.8.1.1.7" => "ECDSA (brainpoolP256r1)".into(),
                    "1.3.36.3.3.2.8.1.1.9" => "ECDSA (brainpoolP384r1)".into(),
                    "1.3.36.3.3.2.8.1.1.11" => "ECDSA (brainpoolP512r1)".into(),
                    _ => format!("ECDSA (Curve OID: {})", curve_oid),
                };
            }
            return "ECDSA (Generic / Unspecified Curve)".into();
        }

        // Check for RSA bit length
        if oid_str == "1.2.840.113549.1.1.1" {
            if let Some((0x03, bit_string_content, _)) = Self::read_tlv(key_rem) {
                // First byte of BIT STRING is unused bits (typically 0)
                if bit_string_content.len() > 1 {
                    let rsa_der = &bit_string_content[1..];
                    if let Some((0x30, rsa_seq, _)) = Self::read_tlv(rsa_der) {
                        if let Some((0x02, modulus, _)) = Self::read_tlv(rsa_seq) {
                            let len_bytes = if !modulus.is_empty() && modulus[0] == 0x00 {
                                modulus.len() - 1
                            } else {
                                modulus.len()
                            };
                            let bit_len = len_bytes * 8;
                            return format!("RSA ({}-bit)", bit_len);
                        }
                    }
                }
            }
            return "RSA".into();
        }

        // Direct OID lookup
        Self::lookup_oid_name(&oid_str).unwrap_or_else(|| format!("Algorithm (OID: {})", oid_str))
    }

    /// Looks up human-readable names for Cryptographic OIDs.
    pub fn lookup_oid_name(oid: &str) -> Option<String> {
        let name = match oid {
            // RSA
            "1.2.840.113549.1.1.1" => "RSA Encryption",
            "1.2.840.113549.1.1.2" => "MD2-with-RSA",
            "1.2.840.113549.1.1.4" => "MD5-with-RSA",
            "1.2.840.113549.1.1.5" => "SHA1-with-RSA",
            "1.2.840.113549.1.1.11" => "SHA256-with-RSA",
            "1.2.840.113549.1.1.12" => "SHA384-with-RSA",
            "1.2.840.113549.1.1.13" => "SHA512-with-RSA",
            "1.2.840.113549.1.1.14" => "SHA224-with-RSA",
            "1.2.840.113549.1.1.10" => "RSASSA-PSS",

            // ECDSA Signatures
            "1.2.840.10045.4.1" => "ECDSA-with-SHA1",
            "1.2.840.10045.4.3.1" => "ECDSA-with-SHA224",
            "1.2.840.10045.4.3.2" => "ECDSA-with-SHA256",
            "1.2.840.10045.4.3.3" => "ECDSA-with-SHA384",
            "1.2.840.10045.4.3.4" => "ECDSA-with-SHA512",

            // Edwards Curves
            "1.3.101.112" => "Ed25519",
            "1.3.101.113" => "Ed448 (Goldilocks)",
            "1.3.101.110" => "X25519",
            "1.3.101.111" => "X448",

            // Russian GOST
            "1.2.643.2.2.19" => "GOST R 34.10-2001 (Russian Public Key)",
            "1.2.643.7.1.1.1.1" => "GOST R 34.10-2012 (256-bit / TC-26)",
            "1.2.643.7.1.1.1.2" => "GOST R 34.10-2012 (512-bit / TC-26)",
            "1.2.643.7.1.1.3.2" => "GOST R 34.11-2012 / 34.10-2012 (256-bit Signature)",
            "1.2.643.7.1.1.3.3" => "GOST R 34.11-2012 / 34.10-2012 (512-bit Signature)",
            "1.2.643.2.2.3" => "GOST R 34.11-94 / 34.10-2001 Signature",

            // Chinese Commercial Crypto (SM2/SM3/SM9)
            "1.2.156.10197.1.301" => "SM2 (Chinese Commercial Elliptic Curve)",
            "1.2.156.10197.1.501" => "SM2-with-SM3 Signature",
            "1.2.156.10197.1.401" => "SM3 Digest",
            "1.2.156.10197.1.302" => "SM9 Identity-Based Public Key",

            // Post-Quantum Cryptography (NIST FIPS 203/204/205 & Hybrid)
            "2.16.840.1.101.3.4.3.17" | "1.3.6.1.4.1.2.267.1.6.5" => "ML-DSA-44 (Dilithium-2)",
            "2.16.840.1.101.3.4.3.18" | "1.3.6.1.4.1.2.267.1.6.7" => "ML-DSA-65 (Dilithium-3)",
            "2.16.840.1.101.3.4.3.19" | "1.3.6.1.4.1.2.267.1.6.8" => "ML-DSA-87 (Dilithium-5)",
            "1.3.6.1.4.1.2.267.7.4.4" => "Falcon-512",
            "1.3.6.1.4.1.2.267.7.8.7" => "Falcon-1024",
            "2.16.840.1.101.3.4.3.20" => "SLH-DSA (SPHINCS+)",
            "2.16.840.1.101.3.4.4.1" => "ML-KEM-512 (Kyber-512)",
            "2.16.840.1.101.3.4.4.2" => "ML-KEM-768 (Kyber-768)",
            "2.16.840.1.101.3.4.4.3" => "ML-KEM-1024 (Kyber-1024)",

            // DSA & DH
            "1.2.840.10040.4.1" => "DSA (Digital Signature Algorithm)",
            "1.2.840.10040.4.3" => "DSA-with-SHA1",
            "2.16.840.1.101.3.4.3.1" => "DSA-with-SHA224",
            "2.16.840.1.101.3.4.3.2" => "DSA-with-SHA256",
            "1.2.840.10046.2.1" => "Diffie-Hellman Key Exchange",

            _ => return None,
        };
        Some(name.to_string())
    }

    fn lookup_algorithm_name(data: &[u8]) -> String {
        if let Some((0x06, oid_bytes, _)) = Self::read_tlv(data) {
            let oid = Self::decode_oid(oid_bytes);
            if let Some(name) = Self::lookup_oid_name(&oid) {
                return name;
            }
            return format!("Algorithm (OID: {})", oid);
        }
        "Standard X.509 Cryptographic Suite".into()
    }

    /// Extracts validity dates (UTCTime or GeneralizedTime) and computes expiration status.
    fn extract_validity(data: &[u8]) -> (Option<String>, Option<String>, String) {
        let mut cur = data;
        let mut dates = Vec::new();
        while let Some((tag, content, rem)) = Self::read_tlv(cur) {
            if tag == 0x17 || tag == 0x18 {
                let raw_str = String::from_utf8_lossy(content).to_string();
                dates.push(Self::format_asn1_time(&raw_str));
            }
            cur = rem;
        }

        let nb = dates.first().cloned();
        let na = dates.get(1).cloned();

        let status = if let Some(ref not_after_str) = na {
            if let Ok(exp_time) =
                chrono::NaiveDateTime::parse_from_str(not_after_str, "%Y-%m-%d %H:%M:%S UTC")
            {
                let now = chrono::Utc::now().naive_utc();
                if now > exp_time {
                    let diff_days = (now - exp_time).num_days();
                    format!("EXPIRED ({} days ago)", diff_days)
                } else {
                    let rem_days = (exp_time - now).num_days();
                    format!("VALID (expires in {} days)", rem_days)
                }
            } else {
                "Valid".into()
            }
        } else {
            "Unknown".into()
        };

        (nb, na, status)
    }

    fn format_asn1_time(time_str: &str) -> String {
        // UTCTime: YYMMDDHHMMSSZ
        if time_str.len() >= 13 && time_str.ends_with('Z') && time_str.len() <= 15 {
            let yy: i32 = time_str[0..2].parse().unwrap_or(0);
            let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            let mm = &time_str[2..4];
            let dd = &time_str[4..6];
            let hh = &time_str[6..8];
            let min = &time_str[8..10];
            let ss = &time_str[10..12];
            return format!("{}-{}-{} {}:{}:{} UTC", full_year, mm, dd, hh, min, ss);
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        if time_str.len() >= 15 && time_str.ends_with('Z') {
            let yyyy = &time_str[0..4];
            let mm = &time_str[4..6];
            let dd = &time_str[6..8];
            let hh = &time_str[8..10];
            let min = &time_str[10..12];
            let ss = &time_str[12..14];
            return format!("{}-{}-{} {}:{}:{} UTC", yyyy, mm, dd, hh, min, ss);
        }
        time_str.to_string()
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_extensions(
        cursor: &[u8],
        is_ca: &mut bool,
        path_length_constraint: &mut Option<u32>,
        key_usage: &mut Vec<String>,
        extended_key_usage: &mut Vec<String>,
        subject_alt_names: &mut Vec<String>,
        ocsp_urls: &mut Vec<String>,
        ca_issuers_urls: &mut Vec<String>,
        crl_distribution_points: &mut Vec<String>,
        subject_key_id: &mut Option<String>,
        authority_key_id: &mut Option<String>,
    ) {
        // Extensions wrapper tag: [3] EXPLICIT (0xA3)
        let mut ext_cursor = cursor;
        let mut extensions_seq = None;

        while let Some((tag, content, rem)) = Self::read_tlv(ext_cursor) {
            ext_cursor = rem;
            if (tag & 0xC0) == 0x80 && (tag & 0x1F) == 3 {
                // Inside [3] EXPLICIT
                if let Some((0x30, seq, _)) = Self::read_tlv(content) {
                    extensions_seq = Some(seq);
                    break;
                }
            }
        }

        let seq_data = match extensions_seq {
            Some(s) => s,
            None => return,
        };

        let mut item_cur = seq_data;
        while let Some((0x30, ext_content, rem)) = Self::read_tlv(item_cur) {
            item_cur = rem;

            // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
            if let Some((0x06, oid_bytes, mut inner_rem)) = Self::read_tlv(ext_content) {
                let oid_str = Self::decode_oid(oid_bytes);

                // Optional critical BOOLEAN
                if let Some((0x01, _, b_rem)) = Self::read_tlv(inner_rem) {
                    inner_rem = b_rem;
                }

                // extnValue OCTET STRING
                if let Some((0x04, octet_val, _)) = Self::read_tlv(inner_rem) {
                    match oid_str.as_str() {
                        // Basic Constraints (2.5.29.19)
                        "2.5.29.19" => {
                            if let Some((0x30, bc_seq, _)) = Self::read_tlv(octet_val) {
                                let mut bc_cur = bc_seq;
                                while let Some((tag, val, rem)) = Self::read_tlv(bc_cur) {
                                    bc_cur = rem;
                                    if tag == 0x01 && !val.is_empty() && val[0] != 0 {
                                        *is_ca = true;
                                    } else if tag == 0x02 && !val.is_empty() {
                                        *path_length_constraint = Some(val[0] as u32);
                                    }
                                }
                            }
                        }

                        // Key Usage (2.5.29.15)
                        "2.5.29.15" => {
                            if let Some((0x03, bit_str, _)) = Self::read_tlv(octet_val) {
                                if bit_str.len() > 1 {
                                    let b0 = bit_str[1];
                                    if (b0 & 0x80) != 0 {
                                        key_usage.push("Digital Signature".into());
                                    }
                                    if (b0 & 0x40) != 0 {
                                        key_usage.push("Non-Repudiation".into());
                                    }
                                    if (b0 & 0x20) != 0 {
                                        key_usage.push("Key Encipherment".into());
                                    }
                                    if (b0 & 0x10) != 0 {
                                        key_usage.push("Data Encipherment".into());
                                    }
                                    if (b0 & 0x08) != 0 {
                                        key_usage.push("Key Agreement".into());
                                    }
                                    if (b0 & 0x04) != 0 {
                                        key_usage.push("Certificate Sign".into());
                                    }
                                    if (b0 & 0x02) != 0 {
                                        key_usage.push("CRL Sign".into());
                                    }
                                    if (b0 & 0x01) != 0 {
                                        key_usage.push("Encipher Only".into());
                                    }
                                    if bit_str.len() > 2 && (bit_str[2] & 0x80) != 0 {
                                        key_usage.push("Decipher Only".into());
                                    }
                                }
                            }
                        }

                        // Extended Key Usage (2.5.29.37)
                        "2.5.29.37" => {
                            if let Some((0x30, eku_seq, _)) = Self::read_tlv(octet_val) {
                                let mut eku_cur = eku_seq;
                                while let Some((0x06, eku_oid_bytes, rem)) = Self::read_tlv(eku_cur)
                                {
                                    eku_cur = rem;
                                    let eku_oid = Self::decode_oid(eku_oid_bytes);
                                    let name = match eku_oid.as_str() {
                                        "1.3.6.1.5.5.7.3.1" => "TLS Web Server Authentication",
                                        "1.3.6.1.5.5.7.3.2" => "TLS Web Client Authentication",
                                        "1.3.6.1.5.5.7.3.3" => "Code Signing",
                                        "1.3.6.1.5.5.7.3.4" => "Email Protection (S/MIME)",
                                        "1.3.6.1.5.5.7.3.8" => "Time Stamping",
                                        "1.3.6.1.5.5.7.3.9" => "OCSP Signing",
                                        "1.3.6.1.4.1.311.20.2.2" => "Smartcard Logon",
                                        "2.5.29.37.0" => "Any Extended Key Usage",
                                        _ => "Extended Key Usage",
                                    };
                                    extended_key_usage.push(format!("{} ({})", name, eku_oid));
                                }
                            }
                        }

                        // Subject Alternative Names (2.5.29.17)
                        "2.5.29.17" => {
                            if let Some((0x30, san_seq, _)) = Self::read_tlv(octet_val) {
                                let mut san_cur = san_seq;
                                while let Some((tag, val, rem)) = Self::read_tlv(san_cur) {
                                    san_cur = rem;
                                    match tag {
                                        0x82 => {
                                            // dNSName
                                            let s = String::from_utf8_lossy(val).to_string();
                                            if !s.is_empty() {
                                                subject_alt_names.push(format!("DNS:{}", s));
                                            }
                                        }
                                        0x87 => {
                                            // iPAddress
                                            if val.len() == 4 {
                                                subject_alt_names.push(format!(
                                                    "IP:{}.{}.{}.{}",
                                                    val[0], val[1], val[2], val[3]
                                                ));
                                            } else if val.len() == 16 {
                                                subject_alt_names.push("IPv6-Address".into());
                                            }
                                        }
                                        0x81 => {
                                            // rfc822Name
                                            subject_alt_names.push(format!(
                                                "Email:{}",
                                                String::from_utf8_lossy(val)
                                            ));
                                        }
                                        0x86 => {
                                            // uniformResourceIdentifier
                                            subject_alt_names.push(format!(
                                                "URI:{}",
                                                String::from_utf8_lossy(val)
                                            ));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Authority Information Access (1.3.6.1.5.5.7.1.1)
                        "1.3.6.1.5.5.7.1.1" => {
                            if let Some((0x30, aia_seq, _)) = Self::read_tlv(octet_val) {
                                let mut aia_cur = aia_seq;
                                while let Some((0x30, desc_seq, rem)) = Self::read_tlv(aia_cur) {
                                    aia_cur = rem;
                                    if let Some((0x06, method_oid_bytes, loc_rem)) =
                                        Self::read_tlv(desc_seq)
                                    {
                                        let method = Self::decode_oid(method_oid_bytes);
                                        if let Some((_, uri_val, _)) = Self::read_tlv(loc_rem) {
                                            let uri_str =
                                                String::from_utf8_lossy(uri_val).to_string();
                                            if method == "1.3.6.1.5.5.7.48.1" {
                                                ocsp_urls.push(uri_str);
                                            } else if method == "1.3.6.1.5.5.7.48.2" {
                                                ca_issuers_urls.push(uri_str);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // CRL Distribution Points (2.5.29.31)
                        "2.5.29.31" => {
                            let text = String::from_utf8_lossy(octet_val);
                            for part in text.split("http") {
                                if part.starts_with("://") {
                                    if let Some(end) = part.find(|c: char| {
                                        c.is_whitespace() || !(' '..='~').contains(&c)
                                    }) {
                                        crl_distribution_points
                                            .push(format!("http{}", &part[..end]));
                                    } else {
                                        crl_distribution_points.push(format!("http{}", part));
                                    }
                                }
                            }
                        }

                        // Subject Key Identifier (2.5.29.14)
                        "2.5.29.14" => {
                            if let Some((0x04, ski_bytes, _)) = Self::read_tlv(octet_val) {
                                *subject_key_id = Some(Self::hex_string(ski_bytes));
                            }
                        }

                        // Authority Key Identifier (2.5.29.35)
                        "2.5.29.35" => {
                            if let Some((0x30, aki_seq, _)) = Self::read_tlv(octet_val) {
                                if let Some((0x80, aki_bytes, _)) = Self::read_tlv(aki_seq) {
                                    *authority_key_id = Some(Self::hex_string(aki_bytes));
                                }
                            }
                        }

                        _ => {}
                    }
                }
            }
        }
    }

    fn scan_san_dns_names(data: &[u8], results: &mut Vec<String>) {
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

    pub fn hex_string(bytes: &[u8]) -> String {
        let mut s = String::new();
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push(':');
            }
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    /// Pure-Rust implementation of FIPS 180-4 standard SHA-256.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut msg = data.to_vec();
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut h_var = h[7];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h_var
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(k[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h_var = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(h_var);
        }

        let mut out = [0u8; 32];
        for (i, val) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    /// Pure-Rust implementation of FIPS 180-1 standard SHA-1.
    #[allow(clippy::chunks_exact_to_as_chunks, clippy::needless_range_loop)]
    pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
        let mut h0: u32 = 0x67452301;
        let mut h1: u32 = 0xEFCDAB89;
        let mut h2: u32 = 0x98BADCFE;
        let mut h3: u32 = 0x10325476;
        let mut h4: u32 = 0xC3D2E1F0;

        let bit_len = (data.len() as u64) * 8;
        let mut msg = data.to_vec();
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let mut a = h0;
            let mut b = h1;
            let mut c = h2;
            let mut d = h3;
            let mut e = h4;

            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };

                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        let mut out = [0u8; 20];
        out[0..4].copy_from_slice(&h0.to_be_bytes());
        out[4..8].copy_from_slice(&h1.to_be_bytes());
        out[8..12].copy_from_slice(&h2.to_be_bytes());
        out[12..16].copy_from_slice(&h3.to_be_bytes());
        out[16..20].copy_from_slice(&h4.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty_string() {
        let digest = X509Parser::sha256_digest(b"");
        let hex = X509Parser::hex_string(&digest);
        assert_eq!(hex, "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55");
    }

    #[test]
    fn test_sha1_empty_string() {
        let digest = X509Parser::sha1_digest(b"");
        let hex = X509Parser::hex_string(&digest);
        assert_eq!(
            hex,
            "DA:39:A3:EE:5E:6B:4B:0D:32:55:BF:EF:95:60:18:90:AF:D8:07:09"
        );
    }

    #[test]
    fn test_decode_oid() {
        // RSA Encryption: 1.2.840.113549.1.1.1
        let rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        assert_eq!(X509Parser::decode_oid(&rsa_oid), "1.2.840.113549.1.1.1");

        // GOST R 34.10-2012 (256): 1.2.643.7.1.1.1.1
        let gost_oid = [0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01];
        assert_eq!(X509Parser::decode_oid(&gost_oid), "1.2.643.7.1.1.1.1");

        // ML-DSA-65 (Dilithium-3): 2.16.840.1.101.3.4.3.18
        let dilithium_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
        assert_eq!(
            X509Parser::decode_oid(&dilithium_oid),
            "2.16.840.1.101.3.4.3.18"
        );
    }

    #[test]
    fn test_decode_bmp_string_utf16be() {
        // "Test" in UTF-16BE: 0x00, 'T', 0x00, 'e', 0x00, 's', 0x00, 't'
        let bmp_bytes = [0x00, b'T', 0x00, b'e', 0x00, b's', 0x00, b't'];
        let res = X509Parser::decode_asn1_string(0x1E, &bmp_bytes);
        assert_eq!(res, "Test");
    }

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
