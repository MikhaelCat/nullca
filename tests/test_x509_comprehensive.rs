use nullca::proto::x509::X509Parser;
use std::path::Path;

#[test]
fn test_real_system_letsencrypt_root_exact_fingerprint() {
    let path = Path::new("/etc/ca-certificates/extracted/cadir/ISRG_Root_X1.pem");
    if !path.exists() {
        eprintln!("Skipping test: ISRG_Root_X1.pem not found on system");
        return;
    }

    let bytes = std::fs::read(path).expect("Read ISRG Root X1");
    let cert = X509Parser::parse(&bytes).expect("Must parse ISRG Root X1");

    assert_eq!(cert.subject_cn.as_deref(), Some("ISRG Root X1"));
    assert_eq!(cert.issuer_cn.as_deref(), Some("ISRG Root X1"));
    assert_eq!(cert.public_key_algorithm, "RSA (4096-bit)");
    assert_eq!(cert.signature_algorithm, "SHA256-with-RSA");
    assert!(cert.is_ca, "ISRG Root X1 must be marked as CA");

    // Standard OpenSSL FIPS 180-4 SHA-256 fingerprint for ISRG Root X1:
    assert_eq!(
        cert.fingerprint_sha256,
        "96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6"
    );
}

#[test]
fn test_real_system_microsoft_ecc_root_p384() {
    let path = Path::new("/etc/ca-certificates/extracted/cadir/Microsoft_ECC_Root_Certificate_Authority_2017.pem");
    if !path.exists() {
        return;
    }

    let bytes = std::fs::read(path).expect("Read Microsoft ECC Root");
    let cert = X509Parser::parse(&bytes).expect("Must parse Microsoft ECC Root");

    assert_eq!(cert.public_key_algorithm, "ECDSA (secp384r1 / NIST P-384)");
    assert_eq!(cert.signature_algorithm, "ECDSA-with-SHA384");
    assert!(cert.is_ca);
}

#[test]
fn test_real_system_ca_certificates_bundle_all_119() {
    let path = Path::new("/etc/ssl/certs/ca-certificates.crt");
    if !path.exists() {
        return;
    }

    let bytes = std::fs::read(path).expect("Read system CA bundle");
    let certs = X509Parser::parse_all(&bytes);

    assert!(certs.len() >= 100, "Must parse all certificates in system bundle (got {})", certs.len());
    for (i, c) in certs.iter().enumerate() {
        assert!(!c.fingerprint_sha256.is_empty(), "Cert #{} has empty fingerprint", i);
        assert!(!c.public_key_algorithm.is_empty(), "Cert #{} has empty algorithm", i);
    }
}

#[test]
fn test_real_system_directory_scan() {
    let dir = Path::new("/etc/ca-certificates/extracted/cadir");
    if !dir.exists() {
        return;
    }

    let summary = X509Parser::scan_directory(dir).expect("Directory scan");
    assert!(summary.total_certs_parsed >= 100);
    assert_eq!(summary.parse_errors, 0, "No parse errors expected on standard system CA store");
    assert!(summary.algorithm_counts.contains_key("RSA (4096-bit)") || summary.algorithm_counts.contains_key("RSA (2048-bit)"));
    assert!(summary.algorithm_counts.contains_key("ECDSA (secp384r1 / NIST P-384)"));
}

#[test]
fn test_rare_and_exotic_crypto_oid_lookup() {
    // 1. Russian GOST R 34.10-2012 (256-bit and 512-bit)
    assert_eq!(
        X509Parser::lookup_oid_name("1.2.643.7.1.1.1.1").as_deref(),
        Some("GOST R 34.10-2012 (256-bit / TC-26)")
    );
    assert_eq!(
        X509Parser::lookup_oid_name("1.2.643.7.1.1.3.3").as_deref(),
        Some("GOST R 34.11-2012 / 34.10-2012 (512-bit Signature)")
    );

    // 2. Chinese SM2 Elliptic Curve & SM3 Signature
    assert_eq!(
        X509Parser::lookup_oid_name("1.2.156.10197.1.301").as_deref(),
        Some("SM2 (Chinese Commercial Elliptic Curve)")
    );
    assert_eq!(
        X509Parser::lookup_oid_name("1.2.156.10197.1.501").as_deref(),
        Some("SM2-with-SM3 Signature")
    );

    // 3. Post-Quantum ML-DSA (Dilithium-2, Dilithium-3, Dilithium-5) & Kyber/ML-KEM
    assert_eq!(
        X509Parser::lookup_oid_name("2.16.840.1.101.3.4.3.17").as_deref(),
        Some("ML-DSA-44 (Dilithium-2)")
    );
    assert_eq!(
        X509Parser::lookup_oid_name("2.16.840.1.101.3.4.3.18").as_deref(),
        Some("ML-DSA-65 (Dilithium-3)")
    );
    assert_eq!(
        X509Parser::lookup_oid_name("2.16.840.1.101.3.4.4.2").as_deref(),
        Some("ML-KEM-768 (Kyber-768)")
    );

    // 4. Edwards Goldilocks Ed448 and Ed25519
    assert_eq!(
        X509Parser::lookup_oid_name("1.3.101.113").as_deref(),
        Some("Ed448 (Goldilocks)")
    );
    assert_eq!(
        X509Parser::lookup_oid_name("1.3.101.112").as_deref(),
        Some("Ed25519")
    );

    // 5. RSASSA-PSS and Legacy MD5-with-RSA
    assert_eq!(
        X509Parser::lookup_oid_name("1.2.840.113549.1.1.10").as_deref(),
        Some("RSASSA-PSS")
    );
    assert_eq!(
        X509Parser::lookup_oid_name("1.2.840.113549.1.1.4").as_deref(),
        Some("MD5-with-RSA")
    );
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(tag);
    if content.len() < 128 {
        v.push(content.len() as u8);
    } else {
        let len_bytes = (content.len() as u32).to_be_bytes();
        let non_zero = len_bytes.iter().skip_while(|&&b| b == 0).count().max(1);
        v.push(0x80 | (non_zero as u8));
        v.extend_from_slice(&len_bytes[4 - non_zero..]);
    }
    v.extend_from_slice(content);
    v
}

#[test]
fn test_synthetic_dilithium_post_quantum_certificate() {
    // Construct a minimal valid DER X.509 certificate featuring Post-Quantum ML-DSA-65 (Dilithium-3)
    let dilithium_oid_bytes = vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]; // 2.16.840.1.101.3.4.3.18
    let sig_alg_oid = der_tlv(0x06, &dilithium_oid_bytes);
    let sig_alg_seq = der_tlv(0x30, &sig_alg_oid);

    // 1. Serial (INTEGER: 0x42)
    let serial = der_tlv(0x02, &[0x42]);

    // 2. Issuer: CN=PQC Root CA
    let issuer_cn_attr = der_tlv(0x30, &[&der_tlv(0x06, &[0x55, 0x04, 0x03])[..], &der_tlv(0x13, b"PQC Root CA")[..]].concat());
    let issuer_rdn = der_tlv(0x31, &issuer_cn_attr);
    let issuer_dn = der_tlv(0x30, &issuer_rdn);

    // 3. Validity (empty sequence)
    let validity = der_tlv(0x30, &[]);

    // 4. Subject: CN=Quantum Leaf
    let subj_cn_attr = der_tlv(0x30, &[&der_tlv(0x06, &[0x55, 0x04, 0x03])[..], &der_tlv(0x13, b"Quantum Leaf")[..]].concat());
    let subj_rdn = der_tlv(0x31, &subj_cn_attr);
    let subject_dn = der_tlv(0x30, &subj_rdn);

    // 5. SubjectPublicKeyInfo (Dilithium-3 algorithm + BIT STRING public key)
    let pubkey_bits = der_tlv(0x03, &[0x00, 0xAA, 0xBB]); // 0x00 unused bits
    let spki = der_tlv(0x30, &[&sig_alg_seq[..], &pubkey_bits[..]].concat());

    // Assemble TBSCertificate
    let tbs_payload = [&serial[..], &sig_alg_seq[..], &issuer_dn[..], &validity[..], &subject_dn[..], &spki[..]].concat();
    let tbs_cert = der_tlv(0x30, &tbs_payload);

    // Outer Certificate: TBSCertificate + SignatureAlgorithm + SignatureValue
    let sig_value = der_tlv(0x03, &[0x00, 0x11, 0x22]);
    let cert_payload = [&tbs_cert[..], &sig_alg_seq[..], &sig_value[..]].concat();
    let outer_cert = der_tlv(0x30, &cert_payload);

    let cert = X509Parser::parse_der(&outer_cert).expect("Must parse synthetic PQC Dilithium certificate");
    assert_eq!(cert.public_key_algorithm, "ML-DSA-65 (Dilithium-3)");
    assert_eq!(cert.signature_algorithm, "ML-DSA-65 (Dilithium-3)");
    assert_eq!(cert.serial_number_hex, "42");
    assert!(cert.subject_dn.contains("Quantum Leaf"));
}

#[test]
fn test_parse_x509_csr_request() {
    let csr_pem = r#"-----BEGIN CERTIFICATE REQUEST-----
MIICizCCAXMCAQAwRjELMAkGA1UEBhMCVVMxEzARBgNVBAoMCk51bGxDQSBJbmMx
IjAgBgNVBAMMGXF1YW50dW0tZGV2LnRlc3QuaW50ZXJuYWwwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCjhWrorYMUnKY+gCHjh0pAeLr0IHheQv+ggZsL
L6Wmr+ADzZE7B2OraX+fJOwyQa+ctoP2p9FjCyh00C8Z44kUny/XukJ2MzZojd4Y
Vt88QJWNp4XyV+8WpNJK3iZZhixDsiooioNx2v7eSt6i3uCiy/DmusO+ha2zOF9J
nYHMcQD+LnjkNf/jw8V3PyyjpWvgJmbu7YgVNLSH1vInvZ8XyIciiiEsYkiOUnXZ
bRMwH41brQ//MSBDBrwCEFQhrelKpQ+5ccrigtKzfW4hwnji3Pe/VfJge5PTXk3z
vWFIMN5LAVqUtWiNHwItP7oYaJ5qw+xvLrbkjBr/r3XI3aB3AgMBAAGgADANBgkq
hkiG9w0BAQsFAAOCAQEABE+/IBEN7QnaWSiIpOz90R5vm2mv1jYB5rl6ixOjlbri
mmMsQVcpalcyA3MjT+f7DGCrMGwGLMUSSb0RYksnQ3Yo+jrSTLtVwTbPYcL9/PRp
TX9ikL9XJ7rZaAv6iUV1RTP5iygxXgqAnwM1mSWmnpFgIKifw5O4b2bfgvHceWJn
36kI22WxAtdOWQzVMRM58RRGn1SP6IrsOsMg4PIZopO4eKQ0bp9Um/FO+3YHofvU
+tIEunotPDvsZ/82pKNLxxL1Rrt4ml2NTBnF/YQw7t2qlnKO5RZRHTuZSBzn5wkC
Ejizbt45Nc88/vAXC0acbfw4yQJ8FVdAF5rhV6ZCtw==
-----END CERTIFICATE REQUEST-----"#;

    let csr = X509Parser::parse_csr(csr_pem.as_bytes()).expect("Must parse valid CSR");
    assert_eq!(csr.subject_cn.as_deref(), Some("quantum-dev.test.internal"));
    assert_eq!(csr.subject_org.as_deref(), Some("NullCA Inc"));
    assert_eq!(csr.public_key_algorithm, "RSA (2048-bit)");
    assert_eq!(csr.signature_algorithm, "SHA256-with-RSA");
}

#[test]
fn test_parse_x509_crl() {
    let sha256_rsa_oid = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]; // 1.2.840.113549.1.1.11
    let sig_alg_oid = der_tlv(0x06, &sha256_rsa_oid);
    let sig_alg_seq = der_tlv(0x30, &sig_alg_oid);

    // 1. Version v2 (INTEGER 1)
    let version = der_tlv(0x02, &[0x01]);

    // 2. Issuer DN: CN=Test CRL Issuer
    let issuer_cn_attr = der_tlv(0x30, &[&der_tlv(0x06, &[0x55, 0x04, 0x03])[..], &der_tlv(0x13, b"Test CRL Issuer")[..]].concat());
    let issuer_rdn = der_tlv(0x31, &issuer_cn_attr);
    let issuer_dn = der_tlv(0x30, &issuer_rdn);

    // 3. thisUpdate (UTCTime)
    let this_update = der_tlv(0x17, b"261104120000Z");

    // 4. nextUpdate (UTCTime)
    let next_update = der_tlv(0x17, b"261204120000Z");

    // 5. revokedCertificates entry: serial = 0x1234, revocationDate = UTCTime
    let rev_serial = der_tlv(0x02, &[0x12, 0x34]);
    let rev_date = der_tlv(0x17, b"261104123000Z");
    let rev_entry = der_tlv(0x30, &[&rev_serial[..], &rev_date[..]].concat());
    let rev_list = der_tlv(0x30, &rev_entry);

    // Assemble TBSCertList
    let tbs_payload = [&version[..], &sig_alg_seq[..], &issuer_dn[..], &this_update[..], &next_update[..], &rev_list[..]].concat();
    let tbs_crl = der_tlv(0x30, &tbs_payload);

    // Outer CRL
    let sig_bits = der_tlv(0x03, &[0x00, 0xAA, 0xBB, 0xCC]);
    let outer_crl = der_tlv(0x30, &[&tbs_crl[..], &sig_alg_seq[..], &sig_bits[..]].concat());

    let crl = X509Parser::parse_crl(&outer_crl).expect("Must parse synthetic CRL");
    assert_eq!(crl.version, "v2");
    assert_eq!(crl.issuer_cn.as_deref(), Some("Test CRL Issuer"));
    assert_eq!(crl.signature_algorithm, "SHA256-with-RSA");
    assert_eq!(crl.revoked_count, 1);
    assert_eq!(crl.revoked_certificates[0].serial_number_hex, "12:34");
}

#[test]
fn test_live_remote_tls_fetch_google() {
    let certs = X509Parser::fetch_remote_certificates("google.com:443").expect("Fetch live Google TLS chain");
    assert!(!certs.is_empty(), "Must receive at least 1 certificate from google.com");

    let leaf = &certs[0];
    assert!(
        leaf.subject_dn.contains("google.com") || leaf.subject_alt_names.iter().any(|s| s.contains("google.com")),
        "Leaf certificate must be for google.com"
    );
    assert!(leaf.validity_status.starts_with("VALID"), "Google cert should be valid");
    assert!(!leaf.fingerprint_sha256.is_empty());
}
