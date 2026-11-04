# NullCA Documentation Index

Welcome to the official technical documentation for **NullCA** (`⚡ Zero-CA eBPF Plaintext TLS, HTTP/2, WebSocket & gRPC Sniffer in Pure Rust`).

NullCA is an observability and protocol dissection platform designed to capture and analyze unencrypted application traffic directly from process memory using Linux kernel eBPF uprobes.

---

## 📚 Documentation Structure

1. **[Architecture & Design (`ARCHITECTURE.md`)](./ARCHITECTURE.md)**
   - High-level system architecture and data flow.
   - Traditional MitM proxies vs Zero-CA eBPF memory interception.
   - Lock-free kernel-to-userspace Ring Buffer pipeline.
   - Concurrency model and zero-copy parsing.

2. **[eBPF Zero-CA Engine (`EBPF_ENGINE.md`)](./EBPF_ENGINE.md)**
   - eBPF uprobe and uretprobe mechanics on `SSL_read` and `SSL_write`.
   - OpenSSL, BoringSSL, and rustls hook points.
   - Golang ABIInternal register convention and goroutine stack unwinding (`runtime.g`).
   - Stripped ELF binary inspection and `.gopclntab` parsing without DWARF.

3. **[Supported Protocols & Dissectors (`PROTOCOLS.md`)](./PROTOCOLS.md)**
   - **HTTP/1.1**: Pipelining, chunked transfer encoding, stream reassembly.
   - **HTTP/2**: Multiplexed virtual streams, frame parsing, RFC 7541 HPACK dynamic table and canonical Huffman decompression.
   - **gRPC & Protobuf**: Wire format decoders (Varint, Length-delimited, Fixed32/64), nested message reconstruction.
   - **WebSocket (RFC 6455)**: Masked frames, fragmentation, ping/pong, status codes.
   - **X.509 ASN.1 & Certificates**: RSA (1024-8192), NIST Curves, Koblitz secp256k1, Brainpool, Ed25519, Ed448, GOST R 34.10, SM2/SM3, NIST Post-Quantum (Dilithium, Falcon, Kyber).
   - **Database Protocols**: PostgreSQL wire format, Redis RESP3, SMTP.

4. **[CLI Reference Manual (`CLI_REFERENCE.md`)](./CLI_REFERENCE.md)**
   - Complete guide to all CLI subcommands (`trace`, `run`, `list`, `inspect-cert`, `replay`, `diff`, `export-openapi`, `audit`, `export-sslkeylog`, `scan-secrets`, etc.).
   - Filter DSL query expressions and syntax.
   - Terminal Cockpit (TUI) keyboard shortcuts.

5. **[Passive Security Auditor & OpenAPI Generator (`SECURITY_AUDIT_AND_OPENAPI.md`)](./SECURITY_AUDIT_AND_OPENAPI.md)**
   - Passive security posture and header hygiene evaluation (HSTS, CORS, CSP, Cookies, Leaks).
   - Automated OpenAPI 3.0.3 specification synthesis and recursive JSON schema inference.
   - NSS `SSLKEYLOGFILE` streaming and Wireshark integration.
