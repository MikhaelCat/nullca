# NullCA Architecture & System Design

NullCA operates on a fundamentally different principle than legacy network proxies such as Burp Suite, Charles, or mitmproxy. Rather than proxying network packets at L4/L7 and attempting to forge TLS certificates, NullCA hooks into the userspace cryptographic boundary using Linux kernel eBPF uprobes.

---

## 1. Zero-CA Architecture vs Traditional MitM Proxy

```
[ Traditional MitM Proxy (Burp Suite / mitmproxy) ]
Client Process ───[Fake Root CA]───> Proxy Daemon ───[Real TLS]───> Remote Server
  ❌ Breaks on Certificate Pinning (Android, Go binaries, Telegram).
  ❌ Requires installing untrusted Root CA into OS / browser trust store.
  ❌ Fails on mutual TLS (mTLS) without private client key.

[ NullCA Zero-CA Architecture (Linux eBPF uprobes) ]
Client Process ══════════════[ 100% UNTOUCHED REAL TLS ]═════════════> Remote Server
  │
  ├─── Userspace Library Memory (OpenSSL / BoringSSL / Go runtime)
  │    • SSL_read() / crypto/tls.(*Conn).Read()   ───> [uretprobe] (Decrypted Plaintext)
  │    • SSL_write() / crypto/tls.(*Conn).Write()  ───> [uprobe]    (Pre-encryption Plaintext)
  │
  ▼
[ Linux Kernel (eBPF Subsystem) ]
  • bpf_probe_read_user() captures memory buffer
  • Assembles 64-byte structured TlsEvent metadata
  • Emits into Lock-Free BPF Ring Buffer (500,000+ ev/sec)
  ▼
[ NullCA Userspace Daemon (Pure Rust) ]
  ├─── BpfLoader & RingBuffer consumer
  ├─── Stream Reassembler & Protocol Auto-Detector
  ├─── Protocol Dissectors (HTTP/1.1, HTTP/2 HPACK, gRPC, WS, X.509)
  ├─── Filter DSL & Query Engine
  └─── Outputs: Terminal TUI, UNIX IPC, HAR 1.2, PCAP-NG, OpenAPI 3.0
```

---

## 2. Core Subsystems

### A. Kernel eBPF Module (`src/bpf/tls_uprobe.bpf.c`)
- Implements eBPF probes compiled with `clang -target bpf -O2`.
- `probe_entry_ssl_write`: Captures the plaintext buffer *before* OpenSSL/BoringSSL encrypts it.
- `probe_exit_ssl_read`: Captures the plaintext buffer *after* OpenSSL/BoringSSL decrypts it.
- Golang ABI probes: Maps CPU registers (`AX`, `BX`, `CX`) to locate Go slices and extracts the goroutine context pointer `runtime.g`.

### B. High-Throughput Ring Buffer Pipeline
- Uses Linux 5.8+ `BPF_MAP_TYPE_RINGBUF`.
- Zero-copy ring buffer with memory-mapped memory pages shared between kernel space and NullCA userspace.
- Guarantees in-order event delivery per core without spinlock contention.

### C. Protocol Stream Reassembler (`src/proto/reassembler.rs`)
- TLS plaintexts can arrive in arbitrary chunk sizes (e.g. 1-byte chunks, TCP segment fragmentation, chunked HTTP transfers).
- Maintains stateful per-socket buffers that accumulate bytes until a full application message or frame boundary is recognized.

### D. Multi-Protocol Dissection Engine (`src/proto/`)
- **HTTP/1.1 Parser**: Content-Length, Chunked Transfer Encoding, pipelining, and RFC 7230 §3.3.3 EOF-delimited connection close reassembly.
- **HTTP/2 & HPACK Engine**: Full frame parsing (HEADERS, DATA, SETTINGS, CONTINUATION), CONTINUATION flood mitigation, dynamic table management, canonical Huffman decoder.
- **HTTP/3 & QUIC Engine**: RFC 9114 HTTP/3 frames (DATA, HEADERS, SETTINGS, GOAWAY), RFC 9000 QUIC varint codec, and RFC 9204 QPACK static/dynamic table decompressor.
- **DNS & DoH Dissector**: RFC 1035 and RFC 8484 wire parser with QNAME jump-table decompression and support for A, AAAA, CNAME, TXT, MX, NS records.
- **Server-Sent Events (SSE) Engine**: RFC 8895 stream parser with automated LLM streaming token extractor (OpenAI, Anthropic Claude, Ollama).
- **gRPC & Protobuf Dissector**: Decodes wire types (Varint, 64-bit, Length-delimited, 32-bit) without requiring pre-compiled `.proto` files.
- **WebSocket Dissector**: RFC 6455 frame de-masking, fragmentation assembly, and RFC 7692 `permessage-deflate` decompression.
- **X.509 ASN.1 Dissector**: Zero-dependency DER/PEM parser supporting RSA, ECC, Edwards, GOST, SM2, and Post-Quantum cryptography.
- **Stream Decompression**: Native Brotli, Gzip, and Deflate/Zlib multi-algorithm decompressor.

### E. Analytics, Auditing & Export Pipeline
- **Security Auditor (`src/engine/audit.rs`)**: Real-time hygiene checks for HSTS, CORS, CSP, Cookies, Server banners, and Leaked Secrets.
- **Deep JWT Cryptographic Scanner (`src/engine/jwt_audit.rs`)**: Zero-dependency RFC 2104 HMAC-SHA256 dictionary cracker, CVE-2015-9235 `alg: none` bypass detection, and expiration validation.
- **IDOR / BOLA Detector (`src/engine/idor.rs`)**: Cross-identity multi-tenant object access violation tracker.
- **Active Parameter Fuzzer (`src/engine/fuzz.rs`)**: Mutation-based payload generator testing for server-side crashes, SQLi/traversal echoes, and timing anomalies.
- **OpenAPI Synthesizer (`src/export/openapi.rs`)**: Automatic schema generation from captured HTTP streams.
- **Postman Collection Exporter (`src/export/postman.rs`)**: Postman v2.1.0 JSON format exporter with URL decomposition and raw payload modeling.
- **Exporters**: Wireshark PCAP-NG with Decryption Secrets Blocks (DSB, type 0x0000000A) and real 4-tuple TCP resolution, Chrome HAR 1.2, cURL command generator, and NSS SSLKEYLOGFILE.
- **Cockpit TUI (`src/ui/dashboard.rs`)**: Real-time throughput sparkline (`ratatui::widgets::Sparkline`), Vim command mode, live search, request repeater, and multi-protocol inspector.
