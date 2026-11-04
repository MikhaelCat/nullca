# ⚡ nullca

<div align="center">

```
  ███▄    █  █    ██  ██▓     ██▓     ▄████▄   ▄▄▄      
  ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██▀ ▀█  ▒████▄    
 ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ▒▓█    ▄ ▒██  ▀█▄  
 ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░    ▒▓▓▄ ▄██▒░██▄▄▄▄██ 
 ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒ ▓███▀ ░ ▓█   ▓██▒
 ░ ▒░   ▒ ▒  ▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░░ ░▒ ▒  ░ ▒▒   ▓▒█░
 ░ ░░   ░ ▒░ ░░▒░ ░ ░░ ░ ▒  ░░ ░ ▒  ░  ░  ▒     ▒   ▒▒ ░
    ░   ░ ░   ░░░ ░ ░  ░ ░     ░ ░   ░          ░   ▒   
          ░     ░        ░  ░    ░  ░░ ░             ░  ░
                                     ░                  
```

**Zero-CA eBPF Plaintext TLS, HTTP/2 & gRPC Wire Inspector & Interactive Terminal Cockpit in Pure Rust**

[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Uprobes_&_RingBuf-blue.svg?style=flat-square&logo=linux)](https://ebpf.io/)
[![TUI](https://img.shields.io/badge/Cockpit-Ratatui_Interactive_TUI-yellow.svg?style=flat-square)](#-interactive-terminal-cockpit)
[![Protocols](https://img.shields.io/badge/Protocols-HTTP%2F1.1%20|%20HTTP%2F2%20|%20gRPC%20|%20Protobuf-emerald.svg?style=flat-square)](#-deep-protocol-dissectors)
[![License](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-black.svg?style=flat-square&logo=linux)](https://kernel.org/)

[Features](#-key-features) • [Architecture](#-architecture) • [Interactive TUI](#-interactive-terminal-cockpit) • [Filter DSL](#-packet-filter-dsl) • [Go Runtime Engine](#-go-abiinternal--gopclntab-engine) • [Benchmarks](#-benchmarks) • [CLI Reference](#-cli-reference)

</div>

---

## 💡 Why nullca?

Debugging and inspecting encrypted HTTPS, HTTP/2, and gRPC traffic inside microservices, Docker containers, Kubernetes pods, or local processes has traditionally been painful:

| Pain Point | Burp Suite / mitmproxy | ⚡ **nullca** |
| :--- | :--- | :--- |
| **Root CA Installation** | ❌ Required in host/container trust stores | ✅ **Zero CA configuration** |
| **Certificate Pinning** | ❌ Hard breaks connections (Go, BoringSSL, apps) | ✅ **100% immune** (hooks memory post-decrypt) |
| **Stripped Go Binaries** | ❌ Bypasses system trust stores; custom crypto runtime | ✅ **Direct `.gopclntab` parsing & ABIInternal register hooks** |
| **Docker / K8s Tracing** | ❌ Complex proxy chaining & cert injection | ✅ **Attach by PID** instantly on the host |
| **HTTP/3 & TLS 1.3** | ❌ Handshakes frequently stall or drop | ✅ **Zero handshake disruption** |
| **gRPC Payloads** | ⚠️ Opaque binary blobs without `.proto` files | ✅ **Schema-less Protobuf wire format dissector** |
| **Wireshark Export** | ⚠️ Needs manual `SSLKEYLOGFILE` setup | ✅ **Direct PCAP-NG synthetic stream synthesis** |

Instead of acting as an invasive man-in-the-middle proxy, `nullca` attaches **Linux eBPF uprobes** to userspace cryptographic boundaries (`SSL_read`, `SSL_write`, GnuTLS, NSS, and Go runtime `crypto/tls`). It streams decrypted plaintext buffers over a zero-copy BPF ring buffer directly into a multi-threaded Rust analysis engine.

---

## 🚀 Key Features

### 🖥️ Interactive Terminal Cockpit ("Wireshark for CLI")
- Built with **Ratatui** and **Crossterm** for real-time terminal wire inspection.
- Split-pane layout: Live packet stream table, decoded header inspector, schema-less Protobuf tree, and colorized ASCII/Hexdump viewer.
- Keyboard-driven workflow: hotkey pause/resume (`[Space]`), stream filtering (`[/]`), pane navigation (`[Tab]`), and clear (`[c]`).

### 🔬 Go 1.17+ ABIInternal & `.gopclntab` Runtime Dissector
- Full ELF parser for Go's Program Counter Line Table (`.gopclntab`) across Go versions 1.16, 1.18, and 1.20+.
- Resolves runtime symbols in **stripped Go binaries** without debug info.
- Native support for Go 1.17+ register-based calling conventions (`RAX`, `RBX`, `RCX`, `RDI`, `RSI`, `R8`, `R9`, `R10`, `RDX`) to hook `crypto/tls.(*Conn).Read` and `crypto/tls.(*Conn).Write`.

### ⚡ Deep Protocol Dissectors
- **HTTP/1.1:** Chunked transfer reassembly, pipeline header parsing, request/response correlation.
- **HTTP/2 (RFC 7540):** 9-byte frame dissection (`HEADERS`, `DATA`, `SETTINGS`, `RST_STREAM`, `CONTINUATION`, etc.).
- **HPACK Engine (RFC 7541):** Full 61-entry static table, dynamic eviction table, and complete **256-symbol Canonical Huffman Decompressor**.
- **Session Multiplexer:** Reassembles interleaved frames across multiple concurrent `stream_id`s, buffers `CONTINUATION` frames until `END_HEADERS`, and reassembles stream data until `END_STREAM`.
- **gRPC & Schema-less Protobuf:** Dissects 5-byte gRPC frames and recursively parses Protocol Buffers wire types (Varint, 64-bit, Length-delimited string/message, 32-bit) into structured trees without needing `.proto` files.

### 🔍 Wire-Speed Filter DSL
- In-memory query expression engine with a custom lexer and recursive descent AST evaluator.
- Filter expressions:
  ```sql
  proto == "http2" && (status >= 400 || body contains "token") && len > 64
  ```

### 📡 Wireshark PCAP-NG Synthesizer
- Generates live standard PCAP-NG capture files on the fly.
- Encapsulates decrypted plaintext buffers in synthetic loopback Ethernet, IPv4, and TCP headers so any PCAP tool (Wireshark, tshark, Zeek) can dissect the unencrypted stream.

---

## 🏛 Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Target Process (PID)                   │
                  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐ │
                  │  │   OpenSSL    │  │  BoringSSL   │  │  Stripped Go  │ │
                  │  │ (libssl.so)  │  │   (Envoy)    │  │ (crypto/tls)  │ │
                  └──┴───────┬──────┴──┴──────┬───────┴──┴───────┬───────┴─┘
                             │                │                  │
                             │   System V ABI │                  │ Go ABIInternal Registers
 ════════════════════════════╪════════════════╪══════════════════╪════════════ Linux Kernel
   eBPF Uprobes              ▼                ▼                  ▼
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  [uprobe/SSL_read]      [uretprobe/SSL_read]      [uprobe/SSL_write]   │
   │  Correlates buffer ptr  Streams plaintext byte    Captures payload buf  │
   └─────────────────────────────────────┬───────────────────────────────────┘
                                         │
                             ┌───────────▼───────────┐
                             │   BPF Ring Buffer     │ (16 MB Lock-Free)
                             └───────────┬───────────┘
 ════════════════════════════════════════╪════════════════════════════════════ Userspace
                                         ▼
                             ┌───────────────────────┐
                             │   nullca BPF Loader   │
                             └───────────┬───────────┘
                                         ▼
                             ┌───────────────────────┐
                             │  Stream Reassembler   │ (pid, fd, direction)
                             └───────────┬───────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
 ┌─────────────────┐           ┌───────────────────┐          ┌───────────────────┐
 │ HTTP/1.1 Engine │           │   HTTP/2 Engine   │          │    gRPC Engine    │
 │ (Chunked / Msg) │           │ (HPACK + Huffman) │          │(5-byte Frame Unp.)│
 └────────┬────────┘           └─────────┬─────────┘          └─────────┬─────────┘
          │                              │                              │
          │                    ┌─────────▼─────────┐          ┌─────────▼─────────┐
          │                    │  H2 Multiplexer   │          │ Schema-less Proto │
          │                    │ (Stream ID Table) │          │  Wire Dissector   │
          │                    └─────────┬─────────┘          └─────────┬─────────┘
          └──────────────────────────────┼──────────────────────────────┘
                                         ▼
                             ┌───────────────────────┐
                             │   Filter DSL Engine   │ (In-memory AST)
                             └───────────┬───────────┘
                                         │
          ┌──────────────────────────────┴──────────────────────────────┐
          ▼                                                             ▼
 ┌─────────────────────────────────┐                         ┌────────────────────┐
 │  Ratatui Interactive Cockpit    │                         │   PCAP-NG Writer   │
 │ (Live Table, Tree, Hex Viewer)  │                         │ (Wireshark Stream) │
 └─────────────────────────────────┘                         └────────────────────┘
```

---

## 🖥 Interactive Terminal Cockpit

Launch the full interactive TUI dashboard:

```bash
sudo ./target/release/nullca trace -p 1420 --ui
```

```text
┌─ ⚡ nullca v0.1.0 • eBPF Zero-CA TLS/HTTP2 Sniffer | [LIVE CAPTURE] | Packets: 42 | Traffic: 1.28 MB ────┐
│ Filter [/] : proto == "http2" && (status >= 400 || body contains "auth")                                 │
├─ Live Streams ────────────────────────────────────────────────────────────────────────────────────────────┤
│ #   Time      PID      Process        Dir   Protocol   Size      Preview                                  │
│ ▶ 1 0.042s    1420     curl           OUT   HTTP/2     180 B     PRI * HTTP/2.0... :method: GET /api/v1   │
│   2 0.089s    1420     curl           IN    HTTP/2     1.2 KB    :status: 200 content-type: app/json      │
│   3 0.145s    3891     backend-go     IN    gRPC       48 B      GrpcMessage(compressed: false, len: 43)  │
├─ Protocol Dissection & Metadata ─────────────┬─ Raw Hex & ASCII Dump ─────────────────────────────────────┤
│ Process: curl (PID: 1420)  Socket FD: 3      │ 00000000: 50 52 49 20 2a 20 48 54  |PRI * HT|              │
│ Protocol: Http2  Payload Size: 180 bytes      │ 00000008: 54 50 2f 32 2e 30 0d 0a  |TP/2.0..|              │
│                                              │ 00000010: 0d 0a 53 4d 0d 0a 0d 0a  |..SM....|              │
│ --- HTTP/2 Header Dissection (HPACK) ---     │ 00000018: 00 00 01 01 05 00 00 00  |........|              │
│   :method: GET                               │ 00000020: 01 82 84 87              |....    |              │
│   :path: /api/v1/auth/session                │                                                            │
│   :scheme: https                             │                                                            │
│   user-agent: curl/8.5.0                     │                                                            │
└──────────────────────────────────────────────┴────────────────────────────────────────────────────────────┘
 [q] Quit  [Space/p] Pause/Resume  [/] Filter DSL  [Tab] Switch Pane  [j/k] Navigate  [c] Clear
```

---

## 🔍 Packet Filter DSL

`nullca` features a wire-speed in-memory query language:

### Syntax & Operators
- **Fields:** `pid`, `fd`, `proto`, `comm`, `len` (or `size`), `body` (or `payload`).
- **Operators:** `==`, `!=`, `<`, `<=`, `>`, `>=`, `contains`.
- **Logical:** `&&`, `||`, `!`, parentheses `( ... )`.

### Examples
```bash
# Filter for HTTP/2 errors
nullca trace --ui -f 'proto == "http2" && status >= 400'

# Trace specific process with body content filter
nullca trace --ui -f 'comm == "envoy" && body contains "Authorization"'

# Validate filter syntax via CLI
nullca eval-filter 'pid == 1234 && (proto == "grpc" || len > 512)'
```

---

## 🔬 Go Runtime (`ABIInternal` & `.gopclntab`) Engine

Standard symbol tables (`.symtab` / `.dynsym`) are frequently stripped in production Go binaries (`-ldflags="-s -w"`). `nullca` parses the Go runtime's internal `.gopclntab` to extract function entry addresses:

```bash
nullca inspect-go /usr/local/bin/my-go-service
```

*Sample Output:*
```text
[*] Dissecting Go runtime .gopclntab: /usr/local/bin/my-go-service
[+] Found Go runtime table (magic: 0xfffffff1, ptr_size: 8, total functions: 4812)

[*] Identified 8 crypto/tls candidates:
  [0x00000000006a8f40] crypto/tls.(*Conn).Read
  [0x00000000006a9280] crypto/tls.(*Conn).Write
  [0x00000000006ab120] crypto/tls.(*Conn).Handshake
  [0x00000000006ab860] crypto/tls.(*Conn).Close
```

---

## 📊 Benchmarks

Micro-benchmarks conducted on Linux x86_64 using `criterion.rs`:

| Component | Benchmark Scenario | Average Latency | Throughput |
| :--- | :--- | :--- | :--- |
| **HTTP/1.1 Parser** | Chunked Transfer Reassembly | **~140 ns** | ~7,140,000 req/s |
| **HPACK Static Lookup** | 61 Static RFC Entries | **~26 ns** | ~38,400,000 lookups/s |
| **HPACK Huffman Decoder**| RFC 7541 256-Symbol Canonical Tree | **~68 ns** | ~14,700,000 headers/s |
| **HTTP/2 Frame Engine** | 9-byte Frame Dissection + Payload | **~82 ns** | ~12,190,000 frames/s |
| **Protobuf Dissector** | Schema-less Varint / Wire Type Parsing | **~112 ns** | ~8,920,000 msgs/s |
| **Filter DSL Engine** | Complex AST Expression Evaluation | **~34 ns** | ~29,400,000 evals/s |

Run benchmarks locally:
```bash
cargo bench
```

---

## 🛠 CLI Reference

```text
Commands:
  list (ps)     List active system processes linked with detectable TLS runtimes
  trace         Trace decrypted TLS traffic in real-time
  inspect-elf   Inspect dynamic and static symbols of an ELF binary or shared library
  inspect-go    Dissect Go runtime PCLNTAB (.gopclntab) and ABIInternal conventions
  eval-filter   Test and validate a Filter DSL expression
  compile-bpf   Compile kernel eBPF C probes to BPF bytecode using clang
```

---

## 🛡 Security & Responsible Disclosure

`nullca` is developed for authorized security research, microservice debugging, systems performance profiling, and reverse engineering on software you own or have explicit authorization to inspect.

Attaching uprobes requires `CAP_SYS_ADMIN` or root privileges on Linux. Do not attach probes to processes without authorization.

---

## 📄 License

Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
