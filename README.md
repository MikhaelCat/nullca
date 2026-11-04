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

**Zero-CA eBPF Plaintext TLS, HTTP/2 & gRPC Wire Inspector, Spawn-Tracer & Interactive Cockpit in Pure Rust**

[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Uprobes_&_RingBuf-blue.svg?style=flat-square&logo=linux)](https://ebpf.io/)
[![TUI](https://img.shields.io/badge/Cockpit-Ratatui_Interactive_TUI-yellow.svg?style=flat-square)](#-interactive-terminal-cockpit)
[![Protocols](https://img.shields.io/badge/Protocols-HTTP%2F1.1%20|%20HTTP%2F2%20|%20gRPC%20|%20Protobuf-emerald.svg?style=flat-square)](#-deep-protocol-dissectors)
[![Secrets](https://img.shields.io/badge/Secrets-JWT_&_Token_Dissector-red.svg?style=flat-square)](#-automated-jwt--secret-credential-dissector)
[![Export](https://img.shields.io/badge/Export-cURL_|_HAR_1.2_|_PCAP--NG-cyan.svg?style=flat-square)](#-copy-as-curl--har-12-export)
[![License](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-black.svg?style=flat-square&logo=linux)](https://kernel.org/)

[Why nullca?](#-why-nullca) • [Features](#-key-features) • [Architecture](#-architecture) • [Spawn & Trace](#-spawn--trace-mode) • [Interactive TUI](#-interactive-terminal-cockpit) • [Secrets Dissector](#-automated-jwt--secret-credential-dissector) • [cURL & HAR Export](#-copy-as-curl--har-12-export) • [Benchmarks](#-benchmarks) • [CLI Reference](#-cli-reference)

</div>

---

## 💡 Why nullca?

Debugging, reverse-engineering, and inspecting encrypted HTTPS, HTTP/2, and gRPC traffic inside microservices, Docker containers, Kubernetes pods, or CLI tools has traditionally been painful:

| Pain Point | Burp Suite / mitmproxy | ⚡ **nullca** |
| :--- | :--- | :--- |
| **Root CA Installation** | ❌ Required in host/container trust stores | ✅ **Zero CA configuration** |
| **Certificate Pinning** | ❌ Hard breaks connections (Go, BoringSSL, apps) | ✅ **100% immune** (hooks memory post-decrypt) |
| **Stripped Go Binaries** | ❌ Bypasses system trust stores; custom crypto runtime | ✅ **Direct `.gopclntab` parsing & ABIInternal register hooks** |
| **One-Off Command Tracing** | ❌ Must configure proxy environment variables | ✅ **`nullca run -- <cmd>`** spawns & traces instantly |
| **gRPC Payloads** | ⚠️ Opaque binary blobs without `.proto` files | ✅ **Schema-less Protobuf wire format dissector** |
| **Token & Secret Leakage** | ⚠️ Manual searching across raw request tabs | ✅ **Automatic JWT claims, AWS keys, CTF flags scanner** |
| **Tool Interoperability** | ⚠️ Proprietary formats | ✅ **Instant "Copy as cURL", HAR 1.2, and PCAP-NG** |

Instead of acting as an invasive man-in-the-middle proxy, `nullca` attaches **Linux eBPF uprobes** to userspace cryptographic boundaries (`SSL_read`, `SSL_write`, GnuTLS, NSS, and Go runtime `crypto/tls`). It streams decrypted plaintext buffers over a zero-copy BPF ring buffer directly into a multi-threaded Rust analysis engine.

---

## 🚀 Key Features

### ⚡ Spawn & Trace Mode (`nullca run -- <command>`)
- Run and trace any target CLI tool or binary in a single command:
  ```bash
  sudo nullca run --ui -- curl -s https://api.github.com/user
  sudo nullca run --har dump.har -- ./my_microservice
  ```
- Automatically attaches eBPF uprobes upon `execve` before the process initiates its first TLS handshake.

### 🖥️ Interactive Terminal Cockpit ("Wireshark for CLI")
- Built with **Ratatui** and **Crossterm** for real-time terminal wire inspection.
- Split-pane layout: Live packet stream table, decoded header inspector, schema-less Protobuf tree, and colorized ASCII/Hexdump viewer.
- Keyboard-driven workflow: hotkey pause/resume (`[Space]`), stream filtering (`[/]`), pane navigation (`[Tab]`), copy as cURL (`[c]`), export HAR (`[e]`), and clear (`[x]`).

### 🔑 Automated JWT & Secret Credential Dissector
- Real-time scanner for sensitive credentials in requests and responses:
  - **JWT Tokens:** Auto-decodes Base64URL header and payload into human-readable JSON with timestamp expiration analysis.
  - **HTTP Basic Auth:** Decodes `Authorization: Basic ...` into `username:password`.
  - **API Keys & Cloud Credentials:** Detects AWS Access Keys (`AKIA...`), GitHub PATs (`ghp_...`), Stripe keys (`sk_live_...`), Slack tokens (`xoxb-...`), and Private Keys.
  - **CTF Flags:** Automatic regex extraction of flags (`flag{...}`, `THEM{...}`, `ctf{...}`).
- Displays a prominent red `[JWT]` / `[KEY]` / `[FLAG]` pill in the stream table and formats decoded claims in the `[3] JWT & Secrets` inspector tab.

### 📋 "Copy as cURL" & HAR 1.2 Export
- **One-key cURL generator:** Press `[c]` in the TUI or use the exporter to generate exact, runnable shell `curl` commands with matched headers, authentication, and payload bodies.
- **HTTP Archive (HAR 1.2) Export:** Export full sessions into standard `.har` JSON files compatible with Chrome DevTools, Burp Suite, Postman, Insomnia, Charles, and Proxyman.

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
- In-memory query expression engine with a custom lexer and recursive descent AST evaluator:
  ```sql
  proto == "http2" && (status >= 400 || body contains "token") && len > 64
  ```

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
                             │  JWT & Secrets Engine │ (Auto Base64URL Dec.)
                             └───────────┬───────────┘
                                         ▼
                             ┌───────────────────────┐
                             │   Filter DSL Engine   │ (In-memory AST)
                             └───────────┬───────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
 ┌─────────────────────────────────┐ ┌────────────────────┐ ┌────────────────────┐
 │  Ratatui Interactive Cockpit    │ │   PCAP-NG Writer   │ │   HAR 1.2 Export   │
 │ (Live Table, Tree, Hex Viewer)  │ │ (Wireshark Stream) │ │(Chrome / Burp /..) │
 └─────────────────────────────────┘ └────────────────────┘ └────────────────────┘
```

---

## ⚡ Spawn & Trace Mode

Spawn any command and trace its decrypted network activity immediately:

```bash
# Run curl and launch interactive TUI cockpit
sudo ./target/release/nullca run --ui -- curl -s https://api.github.com/user

# Run a Go binary or CTF client and dump to HAR
sudo ./target/release/nullca run --har session.har -- ./ctf_challenge_binary
```

---

## 🖥 Interactive Terminal Cockpit

Launch the full interactive TUI dashboard:

```bash
sudo ./target/release/nullca trace -p 1420 --ui
```

```text
┌─ ⚡ nullca v0.1.0 • eBPF TLS/HTTP2/gRPC Sniffer | [LIVE CAPTURE] | Pkts: 42 | Traffic: 1.28 MB ──────────┐
│ Filter [/] : proto == "http2" && (status >= 400 || body contains "auth")                                 │
├─ Live Streams ────────────────────────────────────────────────────────────────────────────────────────────┤
│ #   Time     PID     Process        Dir  Protocol  Secrets   Size     Preview                             │
│ ▶ 1 0.042s   1420    curl           OUT  HTTP/2    -         180 B    PRI * HTTP/2.0... :method: GET /api │
│   2 0.089s   1420    curl           IN   HTTP/2    [JWT]     1.2 KB   :status: 200 content-type: app/json │
│   3 0.145s   3891    backend-go     IN   gRPC      [FLAG]    48 B     GrpcMessage(compressed: false, len) │
├─ [1] Headers & Info  [2] Protobuf Tree  [3] JWT & Secrets  [4] cURL ────────┬─ Raw Hex & ASCII Dump ──────┤
│ Process: curl (PID: 1420)  Socket FD: 3                                     │ 00000000: 50 52 49 20 |PRI |│
│ Protocol: Http2  Payload Size: 180 bytes                                    │ 00000008: 54 50 2f 32 |TP/2|│
│                                                                             │                             │
│ [#1] JwtToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...                      │                             │
│     HEADER: {"alg": "HS256", "typ": "JWT"}                                  │                             │
│     CLAIMS (PAYLOAD):                                                       │                             │
│       "sub": "admin_user",                                                  │                             │
│       "role": "cluster-admin",                                              │                             │
│       "exp": 1798765432                                                     │                             │
└─────────────────────────────────────────────────────────────────────────────┴─────────────────────────────┘
 [q] Quit  [Space] Pause  [/] Filter  [c] Copy cURL  [e] Save HAR  [1-4] Tabs  [Tab] Panes  [j/k] Move
```

---

## 🔍 Packet Filter DSL

```bash
# Filter for HTTP/2 errors
nullca trace --ui -f 'proto == "http2" && status >= 400'

# Trace specific process with body content filter
nullca trace --ui -f 'comm == "envoy" && body contains "Authorization"'

# Validate filter syntax via CLI
nullca eval-filter 'pid == 1234 && (proto == "grpc" || len > 512)'
```

---

## 🔑 Scan Files for Secrets & Credentials

Scan any packet dump, memory image, or log file directly for leaked tokens:

```bash
nullca scan-secrets /path/to/capture.dump
```

*Sample Output:*
```text
[*] Scanning for secrets in: /path/to/capture.dump

[!] Detected 2 sensitive token(s):

[1] JwtToken (Offset: 142)
  Raw Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3...
    HEADER:
    { "alg": "HS256", "typ": "JWT" }
    CLAIMS (PAYLOAD):
    { "sub": "admin_user", "role": "superuser" }

[2] CtfFlag (Offset: 512)
  Raw Token: flag{ebpf_zero_ca_memory_inspection_ftw}
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
  trace         Trace decrypted TLS traffic of a running process in real-time
  run           Spawn a target command and immediately trace its decrypted TLS activity
  scan-secrets  Scan a file or dump for leaked JWT tokens, API keys, and CTF flags
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
