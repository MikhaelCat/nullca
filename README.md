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

**Zero-CA eBPF Plaintext TLS, HTTP/2, WebSocket & gRPC Wire Inspector, Live Replayer & Diff Engine in Pure Rust**

[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Uprobes_&_RingBuf-blue.svg?style=flat-square&logo=linux)](https://ebpf.io/)
[![TUI](https://img.shields.io/badge/Cockpit-Ratatui_Interactive_TUI-yellow.svg?style=flat-square)](#-interactive-terminal-cockpit)
[![Protocols](https://img.shields.io/badge/Protocols-HTTP%2F1.1%20|%20HTTP%2F2%20|%20WebSocket%20|%20gRPC%20|%20Redis%20|%20SQL%20|%20SMTP-emerald.svg?style=flat-square)](#-deep-protocol-dissectors)
[![Certs](https://img.shields.io/badge/Certificates-Universal_Zero--CA_%26_X.509_ASN.1-blueviolet.svg?style=flat-square)](#-universal-tls-certificate-support--x509-inspector)
[![Secrets](https://img.shields.io/badge/Secrets-JWT_&_Token_Dissector-red.svg?style=flat-square)](#-automated-jwt--secret-credential-dissector)
[![Diff](https://img.shields.io/badge/Diff-Side--by--Side_Engine-purple.svg?style=flat-square)](#-side-by-side--unified-packet-diff-engine)
[![IPC](https://img.shields.io/badge/IPC-Unix_Socket_Streaming-cyan.svg?style=flat-square)](#-unix-domain-socket-ipc-streaming)
[![Export](https://img.shields.io/badge/Export-cURL_|_HAR_1.2_|_PCAP--NG-lightgrey.svg?style=flat-square)](#-copy-as-curl--har-12-export)
[![License](https://img.shields.io/badge/License-MIT-black.svg?style=flat-square)](LICENSE)

[Why nullca?](#-why-nullca) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Spawn & Trace](#-spawn--trace-mode) • [Interactive Cockpit](#-interactive-terminal-cockpit) • [Packet Diff](#-side-by-side--unified-packet-diff-engine) • [Live Replay](#-live-request-replay--tampering) • [IPC Streaming](#-unix-domain-socket-ipc-streaming) • [Benchmarks](#-benchmarks) • [CLI Reference](#-cli-reference)

</div>

---

## 💡 Why nullca?

Debugging, reverse-engineering, and inspecting encrypted HTTPS, HTTP/2, WebSocket, and gRPC traffic inside microservices, Docker containers, Kubernetes pods, or CLI tools has traditionally been painful:

| Pain Point | Burp Suite / mitmproxy | ⚡ **nullca** |
| :--- | :--- | :--- |
| **Root CA Installation** | ❌ Required in host/container trust stores | ✅ **Zero CA configuration** |
| **Certificate Pinning** | ❌ Hard breaks connections (Go, BoringSSL, apps) | ✅ **100% immune** (hooks memory post-decrypt) |
| **Stripped Go Binaries** | ❌ Bypasses system trust stores; custom crypto runtime | ✅ **Direct `.gopclntab` parsing & ABIInternal register hooks** |
| **WebSocket Inspection** | ⚠️ Frame masking complicates manual review | ✅ **Full RFC 6455 unmasking, defragmentation & JSON parsing** |
| **One-Off Command Tracing** | ❌ Must configure proxy environment variables | ✅ **`nullca run -- <cmd>`** spawns & traces instantly |
| **Request Comparison** | ⚠️ Clunky manual diffing across tabs | ✅ **Built-in Side-by-Side Myers Diff Engine (`[d]`)** |
| **Tampering & Replay** | ⚠️ Heavy GUI required | ✅ **Microsecond live request retransmission (`[r]`)** |
| **External Scripting** | ⚠️ Complex Python addon APIs | ✅ **`/tmp/nullca.sock` UNIX IPC daemon streaming NDJSON** |
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
- Split-pane layout: Live packet stream table, decoded header inspector, schema-less Protobuf tree, WebSocket viewer, side-by-side diff inspector, and colorized ASCII/Hexdump viewer.
- Keyboard-driven workflow:
  - `[Space]` / `[p]`: Pause / resume capture stream
  - `[/]`: Live Query Filter DSL
  - `[Tab]`: Switch active pane focus
  - `[c]`: Generate and copy "Copy as cURL" command
  - `[r]`: Instant non-blocking request replay to remote server
  - `[d]`: Mark baseline packet 📌 / toggle Side-by-Side Diff Inspector
  - `[e]`: Export session to HTTP Archive (HAR 1.2) JSON
  - `[x]`: Clear capture buffers
  - `[1-6]`: Switch detail tabs (`[1] Headers`, `[2] Protobuf`, `[3] Secrets`, `[4] cURL`, `[5] WebSocket`, `[6] Diff`)

### 🔍 Side-by-Side & Unified Packet Diff Engine
- Built-in **Myers / LCS diff algorithm** in pure Rust:
  - Compare any two intercepted packets directly in the terminal cockpit by pressing `[d]` to set a baseline 📌 and `[d]` on another packet to inspect differences.
  - Structure-aware diffing: highlights added/removed headers, changed values (`old -> new`), and computes line-by-line colored diffs of formatted JSON or plaintext bodies.
  - CLI command: compare two raw files or packet dumps:
    ```bash
    nullca diff packet_a.txt packet_b.txt
    ```

### ⚡ Live Request Replay & Tampering
- Replay any intercepted HTTP request with microsecond-precision latency telemetry:
  ```bash
  nullca replay --target api.github.com:443 --method GET --path /user -H "Authorization: Bearer token"
  nullca replay --target 127.0.0.1:8080 --raw-file request.raw
  ```
- Measures and prints DNS connect latency, Time-To-First-Byte (TTFB), total roundtrip duration, response headers, and syntax-highlighted response bodies.
- Triggered instantly inside the Cockpit by pressing `[r]` on any selected request packet.

### 📜 Universal TLS Certificate Support & Deep X.509 Dissector
- **Zero-CA Architecture = 100% Real-World Certificate Compatibility:**
  - Conventional proxies (Burp Suite, mitmproxy, Charles) must generate forge certificates signed by a local Root CA. If the application uses Certificate Pinning or strict trust stores, the TLS handshake is rejected.
  - `nullca` does **not** terminate or forge TLS sessions. It hooks userspace crypto boundaries (`SSL_read`, `SSL_write`, `crypto/tls.(*Conn).Read/Write`) **inside process memory**.
  - As a result, **every single TLS certificate in existence works out of the box with zero configuration**:
    - Public CAs: Let's Encrypt, DigiCert, Sectigo, Google Trust Services, Cloudflare, GlobalSign.
    - Private & Enterprise PKI: HashiCorp Vault, Active Directory Certificate Services (AD CS), AWS Private CA.
    - Self-signed & dev certificates: `localhost.pem`, Kubernetes internal TLS, mTLS mutual-auth certs.
    - Pinned certificates: Mobile apps, hardened Go binaries, and embedded TLS trust anchors.
- **Deep Pure-Rust X.509 ASN.1 Engine (`nullca inspect-cert`):**
  - **Full Cryptographic Suite Support:**
    - Standard & Heavy RSA: 1024, 2048, 3072, 4096, 8192-bit and RSASSA-PSS.
    - Elliptic Curves: NIST curves (secp256r1/P-256, secp384r1/P-384, secp521r1/P-521), Koblitz secp256k1 (Bitcoin/Ethereum), and European Brainpool curves (brainpoolP256r1, brainpoolP384r1, brainpoolP512r1).
    - Edwards & Montgomery: Ed25519, Ed448 (Goldilocks curve), X25519, X448.
    - National Standards: Russian GOST R 34.10-2001/2012 (256/512-bit TC-26) and Chinese SM2/SM3/SM9 commercial crypto.
    - Post-Quantum Cryptography (NIST FIPS 203/204/205 & Hybrid): ML-DSA (Dilithium-2/3/5), Falcon-512/1024, Kyber/ML-KEM-512/768/1024, SLH-DSA (SPHINCS+).
    - Legacy Suites: Digital Signature Algorithm (DSA), Diffie-Hellman, SHA-1, MD5, and MD2 legacy suites.
  - **RFC 5280 Extensions Dissection:**
    - Basic Constraints (`is_ca`, `path_length_constraint`).
    - Key Usage bitflags (Digital Signature, Key Encipherment, Cert Sign, CRL Sign, etc.).
    - Extended Key Usage (TLS Server Auth, Client Auth, Code Signing, Time Stamping, OCSP Signing, Smartcard Logon).
    - Subject Alternative Names (SANs) with full DNS Names, IPv4/IPv6 Addresses, Emails, URIs.
    - Authority Information Access (AIA) OCSP Responders and CA Issuer URLs.
    - CRL Distribution Points (revocation endpoint URLs), Subject Key ID (SKI) & Authority Key ID (AKI).
  - **Multi-Certificate Bundles & Directory Inventory:**
    - Inspect single certs, full chains, bundles (`ca-certificates.crt`), or entire directories (`/etc/ssl/certs`):
      ```bash
      # Dissect single certificate with exact cryptographic fingerprints:
      nullca inspect-cert /etc/ca-certificates/extracted/cadir/ISRG_Root_X1.pem

      # Dissect full certificate bundle (e.g. 119 certificates in one file):
      nullca inspect-cert /etc/ssl/certs/ca-certificates.crt

      # Scan entire directory and generate cryptographic inventory summary:
      nullca inspect-cert /etc/ca-certificates/extracted/cadir
      ```

### 🗄️ Non-HTTP Encrypted Protocols (Redis, SQL Database & SMTP)
- Encrypted traffic is not limited to HTTP. `nullca` automatically detects and dissects non-HTTP protocols flowing over TLS:
  - **Redis TLS (RESP):** Intercepts and parses Redis Serialization Protocol commands (`AUTH`, `SET`, `GET`, `PING`, `CLUSTER`, `CONFIG`) directly from encrypted Redis tunnels (`rediss://`).
  - **Database TLS (PostgreSQL & MySQL):** Identifies encrypted database connections and extracts plaintext SQL query commands (`SELECT`, `INSERT`, `UPDATE`, `CREATE TABLE`).
  - **SMTP Mail TLS:** Dissects STARTTLS / SMTPS mail dialogs (`HELO`, `EHLO`, `MAIL FROM:`, `RCPT TO:`, `DATA`).
  - Tagged with dedicated colored table pills (`[REDIS]`, `[SQL]`, `[SMTP]`) in the Cockpit and formatted for instant analysis.

### 🌐 RFC 6455 WebSocket Dissector & Frame Assembler
- Complete WebSocket protocol dissection:
  - Parses Frame Header: `FIN`, `RSV1-3`, `Opcode` (`Continuation`, `Text`, `Binary`, `Close`, `Ping`, `Pong`).
  - Automatic 4-byte masking key extraction and zero-copy payload unmasking (`payload[i] ^ mask[i % 4]`).
  - Handles 7-bit, 16-bit extended (`0x7E`), and 64-bit extended (`0x7F`) payload lengths.
  - Multi-frame defragmentation: seamlessly reassembles split fragmented WebSocket messages across frames.
  - Dissects Close status codes (1000 Normal, 1001 Going Away, 1006 Abnormal, 1011 Server Error) and reason strings.
  - Automatic JSON heuristic detection on WebSocket payloads.

### 🔌 Unix Domain Socket IPC Streaming Daemon
- Stream live decrypted TLS events from background NullCA daemons to external scripts, Python/pwntools bots, or terminal monitors:
  ```bash
  # Start trace with IPC socket broadcast
  sudo nullca trace --socket /tmp/nullca.sock -p 1420

  # Connect and stream live NDJSON without root privileges
  nullca stream --socket /tmp/nullca.sock --json | jq .
  ```
- Enables automated CTF flag extractors, Discord/Telegram alert webhooks, and live penetration-testing pipelines.

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
  proto == "websocket" || (proto == "http2" && status >= 400 && body contains "token")
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
        ┌───────────────────┬────────────┴───────┬───────────────────┐
        ▼                   ▼                    ▼                   ▼
 ┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
 │   HTTP/1    │     │    HTTP/2    │     │  WebSocket  │     │     gRPC     │
 │ (Chunk/Msg) │     │(HPACK+Huffm) │     │ (RFC 6455)  │     │(Proto Wire)  │
 └──────┬──────┘     └──────┬───────┘     └──────┬──────┘     └──────┬───────┘
        │                   │                    │                   │
        └───────────────────┴────────────┬───────┴───────────────────┘
                                         ▼
                             ┌───────────────────────┐
                             │  JWT & Secrets Engine │ (Auto Base64URL Dec.)
                             └───────────┬───────────┘
                                         ▼
                             ┌───────────────────────┐
                             │   Filter DSL Engine   │ (In-memory AST)
                             └───────────┬───────────┘
                                         │
           ┌─────────────────────────────┼─────────────────────────────┐
           ▼                             ▼                             ▼
 ┌───────────────────┐         ┌───────────────────┐         ┌───────────────────┐
 │ Ratatui Cockpit   │         │ Unix IPC Stream   │         │ Replay & Tamper   │
 │ (Diff, Tabs, TUI) │         │ (/tmp/nullca.sock)│         │ (Latency Stats)   │
 └───────────────────┘         └───────────────────┘         └───────────────────┘
```

---

## ⚡ Spawn & Trace Mode

Spawn any command and trace its decrypted network activity immediately:

```bash
# Run curl and launch interactive TUI cockpit
sudo nullca run --ui -- curl -s https://api.github.com/user

# Run a Go binary or CTF client and dump to HAR
sudo nullca run --har session.har -- ./ctf_challenge_binary
```

---

## 🖥 Interactive Terminal Cockpit

Launch the full interactive TUI dashboard:

```bash
sudo nullca trace -p 1420 --ui
```

```text
┌─ ⚡ NullCA Cockpit ─ eBPF Plaintext TLS, HTTP/2 & WebSocket Inspector  [LIVE]  [BASE: #1] ────────────────┐
│ Filter [/] : proto == "websocket" || status >= 400                                                        │
├─ Captured Decrypted Packets ──────────────────────────────────────────────────────────────────────────────┤
│ #     DIR  PROTO    PROCESS        PID      SIZE       SECURITY   PAYLOAD PREVIEW                         │
│ 📌 #1 OUT  HTTP/1.1 curl           1420     180 B      -          POST /api/v1/auth HTTP/1.1              │
│ ▶  #2 IN   HTTP/1.1 curl           1420     1.2 KB     [JWT]      HTTP/1.1 200 OK Content-Type: app/json  │
│    #3 OUT  WS       binance-bot    3891     64 B       -          [TEXT] {"action":"subscribe"}           │
│    #4 IN   WS       binance-bot    3891     128 B      -          [JSON] {"event":"subscribed","chan":1}  │
├─ [1] Headers & Info  [2] Protobuf  [3] JWT & Secrets  [4] cURL  [5] WebSocket  [6] Diff ───┬─ Hexdump ────┤
│ Process: curl (PID: 1420)  Socket FD: 3                                                    │ 00000000: ...│
│ Protocol: Http1  Payload Size: 1240 bytes                                                  │ 00000010: ...│
│                                                                                            │              │
│ Detected 1 sensitive token(s):                                                             │              │
│   Type: JwtToken (Offset: 120)                                                             │              │
│   Raw: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...                                             │              │
│   HEADER: {"alg": "HS256", "typ": "JWT"}                                                   │              │
│   CLAIMS: {"sub": "root", "role": "admin", "exp": 1798765432}                              │              │
└────────────────────────────────────────────────────────────────────────────────────────────┴──────────────┘
 [q] Quit  [Space] Pause  [/] Filter  [c] cURL  [r] Replay  [d] Diff  [e] HAR  [1-6] Tabs  [Tab] Panes  [j/k] Move
```

---

## 🔍 Side-by-Side & Unified Packet Diff Engine

Compare two requests or responses side-by-side to understand authentication divergences, rate limit triggers, or parameter changes:

```bash
# Compare two intercepted HTTP requests
nullca diff req1.txt req2.txt
```

*Inside Cockpit:*
1. Highlight any packet and press `[d]` to set baseline 📌.
2. Navigate to another packet and press `[d]` to open the **Diff Inspector** tab!
3. View highlighted header additions (`+`), removals (`-`), modified values (`old -> new`), and JSON body diffs.
4. Press `[Esc]` to clear baseline.

---

## ⚡ Live Request Replay & Tampering

Retransmit requests directly from the CLI or within the Cockpit:

```bash
# Replay against API endpoint
nullca replay --target api.github.com:443 --method GET --path /zen -H "User-Agent: nullca/0.1.0"

# Replay from captured raw request file
nullca replay --target 127.0.0.1:8080 --raw-file /path/to/request.raw
```

*Output:*
```text
[*] Preparing request replay to target: api.github.com:443
[+] Transmitting: GET /zen (Host: api.github.com:443)

=== Replay Response ===
Status: 200 OK
Timing: Connect: 12.40ms | TTFB: 28.50ms | Total: 41.20ms

--- Headers ---
content-type: text/plain;charset=utf-8
server: github.com

--- Body (23 bytes) ---
Practicality beats purity.
```

---

## 🔌 Unix Domain Socket IPC Streaming

Stream live decrypted TLS events into external pipelines, Python scripts, or custom alert bots:

```bash
# Terminal 1: Run trace with IPC socket broadcast
sudo nullca trace -p 1420 --socket /tmp/nullca.sock

# Terminal 2: Stream live NDJSON without root
nullca stream --socket /tmp/nullca.sock --json | jq '{comm, proto, data_len}'
```

*Python Integration Example:*
```python
import socket, json

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/tmp/nullca.sock")
file_obj = sock.makefile("r")

for line in file_obj:
    event = json.loads(line)
    print(f"[{event['comm']}] {event['direction']} {event['data_len']} bytes")
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
  stream        Stream live decrypted events from a background NullCA daemon socket
  replay        Replay and tamper an HTTP request against a target server with microsecond latency metrics
  diff          Compare two intercepted packets, payload dumps, or HTTP messages side-by-side
  inspect-cert  Dissect and inspect an X.509 certificate (PEM or DER binary)
  completions   Generate shell autocompletion script (bash, zsh, fish, powershell)
  scan-secrets  Scan a file or dump for leaked JWT tokens, API keys, and CTF flags
  inspect-elf   Inspect dynamic and static symbols of an ELF binary or shared library
  inspect-go    Dissect Go runtime PCLNTAB (.gopclntab) and ABIInternal conventions in Go binaries
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
