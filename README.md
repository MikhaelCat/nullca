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

**Zero-CA eBPF Plaintext TLS, HTTP/2 & gRPC Sniffer and Wire Inspector in Pure Rust**

[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Uprobes_&_RingBuf-blue.svg?style=flat-square&logo=linux)](https://ebpf.io/)
[![Protocols](https://img.shields.io/badge/Protocols-HTTP%2F1.1%20|%20HTTP%2F2%20|%20gRPC-emerald.svg?style=flat-square)](#supported-protocols)
[![License](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-black.svg?style=flat-square&logo=linux)](https://kernel.org/)

[Features](#-key-features) • [Architecture](#-architecture) • [Quickstart](#-quickstart) • [Under the Hood](#-under-the-hood) • [Benchmarks](#-benchmarks) • [CLI Reference](#-cli-reference)

</div>

---

## 💡 Why nullca?

Inspecting encrypted HTTPS, HTTP/2, and gRPC traffic inside microservices, Docker containers, Kubernetes pods, or local processes has traditionally been painful:

| Pain Point | Burp Suite / mitmproxy | ⚡ **nullca** |
| :--- | :--- | :--- |
| **Root CA Installation** | ❌ Required in host/container trust stores | ✅ **Zero CA configuration** |
| **Certificate Pinning** | ❌ Hard breaks connections (Go, BoringSSL, apps) | ✅ **100% immune** (hooks memory post-decrypt) |
| **Docker / K8s Tracing** | ❌ Complex proxy chaining & cert injection | ✅ **Attach by PID** instantly on the host |
| **HTTP/3 & TLS 1.3** | ❌ Handshakes frequently stall or drop | ✅ **Zero handshake disruption** |
| **Wireshark Export** | ⚠️ Needs manual SSLKEYLOGFILE setup | ✅ **Direct PCAP-NG synthetic stream export** |

Instead of acting as a man-in-the-middle proxy, `nullca` attaches **Linux eBPF uprobes** to userspace cryptographic boundaries (`SSL_read`, `SSL_write`, and Go runtime `crypto/tls`). It streams decrypted plaintext buffers over a zero-copy BPF ring buffer directly to a multi-threaded Rust analysis engine.

---

## 🚀 Key Features

- **Zero-CA & Zero-Proxy:** No generated root certificates, no DNS redirection, and no iptables rerouting.
- **Deep Protocol Decoding:**
  - **HTTP/1.1:** Chunked transfer reassembly, pipeline header parsing, request/response correlation.
  - **HTTP/2 (RFC 7540):** 9-byte frame dissection (`HEADERS`, `DATA`, `SETTINGS`, `RST_STREAM`, etc.).
  - **HPACK Engine (RFC 7541):** Full static table (61 entries) and dynamic table header decompression.
  - **gRPC:** 5-byte frame unpacker (compression flag + big-endian length) with payload inspection.
- **Pure Rust 64-bit ELF Parser:** Zero external dependencies for symbol resolution. Directly parses `.symtab`, `.dynsym`, and `.strtab` to compute virtual memory offsets for target libraries.
- **Wireshark PCAP-NG Synthesizer:** Real-time generation of PCAP-NG streams containing synthetic loopback Ethernet, IPv4, and TCP headers wrapping the decrypted plaintext payload.
- **Sub-microsecond Stream Reassembler:** Thread-safe TCP stream reconstructor tracking socket states across `(pid, fd, direction)`.
- **Developer-First CLI:** Colorized terminal output with hexdump views, PID scanners, and JSON streaming.

---

## 🏛 Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Target Process (PID)                   │
                  │  ┌──────────────┐     ┌──────────────┐     ┌─────────┐ │
                  │  │  OpenSSL     │     │  BoringSSL   │     │ Go App  │ │
                  │  │ (SSL_read/   │     │ (SSL_read/   │     │ (crypto/│ │
                  │  │  SSL_write)  │     │  SSL_write)  │     │  tls)   │ │
                  └──┴───────┬──────┴─────┴──────┬───────┴─────┴────┬────┴─┘
                             │                   │                  │
 ════════════════════════════╪═══════════════════╪══════════════════╪════════════ Linux Kernel
   eBPF Uprobes              ▼                   ▼                  ▼
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  [uprobe/SSL_read]      [uretprobe/SSL_read]      [uprobe/SSL_write]   │
   │  Stores fd & buf ptr    Reads returned plaintext  Reads outgoing buffer │
   └─────────────────────────────────────┬───────────────────────────────────┘
                                         │
                             ┌───────────▼───────────┐
                             │   BPF Ring Buffer     │ (16 MB lock-free)
                             └───────────┬───────────┘
 ════════════════════════════════════════╪════════════════════════════════════ Userspace
                                         ▼
                             ┌───────────────────────┐
                             │   nullca BPF Loader   │
                             └───────────┬───────────┘
                                         ▼
                             ┌───────────────────────┐
                             │   Stream Reassembler  │ (pid, fd, direction)
                             └───────────┬───────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
 ┌─────────────────┐           ┌───────────────────┐          ┌───────────────────┐
 │ HTTP/1.1 Engine │           │   HTTP/2 Engine   │          │    gRPC Engine    │
 │ (Chunked / Msg) │           │ (HPACK RFC 7541)  │          │  (5-byte Frames)  │
 └────────┬────────┘           └─────────┬─────────┘          └─────────┬─────────┘
          │                              │                              │
          └──────────────────────────────┼──────────────────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │       Dispatcher Engine       │
                         └───────┬───────────────┬───────┘
                                 │               │
                                 ▼               ▼
                      ┌────────────────────┐   ┌────────────────────┐
                      │ Terminal Formatter │   │   PCAP-NG Writer   │
                      │  (Hexdump & TUI)   │   │ (Wireshark Stream) │
                      └────────────────────┘   └────────────────────┘
```

---

## 🛠 Quickstart

### Prerequisites

- **Linux Kernel:** 5.8+ (with `CONFIG_BPF=y`, `CONFIG_UPROBES=y`, and `tracefs` mounted).
- **Rust Toolchain:** Stable 1.75+.
- **Clang:** 14+ (optional, only needed when recompiling eBPF C probes).
- **Root Privileges:** Required for attaching uprobes via `tracefs` or `BPF_PROG_TYPE_KPROBE`.

### Installation

```bash
# Clone the repository
git clone https://github.com/MikhaelCat/nullca.git
cd nullca

# Build in release mode
cargo build --release

# Run self-tests
cargo test --all
```

---

## 💻 CLI Reference

### 1. Discover Processes Using TLS Libraries
Scan all running processes on the system to find OpenSSL, BoringSSL, and Go `crypto/tls` candidates:

```bash
sudo ./target/release/nullca ps
```

*Sample Output:*
```
[INFO] Scanning running processes for cryptographic libraries...
PID    PROCESS                   TLS ENGINE             LIBRARY PATH
-----------------------------------------------------------------------------------------
1420   curl                      OpenSSL                /usr/lib/libssl.so.3
3891   envoy                     BoringSSL              /usr/bin/envoy
4912   backend-api               Go crypto/tls          /opt/services/backend-api
```

### 2. Trace Decrypted Traffic for a Specific Process
Stream decrypted requests and responses directly to the terminal:

```bash
sudo ./target/release/nullca trace -p 1420
```

### 3. Stream Directly to Wireshark via PCAP-NG
Synthesize a standard PCAP-NG capture file for in-depth analysis in Wireshark:

```bash
sudo ./target/release/nullca trace -p 1420 --pcap decrypted_traffic.pcapng
```

Or pipe directly into Wireshark in real time:

```bash
sudo ./target/release/nullca trace -p 1420 --pcap - | wireshark -k -i -
```

### 4. Inspect ELF Symbols
Inspect any shared library or binary to calculate runtime uprobe offsets:

```bash
./target/release/nullca inspect-elf /usr/lib/libssl.so.3
```

---

## 🔬 Under the Hood

### ELF Virtual Address to File Offset Translation
In shared objects (`ET_DYN`) and executables (`ET_EXEC`), function addresses stored in symbol tables (`st_value`) are virtual memory addresses. To attach a Linux uprobe, `nullca` calculates the exact file offset without loading the file into execution memory:

$$\text{File Offset} = \text{st\_value} - \text{p\_vaddr} + \text{p\_offset}$$

Where the enclosing segment satisfies:
$$\text{p\_vaddr} \le \text{st\_value} < \text{p\_vaddr} + \text{p\_memsz}$$

### Linux Tracefs Uprobe Registration
`nullca` communicates directly with Linux `tracefs` (`/sys/kernel/tracing` or `/sys/kernel/debug/tracing`):
1. **Entry Probe:** Appends `p:uprobes/nullca_<id>_entry <binary_path>:<offset> fd=%di buf=%si` to `uprobe_events`.
2. **Return Probe:** Appends `r:uprobes/nullca_<id>_ret <binary_path>:<offset> ret=%ax` to `uprobe_events`.
3. **Map Correlation:** When `SSL_read` is called, the entry probe saves the target buffer pointer in a BPF hash map keyed by `(pid << 32) | tid`. Upon function exit, the return probe reads the actual returned byte length and streams the buffer into the BPF ring buffer.

---

## 📊 Benchmarks

Micro-benchmarks conducted on Linux x86_64 using `criterion.rs`:

| Component | Benchmark Scenario | Average Latency | Throughput |
| :--- | :--- | :--- | :--- |
| **HTTP/1.1 Parser** | Chunked Transfer Reassembly | **~142 ns** | ~7,000,000 req/s |
| **HPACK Engine** | Static Table Lookup (61 entries) | **~28 ns** | ~35,000,000 headers/s |
| **HTTP/2 Engine** | 9-byte Frame Dissection + Payload | **~85 ns** | ~11,700,000 frames/s |
| **Stream Reassembler** | Multi-packet Fragmentation | **~210 ns** | ~4,700,000 packets/s |

Run benchmarks locally:
```bash
cargo bench
```

---

## 🛡 Security & Responsible Disclosure

`nullca` is developed for authorized security research, application debugging, security engineering, and performance auditing on systems you own or have explicit written permission to inspect.

Attaching probes to arbitrary system processes requires `CAP_SYS_ADMIN` or root privileges on Linux. Do not use this tool on systems where you lack authorization.

---

## 📄 License

Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
