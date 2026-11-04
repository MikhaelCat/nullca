# NullCA CLI Reference Manual

NullCA provides an extensive suite of CLI subcommands for network observability, traffic analysis, certificate dissection, and automated auditing.

---

## Command Overview

```
nullca <COMMAND> [OPTIONS]
```

| Subcommand | Alias | Description |
|---|---|---|
| `list` | `ps` | List running processes linked with OpenSSL, BoringSSL, rustls, or Go TLS |
| `trace` | | Trace decrypted TLS traffic of a running process in real-time |
| `run` | | Spawn a target command and immediately trace its decrypted TLS activity |
| `stream` | | Stream live decrypted events from a background NullCA daemon socket |
| `inspect-cert` | | Dissect X.509 certificates (PEM, DER, bundles, directories, CSR, CRL, remote endpoints) |
| `export-openapi` | | Synthesize an OpenAPI 3.0 specification from captured HTTP HAR logs |
| `audit` | | Run passive security posture, header hygiene, and secret leak audit |
| `export-sslkeylog` | | Export TLS session secrets in standard NSS SSLKEYLOGFILE format for Wireshark |
| `web` | | Launch embedded Web Cockpit dashboard and REST API daemon |
| `fuzz` | | Active parameter fuzzing and boundary mutation testing against target endpoint |
| `replay` | | Replay and tamper an HTTP request against a target server with microsecond latency metrics |
| `diff` | | Compare two intercepted packets, payload dumps, or HTTP messages side-by-side |
| `scan-secrets` | | Scan a file or dump for leaked JWT tokens, API keys, and CTF flags |
| `inspect-elf` | | Inspect dynamic and static symbols of an ELF binary or shared library |
| `inspect-go` | | Dissect Go runtime PCLNTAB (`.gopclntab`) and ABIInternal conventions in Go binaries |
| `eval-filter` | | Test and validate a Filter DSL query expression |
| `compile-bpf` | | Compile kernel eBPF C probes to BPF bytecode using clang |
| `completions` | | Generate shell autocompletion script (bash, zsh, fish, powershell) |

---

## Detailed Subcommand Usage

### 1. `nullca list` (`nullca ps`)
Scans `/proc` to find all active processes linked with OpenSSL, BoringSSL, rustls, or Go `crypto/tls`.
```bash
sudo nullca list
```

### 2. `nullca trace`
Attaches eBPF uprobes to a running process or service.
```bash
# Launch interactive TUI cockpit for target PID
sudo nullca trace --pid 1234 --ui

# Trace by process name, filter for HTTP/2 with status >= 400, export to PCAP-NG and HAR
sudo nullca trace --name nginx --filter 'proto == "http2" && status >= 400' --pcap capture.pcapng --har traffic.har

# Emulate synthetic TLS traffic for testing UI without root privileges
nullca trace --emulate --ui
```

### 3. `nullca run`
Launches a target application and hooks its TLS calls immediately from process creation.
```bash
sudo nullca run --ui -- curl -s https://httpbin.org/get
sudo nullca run --pcap /tmp/api.pcapng -- python3 client.py
```

### 4. `nullca inspect-cert`
Universal X.509 certificate and PKI dissector.
```bash
# Inspect a local PEM certificate
nullca inspect-cert /etc/ssl/certs/ISRG_Root_X1.pem

# Inspect a live remote endpoint without Root CA verification
nullca inspect-cert google.com:443
nullca inspect-cert github.com

# Audit an entire directory of certificates
nullca inspect-cert /etc/ssl/certs

# Inspect a Certificate Revocation List (CRL) or Signing Request (CSR)
nullca inspect-cert revocation_list.crl
nullca inspect-cert request.csr
```

### 5. `nullca export-openapi`
Generates a complete OpenAPI 3.0.3 specification from captured HTTP traffic.
```bash
nullca export-openapi --har traffic.har --output openapi.json --title "Billing Service API" --version "2.1.0"
```

### 6. `nullca audit`
Performs automated security posture and hygiene checks on captured HTTP traffic.
```bash
# Print formatted human-readable report
nullca audit --har traffic.har

# Output as JSON for CI/CD integration
nullca audit --har traffic.har --json > audit_results.json
```

### 7. `nullca export-sslkeylog`
Initializes standard NSS SSLKEYLOGFILE writer for Wireshark live decryption.
```bash
nullca export-sslkeylog --output /tmp/nullca.keys
```

### 8. `nullca web`
Launches the embedded zero-dependency Web Cockpit dashboard and REST API daemon.
```bash
nullca web --port 8080
# Open http://localhost:8080 in any browser or mobile device
```

### 9. `nullca fuzz`
High-throughput parameter mutation and fuzzing engine for identifying server crashes (HTTP 500), input validation errors, and timing anomalies.
```bash
# Fuzz an endpoint parameter using default boundary dictionary
nullca fuzz --target 127.0.0.1:8080 --method GET --path "/api/v1/user?id=1" --param id

# Fuzz with custom wordlist and structured JSON output
nullca fuzz --target api.local:443 --path "/search?q=test" --param q --wordlist /tmp/payloads.txt --json
```

### 10. `nullca replay`
Replays an HTTP request with custom headers or body, measuring sub-millisecond network timings (TTFB, connect latency).
```bash
nullca replay --target 127.0.0.1:8080 --method POST --path /api/v1/login \
  -H "Content-Type: application/json" \
  --body '{"username":"admin"}'
```

### 9. `nullca diff`
Compares two HTTP messages or payloads with color-coded side-by-side diff.
```bash
nullca diff req1.txt req2.txt
```

---

## Interactive Cockpit TUI: Vim Command Mode (`:`) & Live Search (`/`)

When running `nullca trace --ui` or `nullca run --ui`, the interactive cockpit supports Vim-style controls:

| Key / Command | Action |
|---|---|
| `:` | Open Vim Command Line |
| `:w <path>` or `:save <path>` | Save in-memory packet buffer to a HAR 1.2 file |
| `:clear` or `:c` | Clear all captured packets from memory |
| `:filter <dsl>` | Apply Filter DSL expression on the fly |
| `:export <har\|pcap\|openapi> [path]` | Export capture to specified format |
| `:q` or `:quit` | Exit the cockpit |
| `/` | Start live regex / substring search across packet payloads |
| `F` | Open interactive Filter DSL editor |
| `R` or `t` | Open interactive Request Repeater & Tamper Cockpit |
| `f` or `m` | Maximize current focused pane to Fullscreen |
| `s` | Open Quick Export modal dialog |
| `?` or `h` | Toggle Full Help & Keyboard Reference modal |

---

## Filter DSL Syntax

NullCA includes an AST-compiled expression language for filtering packets in real-time:

```sql
proto == "http2" && status >= 400
method == "POST" && uri contains "/api/v1"
len > 1024 && (proto == "grpc" || proto == "ws")
host == "api.github.com" && status != 200
```

Supported operators:
- Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
- String matching: `contains`, `startswith`, `endswith`
- Logical: `&&`, `||`, `!`
- Field identifiers: `proto`, `method`, `uri`, `status`, `len`, `host`, `pid`
