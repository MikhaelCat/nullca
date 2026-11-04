use clap::{CommandFactory, Parser, Subcommand};
use colored::*;
use nullca::bpf::loader::BpfLoader;
use nullca::engine::audit::SecurityAuditor;
use nullca::engine::diff::DiffEngine;
use nullca::engine::discover::ProcessScanner;
use nullca::engine::filter::FilterEngine;
use nullca::engine::golang::GoSymbolTable;
use nullca::engine::ipc::{IpcClient, IpcServer, DEFAULT_SOCKET_PATH};
use nullca::engine::replay::{ReplayEngine, ReplayRequest};
use nullca::engine::spawn::ProcessLauncher;
use nullca::engine::symbols::ElfBinary;
use nullca::export::har::HarExporter;
use nullca::export::openapi::OpenApiGenerator;
use nullca::export::pcapng::PcapNgWriter;
use nullca::export::sslkeylog::SslKeyLogWriter;
use nullca::export::terminal::TerminalFormatter;
use nullca::proto::secrets::scan_secrets;
use nullca::ui::dashboard::{run_dashboard, run_dashboard_with_drops};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(
    name = "nullca",
    author = "Mikhael (MikhaelCat)",
    version = "0.1.0",
    about = "⚡ Zero-CA eBPF Plaintext TLS, HTTP/2, WebSocket & gRPC Sniffer in Pure Rust",
    long_about = "NullCA dynamically attaches eBPF uprobes to OpenSSL, BoringSSL, Go and Rust runtimes.\nIt captures unencrypted application data without modifying CA bundles, proxies, or breaking Certificate Pinning."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List active system processes linked with detectable TLS runtimes
    #[command(alias = "ps")]
    List,

    /// Trace decrypted TLS traffic of a running process in real-time
    Trace {
        /// Target Process ID (PID)
        #[arg(short, long)]
        pid: Option<u32>,

        /// Filter by process executable name
        #[arg(short, long)]
        name: Option<String>,

        /// Launch interactive terminal cockpit dashboard (TUI)
        #[arg(short, long)]
        ui: bool,

        /// Pre-configured query filter DSL (e.g. 'proto == "http2" && status >= 400')
        #[arg(short, long)]
        filter: Option<String>,

        /// Export decrypted sessions to Wireshark PCAP-NG file
        #[arg(long)]
        pcap: Option<PathBuf>,

        /// Export decrypted HTTP sessions to HTTP Archive (HAR 1.2) JSON
        #[arg(long)]
        har: Option<PathBuf>,

        /// Output events as raw structured JSON lines
        #[arg(long)]
        json: bool,

        /// Display raw byte hexdump alongside decoded messages
        #[arg(long)]
        hexdump: bool,

        /// Broadcast live decrypted events to a UNIX domain socket
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Emulate live TLS traffic with synthetic frames for testing
        #[arg(long)]
        emulate: bool,
    },

    /// Spawn a target command and immediately trace its decrypted TLS activity
    Run {
        /// Launch interactive terminal cockpit dashboard (TUI)
        #[arg(short, long)]
        ui: bool,

        /// Export decrypted sessions to Wireshark PCAP-NG file
        #[arg(long)]
        pcap: Option<PathBuf>,

        /// Export decrypted HTTP sessions to HAR 1.2 format
        #[arg(long)]
        har: Option<PathBuf>,

        /// Broadcast live decrypted events to a UNIX domain socket
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Emulate live TLS traffic for testing
        #[arg(long)]
        emulate: bool,

        /// Target command line to execute (e.g. -- curl -s https://api.github.com)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Stream live decrypted events from a background NullCA daemon socket
    Stream {
        /// Path to NullCA IPC socket (defaults to /tmp/nullca.sock)
        #[arg(short, long, default_value = DEFAULT_SOCKET_PATH)]
        socket: PathBuf,

        /// Pre-configured query filter DSL
        #[arg(short, long)]
        filter: Option<String>,

        /// Output events as raw structured JSON lines
        #[arg(long)]
        json: bool,

        /// Display raw byte hexdump alongside decoded messages
        #[arg(long)]
        hexdump: bool,
    },

    /// Replay and tamper an HTTP request against a target server with microsecond latency metrics
    Replay {
        /// Target host and port (e.g. 127.0.0.1:8080 or example.com:80)
        #[arg(short, long)]
        target: String,

        /// HTTP method (GET, POST, PUT, DELETE, etc.)
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Request URI path
        #[arg(short, long, default_value = "/")]
        path: String,

        /// Custom HTTP header to inject (format: 'Header-Name: Value')
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request body string
        #[arg(short, long)]
        body: Option<String>,

        /// Path to raw HTTP request file
        #[arg(long)]
        raw_file: Option<PathBuf>,
    },

    /// Compare two intercepted packets, payload dumps, or HTTP messages side-by-side
    Diff {
        /// First file path
        file_a: PathBuf,

        /// Second file path
        file_b: PathBuf,
    },

    /// Dissect and inspect an X.509 certificate (PEM or DER binary)
    InspectCert {
        /// Path to certificate file (.pem, .crt, .cer, .der)
        path: PathBuf,
    },

    /// Generate shell autocompletion script (bash, zsh, fish, powershell)
    Completions {
        /// Shell type
        #[arg(short, long)]
        shell: clap_complete::Shell,
    },

    /// Scan a file or dump for leaked JWT tokens, API keys, and CTF flags
    ScanSecrets {
        /// Path to target file
        path: PathBuf,
    },

    /// Inspect dynamic and static symbols of an ELF binary or shared library
    InspectElf {
        /// Path to ELF binary or shared library
        path: PathBuf,

        /// Filter symbol name query
        #[arg(short, long)]
        query: Option<String>,
    },

    /// Dissect Go runtime PCLNTAB (.gopclntab) and ABIInternal conventions in Go binaries
    InspectGo {
        /// Path to Go binary
        path: PathBuf,
    },

    /// Test and validate a Filter DSL expression
    EvalFilter {
        /// Expression string
        query: String,
    },

    /// Compile kernel eBPF C probes to BPF bytecode using clang
    CompileBpf {
        /// Source C file path
        #[arg(short, long, default_value = "src/bpf/tls_uprobe.bpf.c")]
        source: PathBuf,

        /// Output ELF object path
        #[arg(short, long, default_value = "target/tls_uprobe.bpf.o")]
        output: PathBuf,
    },

    /// Synthesize an OpenAPI 3.0 specification from captured HTTP HAR logs or traffic
    ExportOpenapi {
        /// Input HAR file path (.har)
        #[arg(short, long)]
        har: PathBuf,

        /// Output path for OpenAPI specification (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// API specification title
        #[arg(short, long, default_value = "Intercepted API Specification")]
        title: String,

        /// API specification version
        #[arg(short, long, default_value = "1.0.0")]
        version: String,
    },

    /// Run passive security posture, header hygiene, and secret leak audit on captured traffic
    Audit {
        /// Input HAR file path (.har)
        #[arg(short, long)]
        har: PathBuf,

        /// Output findings as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Export TLS session secrets in standard NSS SSLKEYLOGFILE format for Wireshark
    ExportSslkeylog {
        /// Output SSLKEYLOGFILE path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Launch embedded Web Cockpit dashboard and REST API daemon
    Web {
        /// Port to bind Web Cockpit HTTP server
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },

    /// Active parameter fuzzing and mutation testing against target endpoint
    Fuzz {
        /// Target host and port (e.g. 127.0.0.1:8080 or example.com:80)
        #[arg(short, long)]
        target: String,

        /// HTTP method (GET, POST, PUT, DELETE, etc.)
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Request URI path with query string (e.g. /api/user?id=1)
        #[arg(short, long, default_value = "/")]
        path: String,

        /// Parameter name to mutate
        #[arg(short = 'P', long)]
        param: String,

        /// Custom wordlist file path (one payload per line)
        #[arg(short, long)]
        wordlist: Option<PathBuf>,

        /// Output results as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Export captured HTTP HAR logs or traffic to Postman Collection v2.1.0 JSON
    ExportPostman {
        /// Input HAR file path (.har)
        #[arg(short, long)]
        har: PathBuf,

        /// Output path for Postman Collection JSON
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Collection title name
        #[arg(short, long, default_value = "nullca Captured API Collection")]
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            println!(
                "{}",
                "=== NullCA Active TLS Process Scanner ===".bold().cyan()
            );
            let targets = ProcessScanner::list_active_targets()?;

            if targets.is_empty() {
                println!(
                    "{}",
                    "No active processes linked with OpenSSL/Go TLS detected.".yellow()
                );
                return Ok(());
            }

            println!(
                "{:<8} {:<20} {:<15} {}",
                "PID".bold(),
                "NAME".bold(),
                "FLAVOR".bold(),
                "LIBRARY / BINARY PATH".bold()
            );
            println!("{}", "─".repeat(80).dimmed());

            for t in targets {
                for lib in &t.tls_libraries {
                    println!(
                        "{:<8} {:<20} {:<15?} {}",
                        t.pid.to_string().yellow(),
                        t.name.green(),
                        lib.flavor,
                        lib.path.display().to_string().dimmed()
                    );
                }
            }
        }

        Commands::Stream {
            socket,
            filter,
            json,
            hexdump,
        } => {
            println!(
                "{} Connecting to NullCA streaming socket: {}",
                "[*]".bold().blue(),
                socket.display().to_string().cyan()
            );
            let filter_engine = if let Some(ref f) = filter {
                Some(FilterEngine::compile(f)?)
            } else {
                None
            };
            IpcClient::stream(socket, filter_engine, json, hexdump).await?;
        }

        Commands::Replay {
            target,
            method,
            path,
            headers,
            body,
            raw_file,
        } => {
            println!(
                "{} Preparing request replay to target: {}",
                "[*]".bold().blue(),
                target.cyan()
            );

            let (host, port) = if let Some((h, p)) = target.split_once(':') {
                let parsed_p = p.parse::<u16>().unwrap_or(80);
                (h.to_string(), parsed_p)
            } else {
                (target.clone(), 80)
            };

            let req = if let Some(raw_path) = raw_file {
                let bytes = std::fs::read(&raw_path)?;
                ReplayRequest::from_raw(host.clone(), port, &bytes).ok_or_else(|| {
                    anyhow::anyhow!("Failed to parse raw HTTP request from {:?}", raw_path)
                })?
            } else {
                let mut header_map = HashMap::new();
                for h in headers {
                    if let Some((k, v)) = h.split_once(':') {
                        header_map.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
                ReplayRequest {
                    host: host.clone(),
                    port,
                    use_tls: port == 443,
                    method,
                    path,
                    headers: header_map,
                    body: body.unwrap_or_default().into_bytes(),
                }
            };

            println!(
                "{} Transmitting: {} {} (Host: {}:{})",
                "[+]".bold().green(),
                req.method.yellow().bold(),
                req.path.cyan(),
                req.host,
                req.port
            );

            match ReplayEngine::execute(&req).await {
                Ok(resp) => {
                    let status_color = if resp.status_code < 300 {
                        format!("{}", resp.status_code).green().bold()
                    } else if resp.status_code < 400 {
                        format!("{}", resp.status_code).blue().bold()
                    } else if resp.status_code < 500 {
                        format!("{}", resp.status_code).yellow().bold()
                    } else {
                        format!("{}", resp.status_code).red().bold()
                    };

                    println!("\n=== Replay Response ===");
                    println!("Status: {}", status_color);
                    println!(
                        "Timing: Connect: {:.2}ms | TTFB: {:.2}ms | Total: {:.2}ms",
                        resp.metrics.connect_latency_ms,
                        resp.metrics.ttfb_ms,
                        resp.metrics.total_duration_ms
                    );
                    println!("\n--- Headers ---");
                    for (k, v) in &resp.headers {
                        println!("{}: {}", k.cyan(), v);
                    }
                    println!("\n--- Body ({} bytes) ---", resp.body.len());
                    if let Ok(json_v) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                        if let Ok(pretty) = serde_json::to_string_pretty(&json_v) {
                            println!("{}", pretty);
                        } else {
                            println!("{}", String::from_utf8_lossy(&resp.body));
                        }
                    } else {
                        println!("{}", String::from_utf8_lossy(&resp.body));
                    }
                }
                Err(e) => {
                    eprintln!("{} Replay error: {}", "[-]".bold().red(), e);
                }
            }
        }

        Commands::Fuzz {
            target,
            method,
            path,
            param,
            wordlist,
            json,
        } => {
            let (host, port) = if let Some((h, p)) = target.split_once(':') {
                let parsed_p = p.parse::<u16>().unwrap_or(80);
                (h.to_string(), parsed_p)
            } else {
                (target.clone(), 80)
            };

            let base_req = ReplayRequest::new(host, port, method.to_uppercase(), path);

            let mut payloads: Vec<nullca::engine::fuzz::FuzzPayload> = Vec::new();
            if let Some(wpath) = wordlist {
                let content = std::fs::read_to_string(&wpath)?;
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        payloads.push(nullca::engine::fuzz::FuzzPayload::Custom(
                            trimmed.to_string(),
                        ));
                    }
                }
            } else {
                payloads.extend_from_slice(nullca::engine::fuzz::DEFAULT_FUZZ_DICTIONARY);
            }

            if !json {
                println!(
                    "{}",
                    "=== NullCA High-Throughput Request Fuzzing Engine ==="
                        .bold()
                        .cyan()
                );
                println!(
                    "Target:    {}:{}",
                    base_req.host.green(),
                    base_req.port.to_string().yellow()
                );
                println!("Parameter: {}", param.bold().yellow());
                println!(
                    "Payloads:  {} mutations queued\n",
                    payloads.len().to_string().cyan()
                );
                println!(
                    "{:<30} {:<10} {:<12} {:<12} {}",
                    "PAYLOAD".bold(),
                    "STATUS".bold(),
                    "BODY LEN".bold(),
                    "LATENCY".bold(),
                    "ANOMALY".bold()
                );
                println!("{}", "─".repeat(80).dimmed());
            }

            let results =
                nullca::engine::fuzz::FuzzEngine::fuzz_parameter(&base_req, &param, &payloads)
                    .await?;

            if json {
                #[derive(serde::Serialize)]
                struct JsonFuzzOutput {
                    payload: String,
                    status_code: u16,
                    body_len: usize,
                    duration_ms: f64,
                    is_anomaly: bool,
                }
                let json_res: Vec<JsonFuzzOutput> = results
                    .into_iter()
                    .map(|r| JsonFuzzOutput {
                        payload: r.payload,
                        status_code: r.status_code,
                        body_len: r.body_len,
                        duration_ms: r.duration_ms,
                        is_anomaly: r.is_anomaly,
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_res)?);
            } else {
                for r in results {
                    let status_colored = if r.status_code >= 500 {
                        r.status_code.to_string().red().bold()
                    } else if r.status_code >= 400 {
                        r.status_code.to_string().yellow()
                    } else {
                        r.status_code.to_string().green()
                    };

                    let anomaly_badge = if r.is_anomaly {
                        "🚨 ANOMALY".red().bold()
                    } else {
                        "-".dimmed()
                    };

                    let truncated_payload = if r.payload.len() > 28 {
                        format!("{}...", &r.payload[..25])
                    } else {
                        r.payload
                    };

                    println!(
                        "{:<30} {:<10} {:<12} {:<12.1} {}",
                        truncated_payload,
                        status_colored,
                        format!("{} B", r.body_len),
                        format!("{:.1}ms", r.duration_ms),
                        anomaly_badge
                    );
                }
            }
        }

        Commands::Diff { file_a, file_b } => {
            let str_a = std::fs::read_to_string(&file_a)?;
            let str_b = std::fs::read_to_string(&file_b)?;

            let diffs = DiffEngine::diff_text(&str_a, &str_b);
            println!(
                "{}",
                format!("=== Diff: {} vs {} ===", file_a.display(), file_b.display())
                    .bold()
                    .cyan()
            );

            for d in diffs {
                match d.kind {
                    nullca::engine::diff::DiffKind::Added => {
                        println!("{}", format!("+ {}", d.content).green());
                    }
                    nullca::engine::diff::DiffKind::Removed => {
                        println!("{}", format!("- {}", d.content).red());
                    }
                    nullca::engine::diff::DiffKind::Equal => {
                        println!("{}", format!("  {}", d.content).dimmed());
                    }
                    _ => {}
                }
            }
        }

        Commands::InspectCert { path } => {
            if path.is_dir() {
                println!(
                    "{} Scanning certificate directory: {}",
                    "[*]".bold().blue(),
                    path.display().to_string().cyan()
                );
                let summary = nullca::proto::x509::X509Parser::scan_directory(&path)?;

                println!(
                    "\n{}",
                    "=== X.509 Cryptographic Inventory Summary ==="
                        .bold()
                        .cyan()
                );
                println!("{:<28} {}", "Directory Scanned:".bold(), path.display());
                println!(
                    "{:<28} {}",
                    "Files Scanned:".bold(),
                    summary.total_files_scanned
                );
                println!(
                    "{:<28} {} (errors: {})",
                    "Certificates Parsed:".bold(),
                    summary.total_certs_parsed.to_string().green().bold(),
                    summary.parse_errors
                );
                println!(
                    "{:<28} {} CAs / {} End-Entities",
                    "Certificate Roles:".bold(),
                    summary.ca_count.to_string().yellow(),
                    summary.leaf_count
                );
                println!(
                    "{:<28} {} Valid / {} Expired",
                    "Validity Status:".bold(),
                    summary.valid_count.to_string().green(),
                    summary.expired_count.to_string().red()
                );

                println!("\n{}", "[Public Key Algorithms]".bold().yellow());
                for (algo, count) in &summary.algorithm_counts {
                    let pct = (*count as f64 / summary.total_certs_parsed as f64) * 100.0;
                    println!(
                        "  • {:<36} {:>4} ({:.1}%)",
                        algo.cyan(),
                        count.to_string().bold(),
                        pct
                    );
                }

                println!("\n{}", "[Signature Suites]".bold().yellow());
                for (sig, count) in &summary.signature_counts {
                    println!("  • {:<36} {:>4}", sig, count);
                }

                if summary.expired_count > 0 {
                    println!("\n{}", "[Expired Certificates]".bold().red());
                    for cert in summary
                        .certificates
                        .iter()
                        .filter(|c| c.validity_status.starts_with("EXPIRED"))
                    {
                        println!(
                            "  ⚠️  {:<30} Status: {}",
                            cert.subject_cn.as_deref().unwrap_or("Unknown").yellow(),
                            cert.validity_status.red()
                        );
                    }
                }
            } else if path.is_file() {
                println!(
                    "{} Inspecting file: {}",
                    "[*]".bold().blue(),
                    path.display().to_string().cyan()
                );
                let bytes = std::fs::read(&path)?;

                // Check for Certificate Revocation List (CRL)
                if let Some(crl) = nullca::proto::x509::X509Parser::parse_crl(&bytes) {
                    println!(
                        "\n{}",
                        "=== X.509 Certificate Revocation List (CRL) ==="
                            .bold()
                            .magenta()
                    );
                    println!("{:<26} {}", "Version:".bold(), crl.version);
                    println!("{:<26} {}", "Issuer DN:".bold(), crl.issuer_dn.yellow());
                    println!(
                        "{:<26} {}",
                        "Signature Algorithm:".bold(),
                        crl.signature_algorithm
                    );
                    println!(
                        "{:<26} {}",
                        "This Update:".bold(),
                        crl.this_update.as_deref().unwrap_or("?")
                    );
                    println!(
                        "{:<26} {}",
                        "Next Update:".bold(),
                        crl.next_update.as_deref().unwrap_or("None")
                    );
                    if let Some(ref num) = crl.crl_number {
                        println!("{:<26} {}", "CRL Number:".bold(), num);
                    }
                    println!(
                        "{:<26} {}",
                        "Revoked Certificates:".bold(),
                        crl.revoked_count.to_string().red().bold()
                    );

                    if !crl.revoked_certificates.is_empty() {
                        println!(
                            "\n{:<20} {:<24} {}",
                            "Serial Number".bold(),
                            "Revocation Date".bold(),
                            "Reason".bold()
                        );
                        println!("{}", "─".repeat(65).dimmed());
                        for r in &crl.revoked_certificates {
                            println!(
                                "{:<20} {:<24} {}",
                                r.serial_hex.red(),
                                r.revocation_date,
                                r.reason.as_deref().unwrap_or("Unspecified").dimmed()
                            );
                        }
                    }
                    return Ok(());
                }

                // Check for Certificate Signing Request (CSR / PKCS#10)
                let text_sample = String::from_utf8_lossy(&bytes[..bytes.len().min(128)]);
                if text_sample.contains("CERTIFICATE REQUEST") {
                    if let Some(csr) = nullca::proto::x509::X509Parser::parse_csr(&bytes) {
                        println!(
                            "\n{}",
                            "=== X.509 Certificate Signing Request (CSR / PKCS#10) ==="
                                .bold()
                                .cyan()
                        );
                        println!("{:<26} {}", "Version:".bold(), csr.version);
                        println!(
                            "{:<26} {}",
                            "Subject DN:".bold(),
                            csr.subject_dn.green().bold()
                        );
                        if let Some(ref cn) = csr.subject_cn {
                            println!("{:<26} {}", "  Common Name (CN):".dimmed(), cn);
                        }
                        if let Some(ref org) = csr.subject_org {
                            println!("{:<26} {}", "  Organization (O):".dimmed(), org);
                        }
                        println!(
                            "{:<26} {}",
                            "Public Key Algorithm:".bold(),
                            csr.public_key_algorithm.cyan().bold()
                        );
                        println!(
                            "{:<26} {}",
                            "Signature Algorithm:".bold(),
                            csr.signature_algorithm
                        );

                        if !csr.requested_san_names.is_empty() {
                            println!(
                                "\nRequested SAN Extensions ({} SANs):",
                                csr.requested_san_names.len()
                            );
                            for san in &csr.requested_san_names {
                                println!("  • {}", san.cyan());
                            }
                        }
                        return Ok(());
                    }
                }

                // Standard X.509 Certificates / Chains / Bundles
                let certs = nullca::proto::x509::X509Parser::parse_all(&bytes);
                if certs.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Failed to parse valid X.509 ASN.1 DER/PEM certificate from {:?}",
                        path
                    ));
                }

                print_certificate_chain(&certs);
            } else {
                let target_str = path.to_string_lossy().to_string();
                if target_str.contains('.') || target_str.contains(':') {
                    println!(
                        "{} Resolving & connecting to live TLS target: {}",
                        "[*]".bold().blue(),
                        target_str.cyan().bold()
                    );
                    let certs =
                        nullca::proto::x509::X509Parser::fetch_remote_certificates(&target_str)?;
                    println!(
                        "{} Retrieved {} live certificate(s) in peer chain",
                        "[+]".bold().green(),
                        certs.len().to_string().bold()
                    );
                    print_certificate_chain(&certs);
                } else {
                    return Err(anyhow::anyhow!(
                        "File or remote target not found: {:?}",
                        path
                    ));
                }
            }
        }

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "nullca", &mut std::io::stdout());
        }

        Commands::ScanSecrets { path } => {
            println!(
                "{} Scanning for secrets in: {}",
                "[*]".bold().blue(),
                path.display().to_string().cyan()
            );
            let bytes = std::fs::read(&path)?;
            let secrets = scan_secrets(&bytes);

            if secrets.is_empty() {
                println!("{}", "No sensitive tokens or credentials detected.".green());
                return Ok(());
            }

            println!(
                "\n{} Detected {} sensitive token(s):",
                "[!]".bold().red(),
                secrets.len()
            );
            for (i, sec) in secrets.iter().enumerate() {
                println!(
                    "\n[{}] {} ({})",
                    i + 1,
                    format!("{:?}", sec.kind).bold().yellow(),
                    sec.location.dimmed()
                );
                println!("  Raw Token: {}", sec.raw_token.cyan());
                if let Some(ref details) = sec.decoded_details {
                    for line in details.lines() {
                        println!("    {}", line.dimmed());
                    }
                }
            }
        }

        Commands::Run {
            ui,
            pcap,
            har,
            socket,
            emulate,
            command,
        } => {
            println!(
                "{} Spawning and tracing command: {}",
                "[+]".bold().green(),
                command.join(" ").cyan()
            );

            let (tx, rx) = mpsc::channel(256);
            let cmd_clone = command.clone();

            tokio::spawn(async move {
                if let Err(e) = ProcessLauncher::run_and_trace(&cmd_clone, tx, emulate).await {
                    eprintln!("Error tracing spawned process: {}", e);
                }
            });

            let ipc_server = if let Some(ref s_path) = socket {
                println!(
                    "{} Starting IPC broadcast socket at: {}",
                    "[+]".bold().green(),
                    s_path.display().to_string().cyan()
                );
                Some(IpcServer::start(s_path)?)
            } else {
                None
            };

            if ui {
                run_dashboard(rx, ipc_server)
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                return Ok(());
            }

            let mut pcap_writer = if let Some(pcap_path) = pcap {
                Some(PcapNgWriter::create(pcap_path)?)
            } else {
                None
            };

            let mut captured_events = Vec::new();
            let mut formatter = TerminalFormatter::new(false);
            let mut rx = rx;

            while let Some(event) = rx.recv().await {
                if let Some(ref mut pw) = pcap_writer {
                    let _ = pw.write_event(&event);
                }
                if let Some(ref srv) = ipc_server {
                    srv.broadcast(&event);
                }
                let formatted = formatter.format_event(&event);
                print!("{}", formatted);

                if har.is_some() {
                    captured_events.push(event);
                }
            }

            if let Some(har_path) = har {
                let _ = HarExporter::write_to_file(&captured_events, har_path);
            }
        }

        Commands::InspectElf { path, query } => {
            println!(
                "{} Parsing ELF binary: {}",
                "[*]".bold().blue(),
                path.display().to_string().cyan()
            );
            let elf = ElfBinary::parse(&path)?;

            let symbols = elf.symbols();
            println!(
                "{} Total symbols indexed: {}",
                "[+]".bold().green(),
                symbols.len()
            );

            let filtered: Vec<_> = if let Some(ref q) = query {
                symbols.iter().filter(|s| s.name.contains(q)).collect()
            } else {
                symbols.iter().take(25).collect()
            };

            println!(
                "\n{:<18} {:<10} {:<10} {}",
                "OFFSET".bold(),
                "SIZE".bold(),
                "TYPE".bold(),
                "SYMBOL NAME".bold()
            );
            println!("{}", "─".repeat(70).dimmed());
            for sym in filtered {
                let kind = if sym.is_function { "FUNC" } else { "OBJECT" };
                println!(
                    "0x{:<16x} {:<10} {:<10} {}",
                    sym.address,
                    sym.size,
                    kind,
                    sym.name.cyan()
                );
            }
        }

        Commands::InspectGo { path } => {
            println!(
                "{} Dissecting Go Runtime pclntab: {}",
                "[*]".bold().blue(),
                path.display().to_string().cyan()
            );
            let bytes = std::fs::read(&path)?;
            let go_symbols = GoSymbolTable::parse(&bytes)?;

            let version_str = match go_symbols.magic {
                nullca::engine::golang::GO_PCLNTAB_MAGIC_116 => "Go 1.16",
                nullca::engine::golang::GO_PCLNTAB_MAGIC_118 => "Go 1.18 - 1.19",
                nullca::engine::golang::GO_PCLNTAB_MAGIC_120 => "Go 1.20+",
                _ => "Go Runtime (Custom)",
            };

            println!(
                "{} Detected Go Runtime Format: {} (pointer size: {} bytes)",
                "[+]".bold().green(),
                version_str,
                go_symbols.ptr_size
            );
            println!(
                "{} Indexed {} Go functions from .gopclntab",
                "[+]".bold().green(),
                go_symbols.functions.len()
            );

            println!("\nTarget Go Crypto/TLS Entrypoints:");
            println!("{}", "─".repeat(60).dimmed());
            for target in ["crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).Write"] {
                if let Some(func) = go_symbols.functions.get(target) {
                    println!(
                        "  {:<32} Entry: 0x{:x}",
                        func.name.green().bold(),
                        func.entry_pc
                    );
                } else {
                    println!(
                        "  {:<32} {}",
                        target.yellow(),
                        "Not linked or stripped".dimmed()
                    );
                }
            }
        }

        Commands::EvalFilter { query } => {
            println!(
                "{} Parsing Filter DSL Query: {}",
                "[*]".bold().blue(),
                query.cyan()
            );
            match FilterEngine::compile(&query) {
                Ok(engine) => {
                    println!("{}", "[+] Compilation successful!".bold().green());
                    println!("AST: {:?}", engine);
                }
                Err(e) => {
                    eprintln!("{} Filter syntax error: {}", "[-]".bold().red(), e);
                }
            }
        }

        Commands::CompileBpf { source, output } => {
            println!(
                "{} Compiling kernel eBPF C probes: {} -> {}",
                "[*]".bold().blue(),
                source.display().to_string().yellow(),
                output.display().to_string().cyan()
            );

            if !BpfLoader::has_clang_installed() {
                eprintln!(
                    "{}",
                    "[-] clang compiler not found on PATH. Install clang 12+."
                        .bold()
                        .red()
                );
                return Ok(());
            }

            BpfLoader::compile_bpf_program(&source, &output)?;
            println!(
                "{}",
                "[+] eBPF bytecode compilation successful!".bold().green()
            );
        }

        Commands::ExportOpenapi {
            har,
            output,
            title,
            version,
        } => {
            println!(
                "{} Loading HAR capture: {}",
                "[*]".bold().blue(),
                har.display().to_string().cyan()
            );
            let file = std::fs::File::open(&har)?;
            let har_data: nullca::export::har::HarRoot = serde_json::from_reader(file)?;

            let generator = OpenApiGenerator::new();
            let spec = generator.generate_from_har_entries(&har_data.log.entries, &title, &version);
            let json_str = generator.to_json_string(&spec)?;

            if let Some(out_path) = output {
                std::fs::write(&out_path, &json_str)?;
                println!(
                    "{} OpenAPI 3.0 specification successfully saved to: {}",
                    "[+]".bold().green(),
                    out_path.display().to_string().cyan().bold()
                );
            } else {
                println!("{}", json_str);
            }
        }

        Commands::ExportPostman { har, output, name } => {
            println!(
                "{} Loading HAR capture: {}",
                "[*]".bold().blue(),
                har.display().to_string().cyan()
            );
            let har_content = std::fs::read_to_string(&har)?;
            let col =
                nullca::export::postman::PostmanExporter::from_har_str(&har_content, Some(&name))
                    .map_err(|e| anyhow::anyhow!("Failed to parse HAR: {}", e))?;

            let json_str = serde_json::to_string_pretty(&col)?;

            if let Some(out_path) = output {
                std::fs::write(&out_path, &json_str)?;
                println!(
                    "{} Postman v2.1.0 collection successfully saved to: {} ({} requests)",
                    "[+]".bold().green(),
                    out_path.display().to_string().cyan().bold(),
                    col.item.len()
                );
            } else {
                println!("{}", json_str);
            }
        }

        Commands::Audit { har, json } => {
            let file = std::fs::File::open(&har)?;
            let har_data: nullca::export::har::HarRoot = serde_json::from_reader(file)?;

            let auditor = SecurityAuditor::new();
            let report = auditor.audit_har_entries(&har_data.log.entries);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                auditor.print_report(&report);
            }
        }

        Commands::ExportSslkeylog { output } => {
            println!(
                "{} Initializing NSS SSLKEYLOGFILE writer at: {}",
                "[*]".bold().blue(),
                output.display().to_string().cyan()
            );
            let _writer = SslKeyLogWriter::open_append(&output)?;
            println!(
                "{} SSLKEYLOGFILE writer ready. Point Wireshark to this file: Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename",
                "[+]".bold().green()
            );
        }

        Commands::Web { port } => {
            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let (tx, mut rx) = mpsc::channel(256);
            let loader = BpfLoader::new(None);
            let emul = !BpfLoader::has_bpf_capabilities();

            tokio::spawn(async move {
                let _ = loader.run_event_loop(None, tx, emul).await;
            });

            let ev_clone = std::sync::Arc::clone(&events);
            tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    let mut lock = ev_clone.lock().unwrap();
                    lock.push(ev);
                    if lock.len() > 1000 {
                        lock.remove(0);
                    }
                }
            });

            nullca::ui::web::WebServer::start(port, events).await?;
        }

        Commands::Trace {
            pid,
            name: _name,
            ui,
            filter,
            pcap,
            har,
            json,
            hexdump,
            socket,
            emulate,
        } => {
            let filter_engine = if let Some(ref f) = filter {
                Some(FilterEngine::compile(f)?)
            } else {
                None
            };

            let (tx, mut rx) = mpsc::channel(256);
            let loader = BpfLoader::new(pid);
            let drop_counter = loader.drop_counter();

            let emul = emulate || !BpfLoader::has_bpf_capabilities();

            tokio::spawn(async move {
                if let Err(e) = loader.run_event_loop(None, tx, emul).await {
                    eprintln!("Error in event loop: {}", e);
                }
            });

            let ipc_server = if let Some(ref s_path) = socket {
                println!(
                    "{} Starting IPC broadcast socket at: {}",
                    "[+]".bold().green(),
                    s_path.display().to_string().cyan()
                );
                Some(IpcServer::start(s_path)?)
            } else {
                None
            };

            if ui {
                run_dashboard_with_drops(rx, ipc_server, Some(drop_counter))
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                return Ok(());
            }

            println!(
                "{}",
                r#"
  ███╗   ██╗██╗   ██╗██╗     ██╗      ██████╗ █████╗ 
  ████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔══██╗
  ██╔██╗ ██║██║   ██║██║     ██║     ██║     ███████║
  ██║╚██╗██║██║   ██║██║     ██║     ██║     ██╔══██║
  ██║ ╚████║╚██████╔╝███████╗███████╗╚██████╗██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝
  Zero-CA eBPF Plaintext TLS, HTTP/2 & WebSocket Interceptor
                "#
                .bold()
                .cyan()
            );

            let mut pcap_writer = if let Some(pcap_path) = pcap {
                println!(
                    "{} Writing decrypted capture to: {}",
                    "[+]".bold().green(),
                    pcap_path.display().to_string().yellow()
                );
                Some(PcapNgWriter::create(pcap_path)?)
            } else {
                None
            };

            let mut captured_events = Vec::new();
            let mut formatter = TerminalFormatter::new(hexdump);
            println!(
                "{} Listening for decrypted TLS events...\n",
                "[*]".bold().blue()
            );

            while let Some(event) = rx.recv().await {
                if let Some(ref f_engine) = filter_engine {
                    if !f_engine.matches(&event) {
                        continue;
                    }
                }

                if let Some(ref mut pw) = pcap_writer {
                    let _ = pw.write_event(&event);
                }

                if let Some(ref srv) = ipc_server {
                    srv.broadcast(&event);
                }

                if json {
                    if let Ok(serialized) = serde_json::to_string(&event) {
                        println!("{}", serialized);
                    }
                } else {
                    let formatted = formatter.format_event(&event);
                    print!("{}", formatted);
                }

                if har.is_some() {
                    captured_events.push(event);
                }
            }

            if let Some(har_path) = har {
                let _ = HarExporter::write_to_file(&captured_events, har_path);
            }
        }
    }

    Ok(())
}

fn print_certificate_chain(certs: &[nullca::proto::x509::X509CertificateInfo]) {
    if certs.len() == 1 {
        let cert = &certs[0];
        println!("\n{}", "=== X.509 Certificate Dissection ===".bold().cyan());
        println!("{:<26} {}", "Version:".bold(), cert.version);
        println!("{:<26} {}", "Serial Number:".bold(), cert.serial_number_hex);
        println!(
            "{:<26} {}",
            "Subject DN:".bold(),
            cert.subject_dn.green().bold()
        );
        if let Some(ref cn) = cert.subject_cn {
            println!("{:<26} {}", "  Common Name (CN):".dimmed(), cn);
        }
        if let Some(ref org) = cert.subject_org {
            println!("{:<26} {}", "  Organization (O):".dimmed(), org);
        }
        if let Some(ref ou) = cert.subject_ou {
            println!("{:<26} {}", "  Organizational Unit (OU):".dimmed(), ou);
        }
        if let Some(ref country) = cert.subject_country {
            println!("{:<26} {}", "  Country (C):".dimmed(), country);
        }

        println!("{:<26} {}", "Issuer DN:".bold(), cert.issuer_dn.yellow());
        println!(
            "{:<26} {}",
            "Public Key Algorithm:".bold(),
            cert.public_key_algorithm.cyan().bold()
        );
        println!(
            "{:<26} {}",
            "Signature Algorithm:".bold(),
            cert.signature_algorithm
        );
        println!(
            "{:<26} {} -> {}",
            "Validity Period:".bold(),
            cert.not_before.as_deref().unwrap_or("?"),
            cert.not_after.as_deref().unwrap_or("?")
        );
        let status_colored = if cert.validity_status.starts_with("EXPIRED") {
            cert.validity_status.red().bold()
        } else {
            cert.validity_status.green().bold()
        };
        println!("{:<26} {}", "Validity Status:".bold(), status_colored);
        println!(
            "{:<26} {}",
            "Basic Constraints:".bold(),
            if cert.is_ca {
                format!("CA: TRUE (PathLen: {:?})", cert.path_length_constraint)
                    .yellow()
                    .bold()
            } else {
                "End-Entity (Leaf)".normal()
            }
        );

        if !cert.key_usage.is_empty() {
            println!("{:<26} {}", "Key Usage:".bold(), cert.key_usage.join(", "));
        }
        if !cert.extended_key_usage.is_empty() {
            println!(
                "{:<26} {}",
                "Extended Key Usage:".bold(),
                cert.extended_key_usage.join(", ")
            );
        }

        if !cert.subject_alt_names.is_empty() {
            println!(
                "\nSubject Alternative Names ({} SANs):",
                cert.subject_alt_names.len()
            );
            println!("{}", "─".repeat(50).dimmed());
            for san in &cert.subject_alt_names {
                println!("  • {}", san.cyan());
            }
        }

        if !cert.ocsp_urls.is_empty() {
            println!("\nOCSP Responder URLs:");
            for url in &cert.ocsp_urls {
                println!("  • {}", url.dimmed());
            }
        }

        if !cert.crl_distribution_points.is_empty() {
            println!("\nCRL Distribution Points:");
            for url in &cert.crl_distribution_points {
                println!("  • {}", url.dimmed());
            }
        }

        if let Some(ref ski) = cert.subject_key_id {
            println!("{:<26} {}", "Subject Key ID (SKI):".bold(), ski);
        }
        if let Some(ref aki) = cert.authority_key_id {
            println!("{:<26} {}", "Authority Key ID (AKI):".bold(), aki);
        }

        println!("\n{}", "[Cryptographic Fingerprints]".bold().yellow());
        println!(
            "{:<26} {}",
            "SHA-256 Fingerprint:".bold(),
            cert.fingerprint_sha256.cyan().bold()
        );
        println!(
            "{:<26} {}",
            "SHA-1 Fingerprint:".bold(),
            cert.fingerprint_sha1.dimmed()
        );
    } else {
        println!(
            "\n{}",
            format!(
                "=== X.509 Certificate Chain / Bundle ({} Certificates) ===",
                certs.len()
            )
            .bold()
            .cyan()
        );
        for (i, c) in certs.iter().enumerate() {
            let role = if i == 0 {
                "Leaf / Server Certificate"
            } else if c.is_ca {
                "Intermediate / Root CA"
            } else {
                "Certificate"
            };
            println!(
                "\n{} [{}] {}",
                "──".dimmed(),
                format!("#{} {}", i + 1, role).bold().yellow(),
                "──────────────────────────────────────────────".dimmed()
            );
            println!("{:<24} {}", "Subject:".bold(), c.subject_dn.green().bold());
            println!("{:<24} {}", "Issuer:".bold(), c.issuer_dn.yellow());
            println!(
                "{:<24} {}",
                "Key Algorithm:".bold(),
                c.public_key_algorithm.cyan().bold()
            );
            println!(
                "{:<24} {}",
                "Signature Suite:".bold(),
                c.signature_algorithm
            );
            println!(
                "{:<24} {} -> {}",
                "Validity:".bold(),
                c.not_before.as_deref().unwrap_or("?"),
                c.not_after.as_deref().unwrap_or("?")
            );
            let status_colored = if c.validity_status.starts_with("EXPIRED") {
                c.validity_status.red().bold()
            } else {
                c.validity_status.green().bold()
            };
            println!("{:<24} {}", "Status:".bold(), status_colored);
            println!(
                "{:<24} {}",
                "SHA-256 Fingerprint:".bold(),
                c.fingerprint_sha256.cyan()
            );
            if !c.subject_alt_names.is_empty() && i == 0 {
                println!(
                    "{:<24} {}",
                    "SANs (DNS):".bold(),
                    c.subject_alt_names.join(", ").dimmed()
                );
            }
        }
    }
}
