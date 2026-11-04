use clap::{CommandFactory, Parser, Subcommand};
use colored::*;
use nullca::bpf::loader::BpfLoader;
use nullca::engine::diff::DiffEngine;
use nullca::engine::discover::ProcessScanner;
use nullca::engine::filter::FilterEngine;
use nullca::engine::golang::GoSymbolTable;
use nullca::engine::ipc::{IpcClient, IpcServer, DEFAULT_SOCKET_PATH};
use nullca::engine::replay::{ReplayEngine, ReplayRequest};
use nullca::engine::spawn::ProcessLauncher;
use nullca::engine::symbols::ElfBinary;
use nullca::export::har::HarExporter;
use nullca::export::pcapng::PcapNgWriter;
use nullca::export::terminal::TerminalFormatter;
use nullca::proto::secrets::scan_secrets;
use nullca::ui::dashboard::run_dashboard;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            println!("{}", "=== NullCA Active TLS Process Scanner ===".bold().cyan());
            let targets = ProcessScanner::list_active_targets()?;

            if targets.is_empty() {
                println!("{}", "No active processes linked with OpenSSL/Go TLS detected.".yellow());
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
                ReplayRequest::from_raw(host.clone(), port, &bytes)
                    .ok_or_else(|| anyhow::anyhow!("Failed to parse raw HTTP request from {:?}", raw_path))?
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

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "nullca", &mut std::io::stdout());
        }

        Commands::ScanSecrets { path } => {
            println!("{} Scanning for secrets in: {}", "[*]".bold().blue(), path.display().to_string().cyan());
            let bytes = std::fs::read(&path)?;
            let secrets = scan_secrets(&bytes);

            if secrets.is_empty() {
                println!("{}", "No sensitive tokens or credentials detected.".green());
                return Ok(());
            }

            println!("\n{} Detected {} sensitive token(s):", "[!]".bold().red(), secrets.len());
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
                println!("{} Starting IPC broadcast socket at: {}", "[+]".bold().green(), s_path.display().to_string().cyan());
                Some(IpcServer::start(s_path)?)
            } else {
                None
            };

            if ui {
                run_dashboard(rx, ipc_server).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
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
            println!("{} Parsing ELF binary: {}", "[*]".bold().blue(), path.display().to_string().cyan());
            let elf = ElfBinary::parse(&path)?;

            let symbols = elf.symbols();
            println!("{} Total symbols indexed: {}", "[+]".bold().green(), symbols.len());

            let filtered: Vec<_> = if let Some(ref q) = query {
                symbols.iter().filter(|s| s.name.contains(q)).collect()
            } else {
                symbols.iter().take(25).collect()
            };

            println!("\n{:<18} {:<10} {:<10} {}", "OFFSET".bold(), "SIZE".bold(), "TYPE".bold(), "SYMBOL NAME".bold());
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
            println!("{} Dissecting Go Runtime pclntab: {}", "[*]".bold().blue(), path.display().to_string().cyan());
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
                    println!("  {:<32} {}", target.yellow(), "Not linked or stripped".dimmed());
                }
            }
        }

        Commands::EvalFilter { query } => {
            println!("{} Parsing Filter DSL Query: {}", "[*]".bold().blue(), query.cyan());
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
                eprintln!("{}", "[-] clang compiler not found on PATH. Install clang 12+.".bold().red());
                return Ok(());
            }

            BpfLoader::compile_bpf_program(&source, &output)?;
            println!("{}", "[+] eBPF bytecode compilation successful!".bold().green());
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

            let emul = emulate || !BpfLoader::has_bpf_capabilities();

            tokio::spawn(async move {
                if let Err(e) = loader.run_event_loop(None, tx, emul).await {
                    eprintln!("Error in event loop: {}", e);
                }
            });

            let ipc_server = if let Some(ref s_path) = socket {
                println!("{} Starting IPC broadcast socket at: {}", "[+]".bold().green(), s_path.display().to_string().cyan());
                Some(IpcServer::start(s_path)?)
            } else {
                None
            };

            if ui {
                run_dashboard(rx, ipc_server).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
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
            println!("{} Listening for decrypted TLS events...\n", "[*]".bold().blue());

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
