use clap::{Parser, Subcommand};
use colored::*;
use nullca::bpf::loader::BpfLoader;
use nullca::engine::discover::ProcessScanner;
use nullca::engine::filter::FilterEngine;
use nullca::engine::golang::GoSymbolTable;
use nullca::engine::spawn::ProcessLauncher;
use nullca::engine::symbols::ElfBinary;
use nullca::export::har::HarExporter;
use nullca::export::pcapng::PcapNgWriter;
use nullca::export::terminal::TerminalFormatter;
use nullca::proto::secrets::scan_secrets;
use nullca::ui::dashboard::run_dashboard;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(
    name = "nullca",
    author = "Mikhael (MikhaelCat)",
    version = "0.1.0",
    about = "⚡ Zero-CA eBPF Plaintext TLS, HTTP/2 & gRPC Sniffer in Pure Rust",
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

        /// Emulate live TLS traffic for testing
        #[arg(long)]
        emulate: bool,

        /// Target command line to execute (e.g. -- curl -s https://api.github.com)
        #[arg(last = true, required = true)]
        command: Vec<String>,
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

            if ui {
                run_dashboard(rx).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                return Ok(());
            }

            let mut pcap_writer = if let Some(ref pcap_path) = pcap {
                Some(PcapNgWriter::create(pcap_path)?)
            } else {
                None
            };

            let mut captured_events = Vec::new();
            let mut formatter = TerminalFormatter::new(false);
            let mut mut_rx = rx;

            while let Some(event) = mut_rx.recv().await {
                if let Some(ref mut pw) = pcap_writer {
                    let _ = pw.write_event(&event);
                }
                print!("{}", formatter.format_event(&event));
                if har.is_some() {
                    captured_events.push(event);
                }
            }

            if let Some(har_path) = har {
                HarExporter::write_to_file(&captured_events, har_path)?;
                println!("{}", "[+] Exported sessions to HAR 1.2 successfully!".green());
            }
        }

        Commands::InspectElf { path, query } => {
            println!(
                "{} Inspecting ELF: {}",
                "[*]".bold().blue(),
                path.display().to_string().cyan()
            );
            let elf = ElfBinary::parse(&path)?;

            let matched = if let Some(q) = query {
                elf.find_symbols_containing(&q)
            } else {
                elf.symbols().iter().collect()
            };

            println!("Found {} symbol(s):", matched.len());
            for sym in matched.iter().take(50) {
                println!(
                    "  0x{:016x} (offset: 0x{:08x}, size: {:4}) [{}] {}",
                    sym.address,
                    sym.file_offset,
                    sym.size,
                    if sym.is_function { "FUNC" } else { "DATA" },
                    sym.name.green()
                );
            }
            if matched.len() > 50 {
                println!("  ... and {} more symbols", matched.len() - 50);
            }
        }

        Commands::InspectGo { path } => {
            println!(
                "{} Dissecting Go runtime .gopclntab: {}",
                "[*]".bold().blue(),
                path.display().to_string().cyan()
            );
            let bytes = std::fs::read(&path)?;
            let go_table = GoSymbolTable::parse(&bytes)?;

            println!(
                "{} Found Go runtime table (magic: 0x{:08x}, ptr_size: {}, total functions: {})",
                "[+]".bold().green(),
                go_table.magic,
                go_table.ptr_size,
                go_table.functions.len()
            );

            let targets = go_table.find_crypto_tls_targets();
            println!("\n{} Identified {} crypto/tls candidates:", "[*]".bold().yellow(), targets.len());
            for target in targets {
                println!(
                    "  [0x{:016x}] {}",
                    target.entry_pc,
                    target.name.green()
                );
            }
        }

        Commands::EvalFilter { query } => {
            println!("Compiling filter expression: '{}'", query.cyan());
            match FilterEngine::compile(&query) {
                Ok(_) => println!("{}", "[+] Filter compiled successfully with valid AST!".bold().green()),
                Err(err) => eprintln!("{} Syntax error in filter: {:?}", "[-]".bold().red(), err),
            }
        }

        Commands::CompileBpf { source, output } => {
            println!(
                "{} Compiling eBPF probe: {} -> {}",
                "[*]".bold().blue(),
                source.display(),
                output.display()
            );

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
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

            if ui {
                // Interactive Ratatui Dashboard
                run_dashboard(rx).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
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
  Zero-CA eBPF Plaintext TLS, HTTP/2 & gRPC Interceptor
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
