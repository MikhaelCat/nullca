use clap::{Parser, Subcommand};
use colored::*;
use nullca::bpf::loader::BpfLoader;
use nullca::engine::discover::ProcessScanner;
use nullca::engine::symbols::ElfBinary;
use nullca::export::pcapng::PcapNgWriter;
use nullca::export::terminal::TerminalFormatter;
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

    /// Trace decrypted TLS traffic in real-time
    Trace {
        /// Target Process ID (PID)
        #[arg(short, long)]
        pid: Option<u32>,

        /// Filter by process executable name
        #[arg(short, long)]
        name: Option<String>,

        /// Export decrypted sessions to Wireshark PCAP-NG file
        #[arg(long)]
        pcap: Option<PathBuf>,

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

    /// Inspect dynamic and static symbols of an ELF binary or shared library
    InspectElf {
        /// Path to ELF binary or shared library
        path: PathBuf,

        /// Filter symbol name query
        #[arg(short, long)]
        query: Option<String>,
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
            pcap,
            json,
            hexdump,
            emulate,
        } => {
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

            let mut formatter = TerminalFormatter::new(hexdump);
            let (tx, mut rx) = mpsc::channel(100);

            let loader = BpfLoader::new(pid);

            // Spawn event receiver task
            let emul = emulate || !BpfLoader::has_bpf_capabilities();
            if emul && !emulate {
                println!(
                    "{} Notice: Running without root/CAP_BPF; entering live emulation mode.",
                    "[!]".bold().yellow()
                );
            }

            tokio::spawn(async move {
                if let Err(e) = loader.run_event_loop(None, tx, emul).await {
                    eprintln!("Error in event loop: {}", e);
                }
            });

            println!("{} Listening for decrypted TLS events...\n", "[*]".bold().blue());

            while let Some(event) = rx.recv().await {
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
            }
        }
    }

    Ok(())
}
