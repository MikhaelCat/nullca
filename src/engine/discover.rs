use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscoverError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Target process {0} not found")]
    ProcessNotFound(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFlavor {
    OpenSsl,
    BoringSsl,
    GoCryptoTls,
    Rustls,
    GnuTls,
    Nss,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct MappedLibrary {
    pub path: PathBuf,
    pub base_address: u64,
    pub flavor: TlsFlavor,
}

#[derive(Debug, Clone)]
pub struct TargetProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: Option<PathBuf>,
    pub tls_libraries: Vec<MappedLibrary>,
}

pub struct ProcessScanner;

impl ProcessScanner {
    pub fn list_active_targets() -> Result<Vec<TargetProcess>, DiscoverError> {
        let mut targets = Vec::new();

        let proc_entries = match fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(_) => return Ok(targets),
        };

        for entry in proc_entries.flatten() {
            let filename = entry.file_name();
            let pid_str = filename.to_string_lossy();

            if let Ok(pid) = pid_str.parse::<u32>() {
                if let Ok(target) = Self::inspect_process(pid) {
                    if !target.tls_libraries.is_empty() {
                        targets.push(target);
                    }
                }
            }
        }

        targets.sort_by_key(|t| t.pid);
        Ok(targets)
    }

    pub fn inspect_process(pid: u32) -> Result<TargetProcess, DiscoverError> {
        let proc_dir = PathBuf::from(format!("/proc/{}", pid));
        if !proc_dir.exists() {
            return Err(DiscoverError::ProcessNotFound(pid));
        }

        let name = fs::read_to_string(proc_dir.join("comm"))
            .unwrap_or_else(|_| format!("pid_{}", pid))
            .trim()
            .to_string();

        let cmdline = fs::read(proc_dir.join("cmdline"))
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|slice| !slice.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        let exe_path = fs::read_link(proc_dir.join("exe")).ok();

        // Scan memory maps for TLS implementations
        let mut tls_libraries = Vec::new();
        let maps_path = proc_dir.join("maps");

        if let Ok(maps_content) = fs::read_to_string(&maps_path) {
            for line in maps_content.lines() {
                // Example format:
                // 7f9b8c000000-7f9b8c020000 r-xp 00000000 103:02 123456 /usr/lib/libssl.so.3
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let addr_range = parts[0];
                    let perms = parts[1];
                    let pathname = parts[5];

                    // Only look at executable mappings (r-xp)
                    if perms.contains('x') {
                        let path = PathBuf::from(pathname);
                        let file_str = pathname.to_lowercase();

                        let flavor = if file_str.contains("libssl.so") {
                            TlsFlavor::OpenSsl
                        } else if file_str.contains("boringssl") {
                            TlsFlavor::BoringSsl
                        } else if file_str.contains("libgnutls.so") {
                            TlsFlavor::GnuTls
                        } else if file_str.contains("libnspr4.so") || file_str.contains("libnss3.so") {
                            TlsFlavor::Nss
                        } else if file_str.contains("rustls") {
                            TlsFlavor::Rustls
                        } else {
                            TlsFlavor::Unknown
                        };

                        if flavor != TlsFlavor::Unknown || Self::is_go_binary(&path) {
                            let base_addr_str = addr_range.split('-').next().unwrap_or("0");
                            let base_address = u64::from_str_radix(base_addr_str, 16).unwrap_or(0);

                            let final_flavor = if flavor != TlsFlavor::Unknown {
                                flavor
                            } else {
                                TlsFlavor::GoCryptoTls
                            };

                            // Avoid duplicate library records
                            if !tls_libraries.iter().any(|m: &MappedLibrary| m.path == path) {
                                tls_libraries.push(MappedLibrary {
                                    path,
                                    base_address,
                                    flavor: final_flavor,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(TargetProcess {
            pid,
            name,
            cmdline,
            exe_path,
            tls_libraries,
        })
    }

    fn is_go_binary(path: &Path) -> bool {
        // Quick heuristic check for Go binaries: contains go.buildid or gopclntab
        if !path.exists() || !path.is_file() {
            return false;
        }

        if let Ok(mut file) = fs::File::open(path) {
            use std::io::Read;
            let mut head = vec![0u8; 4096];
            if file.read(&mut head).is_ok() {
                return head.windows(11).any(|w| w == b"go.buildid\0")
                    || head.windows(10).any(|w| w == b".gopclntab");
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_current_process() {
        let current_pid = std::process::id();
        let proc = ProcessScanner::inspect_process(current_pid).expect("Should inspect current pid");
        assert_eq!(proc.pid, current_pid);
    }
}
