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
                        } else if file_str.contains("libnspr4.so")
                            || file_str.contains("libnss3.so")
                        {
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

pub struct SocketResolver;

impl SocketResolver {
    /// Attempts to resolve the socket inode for a given (pid, fd).
    pub fn get_socket_inode(pid: u32, fd: i32) -> Option<u64> {
        let path = format!("/proc/{}/fd/{}", pid, fd);
        let link = fs::read_link(path).ok()?;
        let s = link.to_string_lossy();
        if s.starts_with("socket:[") && s.ends_with(']') {
            let inode_str = &s[8..s.len() - 1];
            inode_str.parse::<u64>().ok()
        } else {
            None
        }
    }

    /// Resolves the (src_ip, src_port, dst_ip, dst_port) for a given pid and socket fd.
    pub fn resolve_endpoints(
        pid: u32,
        fd: i32,
        direction: crate::engine::event::Direction,
    ) -> Option<(String, u16, String, u16)> {
        let inode = Self::get_socket_inode(pid, fd)?;
        Self::lookup_inode_endpoints(pid, inode, direction)
    }

    /// Looks up an inode in /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6.
    pub fn lookup_inode_endpoints(
        pid: u32,
        inode: u64,
        direction: crate::engine::event::Direction,
    ) -> Option<(String, u16, String, u16)> {
        // Try process-specific IPv4 first
        if let Some(res) =
            Self::search_proc_net_file(&format!("/proc/{}/net/tcp", pid), inode, direction, false)
        {
            return Some(res);
        }
        // Fallback to system-wide /proc/net/tcp
        if let Some(res) = Self::search_proc_net_file("/proc/net/tcp", inode, direction, false) {
            return Some(res);
        }
        // Try IPv6
        if let Some(res) =
            Self::search_proc_net_file(&format!("/proc/{}/net/tcp6", pid), inode, direction, true)
        {
            return Some(res);
        }
        if let Some(res) = Self::search_proc_net_file("/proc/net/tcp6", inode, direction, true) {
            return Some(res);
        }
        None
    }

    fn search_proc_net_file(
        path: &str,
        target_inode: u64,
        direction: crate::engine::event::Direction,
        is_v6: bool,
    ) -> Option<(String, u16, String, u16)> {
        let content = fs::read_to_string(path).ok()?;
        Self::parse_proc_net_content(&content, target_inode, direction, is_v6)
    }

    pub fn parse_proc_net_content(
        content: &str,
        target_inode: u64,
        direction: crate::engine::event::Direction,
        is_v6: bool,
    ) -> Option<(String, u16, String, u16)> {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 9 {
                if let Ok(entry_inode) = parts[9].parse::<u64>() {
                    if entry_inode == target_inode {
                        let (local_ip, local_port) = Self::parse_hex_endpoint(parts[1], is_v6)?;
                        let (rem_ip, rem_port) = Self::parse_hex_endpoint(parts[2], is_v6)?;

                        return match direction {
                            crate::engine::event::Direction::Egress => {
                                Some((local_ip, local_port, rem_ip, rem_port))
                            }
                            crate::engine::event::Direction::Ingress => {
                                Some((rem_ip, rem_port, local_ip, local_port))
                            }
                        };
                    }
                }
            }
        }
        None
    }

    pub fn parse_hex_endpoint(endpoint: &str, is_v6: bool) -> Option<(String, u16)> {
        let (hex_ip, hex_port) = endpoint.split_once(':')?;
        let port = u16::from_str_radix(hex_port, 16).ok()?;

        if !is_v6 {
            let val = u32::from_str_radix(hex_ip, 16).ok()?;
            let b0 = (val & 0xFF) as u8;
            let b1 = ((val >> 8) & 0xFF) as u8;
            let b2 = ((val >> 16) & 0xFF) as u8;
            let b3 = ((val >> 24) & 0xFF) as u8;
            Some((std::net::Ipv4Addr::new(b0, b1, b2, b3).to_string(), port))
        } else {
            if hex_ip.len() != 32 {
                return None;
            }
            let mut words = [0u32; 4];
            for i in 0..4 {
                words[i] = u32::from_str_radix(&hex_ip[i * 8..(i + 1) * 8], 16).ok()?;
            }
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let wb = words[i].to_ne_bytes();
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&wb);
            }
            Some((std::net::Ipv6Addr::from(bytes).to_string(), port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_current_process() {
        let current_pid = std::process::id();
        let proc =
            ProcessScanner::inspect_process(current_pid).expect("Should inspect current pid");
        assert_eq!(proc.pid, current_pid);
    }

    #[test]
    fn test_socket_resolver_proc_net_parsing() {
        let sample_proc_net_tcp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:A123 0200007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 9959 2 000000005ac379cb 100 0 0 10 0
   1: 0100007F:A56B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 35863 2 0000000069e79ccf 100 0 0 10 0
";
        // Search inode 9959 with Egress direction
        let egress = SocketResolver::parse_proc_net_content(
            sample_proc_net_tcp,
            9959,
            crate::engine::event::Direction::Egress,
            false,
        )
        .expect("Should resolve inode 9959");

        assert_eq!(egress.0, "127.0.0.1");
        assert_eq!(egress.1, 41251); // 0xA123
        assert_eq!(egress.2, "127.0.0.2");
        assert_eq!(egress.3, 443); // 0x01BB

        // Ingress direction flips endpoints
        let ingress = SocketResolver::parse_proc_net_content(
            sample_proc_net_tcp,
            9959,
            crate::engine::event::Direction::Ingress,
            false,
        )
        .expect("Should resolve inode 9959");

        assert_eq!(ingress.0, "127.0.0.2");
        assert_eq!(ingress.1, 443);
        assert_eq!(ingress.2, "127.0.0.1");
        assert_eq!(ingress.3, 41251);
    }
}
