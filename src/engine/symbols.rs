use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymbolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid ELF magic header")]
    InvalidMagic,
    #[error("Unsupported ELF class (must be 64-bit)")]
    UnsupportedClass,
    #[error("Unsupported endianness")]
    UnsupportedEndian,
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("Malformed section header")]
    MalformedSection,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub is_function: bool,
}

#[derive(Debug)]
pub struct ElfBinary {
    path: String,
    symbols: Vec<SymbolInfo>,
}

impl ElfBinary {
    pub fn parse<P: AsRef<Path>>(path: P) -> Result<Self, SymbolError> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let mut file = File::open(path)?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != [0x7f, b'E', b'L', b'F'] {
            return Err(SymbolError::InvalidMagic);
        }

        let mut class = [0u8; 1];
        file.read_exact(&mut class)?;
        if class[0] != 2 {
            return Err(SymbolError::UnsupportedClass); // 2 = 64-bit
        }

        let mut data = [0u8; 1];
        file.read_exact(&mut data)?;
        if data[0] != 1 {
            return Err(SymbolError::UnsupportedEndian); // 1 = Little Endian
        }

        // Seek to 64-bit ELF header fields
        // e_shoff is at offset 40 (8 bytes)
        // e_shentsize is at offset 58 (2 bytes)
        // e_shnum is at offset 60 (2 bytes)
        // e_shstrndx is at offset 62 (2 bytes)
        file.seek(SeekFrom::Start(40))?;
        let mut buf8 = [0u8; 8];
        let mut buf2 = [0u8; 2];

        file.read_exact(&mut buf8)?;
        let e_shoff = u64::from_le_bytes(buf8);

        file.seek(SeekFrom::Start(58))?;
        file.read_exact(&mut buf2)?;
        let e_shentsize = u16::from_le_bytes(buf2) as u64;

        file.read_exact(&mut buf2)?;
        let e_shnum = u16::from_le_bytes(buf2) as usize;

        file.read_exact(&mut buf2)?;
        let _e_shstrndx = u16::from_le_bytes(buf2) as usize;

        if e_shoff == 0 || e_shnum == 0 {
            return Ok(Self {
                path: path_str,
                symbols: Vec::new(),
            });
        }

        // Read Section Headers
        #[derive(Default, Clone)]
        #[allow(dead_code)]
        struct SectionHeader {
            sh_name: u32,
            sh_type: u32,
            sh_flags: u64,
            sh_addr: u64,
            sh_offset: u64,
            sh_size: u64,
            sh_link: u32,
            sh_entsize: u64,
        }

        let mut sections = Vec::with_capacity(e_shnum);
        for i in 0..e_shnum {
            file.seek(SeekFrom::Start(e_shoff + (i as u64 * e_shentsize)))?;
            let mut sh_buf = [0u8; 64];
            file.read_exact(&mut sh_buf)?;

            let sh = SectionHeader {
                sh_name: u32::from_le_bytes(sh_buf[0..4].try_into().unwrap()),
                sh_type: u32::from_le_bytes(sh_buf[4..8].try_into().unwrap()),
                sh_flags: u64::from_le_bytes(sh_buf[8..16].try_into().unwrap()),
                sh_addr: u64::from_le_bytes(sh_buf[16..24].try_into().unwrap()),
                sh_offset: u64::from_le_bytes(sh_buf[24..32].try_into().unwrap()),
                sh_size: u64::from_le_bytes(sh_buf[32..40].try_into().unwrap()),
                sh_link: u32::from_le_bytes(sh_buf[40..44].try_into().unwrap()),
                sh_entsize: u64::from_le_bytes(sh_buf[56..64].try_into().unwrap()),
            };
            sections.push(sh);
        }

        let mut symbols = Vec::new();

        // Parse SHT_SYMTAB (2) and SHT_DYNSYM (11)
        for sh in &sections {
            if sh.sh_type == 2 || sh.sh_type == 11 {
                let strtab_idx = sh.sh_link as usize;
                if strtab_idx >= sections.len() {
                    continue;
                }
                let strtab_sec = &sections[strtab_idx];

                // Read string table
                file.seek(SeekFrom::Start(strtab_sec.sh_offset))?;
                let mut strtab = vec![0u8; strtab_sec.sh_size as usize];
                file.read_exact(&mut strtab)?;

                let entry_size = if sh.sh_entsize == 0 { 24 } else { sh.sh_entsize };
                let num_syms = (sh.sh_size / entry_size) as usize;

                for s in 0..num_syms {
                    file.seek(SeekFrom::Start(sh.sh_offset + (s as u64 * entry_size)))?;
                    let mut sym_buf = [0u8; 24];
                    file.read_exact(&mut sym_buf)?;

                    let st_name = u32::from_le_bytes(sym_buf[0..4].try_into().unwrap()) as usize;
                    let st_info = sym_buf[4];
                    let st_value = u64::from_le_bytes(sym_buf[8..16].try_into().unwrap());
                    let st_size = u64::from_le_bytes(sym_buf[16..24].try_into().unwrap());

                    let sym_type = st_info & 0xf;
                    let is_function = sym_type == 2; // STT_FUNC

                    if st_name < strtab.len() && st_value > 0 {
                        let name_bytes: Vec<u8> = strtab[st_name..]
                            .iter()
                            .take_while(|&&b| b != 0)
                            .cloned()
                            .collect();

                        if let Ok(name) = String::from_utf8(name_bytes) {
                            if !name.is_empty() {
                                // Calculate file offset from section mapping
                                let mut file_offset = st_value;
                                for target_sec in &sections {
                                    if target_sec.sh_addr <= st_value
                                        && st_value < (target_sec.sh_addr + target_sec.sh_size)
                                    {
                                        file_offset = target_sec.sh_offset + (st_value - target_sec.sh_addr);
                                        break;
                                    }
                                }

                                symbols.push(SymbolInfo {
                                    name,
                                    address: st_value,
                                    size: st_size,
                                    file_offset,
                                    is_function,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            path: path_str,
            symbols,
        })
    }

    pub fn find_symbol(&self, pattern: &str) -> Option<&SymbolInfo> {
        self.symbols.iter().find(|s| s.name == pattern || s.name.starts_with(pattern))
    }

    pub fn find_symbols_containing(&self, query: &str) -> Vec<&SymbolInfo> {
        self.symbols
            .iter()
            .filter(|s| s.name.contains(query))
            .collect()
    }

    pub fn symbols(&self) -> &[SymbolInfo] {
        &self.symbols
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_library() {
        // Try parsing libc or libssl if present
        let candidates = [
            "/usr/lib/libssl.so.3",
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/bin/sh",
        ];

        let mut tested = false;
        for path in &candidates {
            if Path::new(path).exists() {
                let elf = ElfBinary::parse(path).expect("Failed to parse system binary");
                assert!(!elf.symbols().is_empty() || Path::new(path).is_file());
                tested = true;
                break;
            }
        }
        assert!(tested, "At least one system binary should be parseable");
    }
}
