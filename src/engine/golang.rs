//! Go 1.17+ ABIInternal Calling Conventions and `.gopclntab` Runtime Symbol Dissector.
//!
//! Enables zero-overhead uprobe tracing for stripped Go binaries by directly parsing
//! the Go runtime Program Counter Line Table (`.gopclntab`) and mapping register conventions.

use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Supported Go runtime PCLNTAB magic numbers across versions.
pub const GO_PCLNTAB_MAGIC_116: u32 = 0xffff_fffb; // Go 1.16
pub const GO_PCLNTAB_MAGIC_118: u32 = 0xffff_fff0; // Go 1.18
pub const GO_PCLNTAB_MAGIC_120: u32 = 0xffff_fff1; // Go 1.20+

/// Go function metadata resolved from `.gopclntab`.
#[derive(Debug, Clone)]
pub struct GoFunctionSymbol {
    pub name: String,
    pub entry_pc: u64,
    pub end_pc: u64,
    pub func_offset: u32,
    pub is_crypto_tls: bool,
}

/// Go ABIInternal register allocation for AMD64 (Go 1.17+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoAbiRegister {
    Rax, // Receiver / Return value / Arg 0
    Rbx, // Arg 1 (e.g. Slice pointer)
    Rcx, // Arg 2 (e.g. Slice length)
    Rdi, // Arg 3 (e.g. Slice capacity)
    Rsi, // Arg 4
    R8,  // Arg 5
    R9,  // Arg 6
    R10, // Arg 7
    Rdx, // Arg 8
}

impl GoAbiRegister {
    pub fn linux_dwarf_reg(&self) -> u16 {
        match self {
            GoAbiRegister::Rax => 0,
            GoAbiRegister::Rdx => 1,
            GoAbiRegister::Rcx => 2,
            GoAbiRegister::Rbx => 3,
            GoAbiRegister::Rsi => 4,
            GoAbiRegister::Rdi => 5,
            GoAbiRegister::R8 => 8,
            GoAbiRegister::R9 => 9,
            GoAbiRegister::R10 => 10,
        }
    }

    pub fn register_name(&self) -> &'static str {
        match self {
            GoAbiRegister::Rax => "%ax",
            GoAbiRegister::Rbx => "%bx",
            GoAbiRegister::Rcx => "%cx",
            GoAbiRegister::Rdi => "%di",
            GoAbiRegister::Rsi => "%si",
            GoAbiRegister::R8 => "%r8",
            GoAbiRegister::R9 => "%r9",
            GoAbiRegister::R10 => "%r10",
            GoAbiRegister::Rdx => "%dx",
        }
    }
}

/// Dissector for Go runtime tables in stripped ELF executables.
pub struct GoSymbolTable {
    pub magic: u32,
    pub ptr_size: u8,
    pub nfunc: usize,
    pub text_start: u64,
    pub functions: HashMap<String, GoFunctionSymbol>,
}

impl GoSymbolTable {
    /// Attempts to locate and parse `.gopclntab` inside a raw ELF binary image.
    pub fn parse(elf_data: &[u8]) -> Result<Self> {
        let magic_offset = find_pclntab_magic(elf_data)
            .ok_or_else(|| anyhow!("No valid Go .gopclntab magic found in binary"))?;

        let header = &elf_data[magic_offset..];
        if header.len() < 32 {
            return Err(anyhow!("Truncated .gopclntab header"));
        }

        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let _min_lc = header[6];
        let ptr_size = header[7];

        if ptr_size != 8 && ptr_size != 4 {
            return Err(anyhow!("Unsupported Go pointer size: {}", ptr_size));
        }

        let nfunc: usize = if ptr_size == 8 {
            u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize
        } else {
            u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize
        };

        // Header field offsets differ between 1.16, 1.18, and 1.20+
        let (text_start, funcname_offset, func_tab_offset) = match magic {
            GO_PCLNTAB_MAGIC_118 | GO_PCLNTAB_MAGIC_120 => {
                let text_start = if ptr_size == 8 {
                    u64::from_le_bytes(header[24..32].try_into().unwrap())
                } else {
                    u32::from_le_bytes(header[16..20].try_into().unwrap()) as u64
                };
                let funcname_off = if ptr_size == 8 {
                    u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize
                } else {
                    u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize
                };
                let func_tab_off = if ptr_size == 8 {
                    u64::from_le_bytes(header[56..64].try_into().unwrap()) as usize
                } else {
                    u32::from_le_bytes(header[32..36].try_into().unwrap()) as usize
                };
                (text_start, funcname_off, func_tab_off)
            }
            _ => {
                // Fallback for Go 1.16 and earlier
                let text_start = 0u64;
                (text_start, 0usize, 16usize)
            }
        };

        let mut functions = HashMap::new();

        // Scan functions in table (capped to 50,000 for sanity)
        let max_funcs = nfunc.min(50_000);
        let func_tab_start = magic_offset + func_tab_offset;
        let funcname_table = magic_offset + funcname_offset;

        for i in 0..max_funcs {
            let entry_offset = func_tab_start + i * (ptr_size as usize * 2);
            if entry_offset + (ptr_size as usize * 2) > elf_data.len() {
                break;
            }

            let entry_pc = if ptr_size == 8 {
                u64::from_le_bytes(elf_data[entry_offset..entry_offset + 8].try_into().unwrap())
            } else {
                u32::from_le_bytes(elf_data[entry_offset..entry_offset + 4].try_into().unwrap()) as u64
            };

            let foff = if ptr_size == 8 {
                u64::from_le_bytes(elf_data[entry_offset + 8..entry_offset + 16].try_into().unwrap()) as usize
            } else {
                u32::from_le_bytes(elf_data[entry_offset + 4..entry_offset + 8].try_into().unwrap()) as usize
            };

            let func_info_offset = magic_offset + foff;
            if func_info_offset + 16 > elf_data.len() {
                continue;
            }

            let name_off = u32::from_le_bytes(elf_data[func_info_offset + 4..func_info_offset + 8].try_into().unwrap()) as usize;
            let full_name_offset = funcname_table + name_off;

            if full_name_offset < elf_data.len() {
                if let Some(name) = read_c_string(&elf_data[full_name_offset..]) {
                    let is_crypto_tls = name.starts_with("crypto/tls.")
                        || name.contains("(*Conn).Read")
                        || name.contains("(*Conn).Write");

                    functions.insert(
                        name.clone(),
                        GoFunctionSymbol {
                            name,
                            entry_pc,
                            end_pc: entry_pc,
                            func_offset: foff as u32,
                            is_crypto_tls,
                        },
                    );
                }
            }
        }

        Ok(Self {
            magic,
            ptr_size,
            nfunc,
            text_start,
            functions,
        })
    }

    /// Finds candidate target functions for uprobe attachment in Go binaries.
    pub fn find_crypto_tls_targets(&self) -> Vec<&GoFunctionSymbol> {
        self.functions
            .values()
            .filter(|f| f.is_crypto_tls)
            .collect()
    }
}

/// Locates Go `.gopclntab` magic bytes in an ELF slice.
fn find_pclntab_magic(data: &[u8]) -> Option<usize> {
    if data.len() < 16 {
        return None;
    }
    // Search for 4-byte magic word
    for i in 0..(data.len() - 4) {
        let val = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if val == GO_PCLNTAB_MAGIC_120 || val == GO_PCLNTAB_MAGIC_118 || val == GO_PCLNTAB_MAGIC_116 {
            // Verify plausible ptr_size (4 or 8) at offset 7
            if i + 8 <= data.len() && (data[i + 7] == 8 || data[i + 7] == 4) {
                return Some(i);
            }
        }
    }
    None
}

/// Reads null-terminated string from byte slice.
fn read_c_string(slice: &[u8]) -> Option<String> {
    let mut end = 0;
    while end < slice.len() && slice[end] != 0 && end < 256 {
        end += 1;
    }
    if end > 0 {
        String::from_utf8(slice[..end].to_vec()).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_abi_registers() {
        assert_eq!(GoAbiRegister::Rax.register_name(), "%ax");
        assert_eq!(GoAbiRegister::Rbx.register_name(), "%bx");
        assert_eq!(GoAbiRegister::Rcx.register_name(), "%cx");
        assert_eq!(GoAbiRegister::Rdi.register_name(), "%di");
    }

    #[test]
    fn test_mock_pclntab_magic_search() {
        let mut mock_elf = vec![0x90; 1024];
        let magic_bytes = GO_PCLNTAB_MAGIC_120.to_le_bytes();
        mock_elf[100..104].copy_from_slice(&magic_bytes);
        mock_elf[107] = 8; // ptr_size = 8

        let found = find_pclntab_magic(&mock_elf);
        assert_eq!(found, Some(100));
    }
}
