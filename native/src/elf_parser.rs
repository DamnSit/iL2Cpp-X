use std::io::Read;

#[derive(Clone, Debug)]
pub struct ElfSegment {
    pub segment_type: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

impl ElfSegment {
    pub fn is_load(&self) -> bool {
        self.segment_type == 1 // PT_LOAD
    }

    pub fn contains_file_offset(&self, file_offset: u64) -> bool {
        file_offset >= self.offset && file_offset < self.offset + self.filesz
    }

    pub fn file_offset_to_vaddr(&self, file_offset: u64) -> u64 {
        self.vaddr + (file_offset - self.offset)
    }

    pub fn vaddr_to_file_offset(&self, target_vaddr: u64) -> u64 {
        self.offset + (target_vaddr - self.vaddr)
    }
}

#[derive(Clone, Debug)]
pub struct ElfSection {
    pub name_offset: u32,
    pub section_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub name: String,
}

impl ElfSection {
    pub fn is_symtab(&self) -> bool {
        self.section_type == 2 // SHT_SYMTAB
    }

    pub fn is_dynsym(&self) -> bool {
        self.section_type == 11 // SHT_DYNSYM
    }

    pub fn is_strtab(&self) -> bool {
        self.section_type == 3 // SHT_STRTAB
    }
}

#[derive(Clone, Debug)]
pub struct ElfSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub section_index: u16,
}

impl ElfSymbol {
    pub fn is_function(&self) -> bool {
        (self.info & 0xF) == 2 // STT_FUNC
    }

    pub fn is_defined(&self) -> bool {
        self.section_index != 0 // SHN_UNDEF
    }

    pub fn end_value(&self) -> u64 {
        self.value + self.size
    }
}

#[derive(Clone, Debug)]
pub struct ElfInfo {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub entry_point: u64,
    pub segments: Vec<ElfSegment>,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
}

impl ElfInfo {
    pub fn load_segments(&self) -> Vec<&ElfSegment> {
        self.segments.iter().filter(|s| s.is_load()).collect()
    }

    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
        for seg in self.load_segments() {
            if vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.memsz {
                return Some(seg.offset + (vaddr - seg.vaddr));
            }
        }
        None
    }

    pub fn file_offset_to_vaddr(&self, file_offset: u64) -> Option<u64> {
        for seg in self.load_segments() {
            if seg.contains_file_offset(file_offset) {
                return Some(seg.file_offset_to_vaddr(file_offset));
            }
        }
        None
    }

    pub fn find_symbol(&self, name: &str) -> Option<&ElfSymbol> {
        self.symbols.iter().find(|s| s.name == name && s.is_defined())
    }

    pub fn find_symbols(&self, prefix: &str) -> Vec<&ElfSymbol> {
        self.symbols.iter().filter(|s| s.name.starts_with(prefix) && s.is_defined()).collect()
    }
}

pub struct ElfParser;

impl ElfParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_file(&self, path: &str) -> std::io::Result<ElfInfo> {
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        self.parse_bytes(&bytes)
    }

    pub fn parse_bytes(&self, bytes: &[u8]) -> std::io::Result<ElfInfo> {
        if bytes.len() < 16 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "File terlalu kecil untuk ELF"));
        }

        // Check magic
        if &bytes[0..4] != b"\x7FELF" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Bukan file ELF valid"));
        }

        let elf_class = bytes[4]; // 1=32-bit, 2=64-bit
        let is_64bit = elf_class == 2;
        let data_encoding = bytes[5]; // 1=LE, 2=BE
        let is_little_endian = data_encoding == 1;

        let (entry_point, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx);

        if is_64bit {
            entry_point = read_u64(bytes, 24, is_little_endian);
            phoff = read_u64(bytes, 32, is_little_endian);
            shoff = read_u64(bytes, 40, is_little_endian);
            phentsize = read_u16(bytes, 54, is_little_endian) as usize;
            phnum = read_u16(bytes, 56, is_little_endian) as usize;
            shentsize = read_u16(bytes, 58, is_little_endian) as usize;
            shnum = read_u16(bytes, 60, is_little_endian) as usize;
            shstrndx = read_u16(bytes, 62, is_little_endian) as usize;
        } else {
            entry_point = read_u32(bytes, 24, is_little_endian) as u64;
            phoff = read_u32(bytes, 28, is_little_endian) as u64;
            shoff = read_u32(bytes, 32, is_little_endian) as u64;
            phentsize = read_u16(bytes, 42, is_little_endian) as usize;
            phnum = read_u16(bytes, 44, is_little_endian) as usize;
            shentsize = read_u16(bytes, 46, is_little_endian) as usize;
            shnum = read_u16(bytes, 48, is_little_endian) as usize;
            shstrndx = read_u16(bytes, 50, is_little_endian) as usize;
        }

        let segments = parse_segments(bytes, phoff, phnum, phentsize, is_64bit, is_little_endian);
        let mut sections = parse_sections(bytes, shoff, shnum, shentsize, is_64bit, is_little_endian);

        // Read section name string table
        let section_names = if shstrndx < sections.len() {
            let strtab = &sections[shstrndx];
            read_string_table(bytes, strtab.offset as usize, strtab.size as usize)
        } else {
            std::collections::HashMap::new()
        };

        // Apply section names
        for sec in &mut sections {
            if let Some(name) = section_names.get(&(sec.name_offset as usize)) {
                sec.name = name.clone();
            }
        }

        let symbols = parse_symbol_tables(bytes, &sections, is_64bit, is_little_endian);

        Ok(ElfInfo {
            is_64bit,
            is_little_endian,
            entry_point,
            segments,
            sections,
            symbols,
        })
    }
}

fn parse_segments(bytes: &[u8], phoff: u64, phnum: usize, phentsize: usize, is_64bit: bool, is_le: bool) -> Vec<ElfSegment> {
    let mut segments = Vec::new();
    for i in 0..phnum {
        let off = (phoff as usize) + i * phentsize;
        if off + phentsize > bytes.len() { break; }

        if is_64bit {
            segments.push(ElfSegment {
                segment_type: read_u32(bytes, off, is_le),
                flags: read_u32(bytes, off + 4, is_le),
                offset: read_u64(bytes, off + 8, is_le),
                vaddr: read_u64(bytes, off + 16, is_le),
                filesz: read_u64(bytes, off + 32, is_le),
                memsz: read_u64(bytes, off + 40, is_le),
            });
        } else {
            segments.push(ElfSegment {
                segment_type: read_u32(bytes, off, is_le),
                offset: read_u32(bytes, off + 4, is_le) as u64,
                vaddr: read_u32(bytes, off + 8, is_le) as u64,
                flags: read_u32(bytes, off + 24, is_le),
                filesz: read_u32(bytes, off + 16, is_le) as u64,
                memsz: read_u32(bytes, off + 20, is_le) as u64,
            });
        }
    }
    segments
}

fn parse_sections(bytes: &[u8], shoff: u64, shnum: usize, shentsize: usize, is_64bit: bool, is_le: bool) -> Vec<ElfSection> {
    let mut sections = Vec::new();
    for i in 0..shnum {
        let off = (shoff as usize) + i * shentsize;
        if off + shentsize > bytes.len() { break; }

        if is_64bit {
            sections.push(ElfSection {
                name_offset: read_u32(bytes, off, is_le),
                section_type: read_u32(bytes, off + 4, is_le),
                flags: read_u64(bytes, off + 8, is_le),
                addr: read_u64(bytes, off + 16, is_le),
                offset: read_u64(bytes, off + 24, is_le),
                size: read_u64(bytes, off + 32, is_le),
                link: read_u32(bytes, off + 40, is_le),
                name: String::new(),
            });
        } else {
            sections.push(ElfSection {
                name_offset: read_u32(bytes, off, is_le),
                section_type: read_u32(bytes, off + 4, is_le),
                flags: read_u32(bytes, off + 8, is_le) as u64,
                addr: read_u32(bytes, off + 12, is_le) as u64,
                offset: read_u32(bytes, off + 16, is_le) as u64,
                size: read_u32(bytes, off + 20, is_le) as u64,
                link: read_u32(bytes, off + 24, is_le),
                name: String::new(),
            });
        }
    }
    sections
}

fn parse_symbol_tables(bytes: &[u8], sections: &[ElfSection], is_64bit: bool, is_le: bool) -> Vec<ElfSymbol> {
    let mut all_symbols = Vec::new();

    for section in sections {
        if !section.is_symtab() && !section.is_dynsym() {
            continue;
        }

        // Find associated string table via sh_link
        let strtab_section = if (section.link as usize) < sections.len() {
            Some(&sections[section.link as usize])
        } else {
            sections.iter().find(|s| s.is_strtab() && s.offset != section.offset)
        };

        let string_table = if let Some(strtab) = strtab_section {
            read_string_table(bytes, strtab.offset as usize, strtab.size as usize)
        } else {
            std::collections::HashMap::new()
        };

        let entry_size = if is_64bit { 24 } else { 16 };
        let entry_count = (section.size as usize) / entry_size;
        let section_offset = section.offset as usize;

        for i in 0..entry_count {
            let off = section_offset + i * entry_size;
            if off + entry_size > bytes.len() { break; }

            let (name_offset, info, value, size, section_index);

            if is_64bit {
                name_offset = read_u32(bytes, off, is_le) as usize;
                info = bytes[off + 4];
                section_index = read_u16(bytes, off + 6, is_le);
                value = read_u64(bytes, off + 8, is_le);
                size = read_u64(bytes, off + 16, is_le);
            } else {
                name_offset = read_u32(bytes, off, is_le) as usize;
                value = read_u32(bytes, off + 4, is_le) as u64;
                size = read_u32(bytes, off + 8, is_le) as u64;
                info = bytes[off + 12];
                section_index = read_u16(bytes, off + 14, is_le);
            }

            if let Some(name) = string_table.get(&name_offset) {
                if !name.is_empty() {
                    all_symbols.push(ElfSymbol {
                        name: name.clone(),
                        value,
                        size,
                        info,
                        section_index,
                    });
                }
            }
        }
    }

    all_symbols
}

fn read_string_table(bytes: &[u8], offset: usize, size: usize) -> std::collections::HashMap<usize, String> {
    let mut result = std::collections::HashMap::new();
    let end = std::cmp::min(offset + size, bytes.len());
    let mut start: Option<usize> = None;

    for i in offset..end {
        if bytes[i] == 0 {
            if let Some(s) = start {
                let name = String::from_utf8_lossy(&bytes[s..i]).to_string();
                result.insert(s - offset, name);
                start = None;
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }

    result
}

fn read_u16(bytes: &[u8], offset: usize, is_le: bool) -> u16 {
    let b0 = bytes[offset] as u16;
    let b1 = bytes[offset + 1] as u16;
    if is_le { b0 | (b1 << 8) } else { (b0 << 8) | b1 }
}

fn read_u32(bytes: &[u8], offset: usize, is_le: bool) -> u32 {
    let b0 = bytes[offset] as u32;
    let b1 = bytes[offset + 1] as u32;
    let b2 = bytes[offset + 2] as u32;
    let b3 = bytes[offset + 3] as u32;
    if is_le {
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    } else {
        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
}

fn read_u64(bytes: &[u8], offset: usize, is_le: bool) -> u64 {
    let lo = read_u32(bytes, offset, is_le) as u64;
    let hi = read_u32(bytes, offset + 4, is_le) as u64;
    if is_le { lo | (hi << 32) } else { (lo << 32) | hi }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u32_le() {
        let bytes = vec![0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32(&bytes, 0, true), 0x12345678);
    }

    #[test]
    fn test_read_u64_le() {
        let bytes = vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x00];
        assert_eq!(read_u64(&bytes, 0, true), 0x00ABCDEF12345678);
    }

    #[test]
    fn test_elf_magic_check() {
        let bad = vec![0u8; 16];
        let parser = ElfParser::new();
        assert!(parser.parse_bytes(&bad).is_err());
    }
}
