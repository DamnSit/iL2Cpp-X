use std::io::{BufWriter, Write};

use crate::elf_parser::ElfInfo;
use crate::metadata_models::*;
use crate::rva_resolver::RvaResult;

pub struct DumpCsWriter {
    pub include_rva_info: bool,
    pub include_inheritance: bool,
}

impl DumpCsWriter {
    pub fn new() -> Self {
        Self {
            include_rva_info: true,
            include_inheritance: true,
        }
    }

    /// Build a lookup from type_index -> "Namespace.TypeName" for display.
    /// If elf_info and lib_bytes are provided, resolves Il2CppType array from the binary
    /// for accurate type name mapping. Otherwise falls back to TypeDef index mapping.
    fn build_type_name_map(
        metadata: &MetadataParseResult,
        elf_info: Option<&ElfInfo>,
        lib_bytes: Option<&[u8]>,
        debug_log: &mut Vec<String>,
    ) -> std::collections::HashMap<usize, String> {
        // Try to resolve from Il2CppType array in the ELF binary
        if let (Some(elf), Some(bytes)) = (elf_info, lib_bytes) {
            match Self::resolve_il2cpp_types(elf, bytes, metadata, debug_log) {
                Some(map) => {
                    debug_log.push(format!("Il2CppType resolved: {} types", map.len()));
                    return map;
                }
                None => {
                    debug_log.push("Il2CppType resolution failed, using fallback".to_string());
                }
            }
        } else {
            debug_log.push("No ELF data provided, using TypeDef fallback".to_string());
        }
        // Fallback: map TypeDef indices directly
        let mut map = std::collections::HashMap::new();
        for t in &metadata.types {
            let fqcn = if !t.namespace_name.is_empty() {
                format!("{}.{}", t.namespace_name, t.name)
            } else {
                t.name.clone()
            };
            map.insert(t.index, fqcn);
        }
        map
    }

    /// Try to resolve Il2CppType array from the ELF binary.
    ///
    /// The types array in MetadataRegistration is `Il2CppType**` — an array of pointers.
    /// Each pointer points to an Il2CppType struct:
    ///   +0: union { void* dummy; int32_t klassIndex; Il2CppType* type; ... } data
    ///   +4/8: bitfields { attrs:16, type:8, num_mods:5, byref:1, pinned:1, valuetype:1 }
    ///
    /// On LE, the type kind byte is at offset +2 of the bitfield word,
    /// so struct offset = data_size + 2 (6 on 32-bit, 10 on 64-bit).
    fn resolve_il2cpp_types(
        elf_info: &ElfInfo,
        lib_bytes: &[u8],
        metadata: &MetadataParseResult,
        debug_log: &mut Vec<String>,
    ) -> Option<std::collections::HashMap<usize, String>> {
        let is_le = elf_info.is_little_endian;
        let is_64 = elf_info.is_64bit;
        let ptr_size: usize = if is_64 { 8 } else { 4 };
        // Il2CppType struct: data union (ptr_size bytes) + bitfields (4 bytes)
        // Type kind byte is at bitfield+2 on LE = struct offset (ptr_size + 2)
        let type_kind_offset = if is_le { ptr_size + 2 } else { ptr_size + 1 };
        // TypeDef index is i32 at data union offset +0
        let data_offset = 0usize;

        // Apply relocations — pointers in .data.rel.ro need R_AARCH64_RELATIVE
        // relocations applied before they contain valid virtual addresses.
        let patched_bytes = crate::rva_resolver::apply_relocations(lib_bytes, elf_info);
        let bytes = &patched_bytes;

        // Look for g_MetadataRegistration symbol (try alternate names too)
        let meta_reg_addr = elf_info.find_symbol("g_MetadataRegistration")
            .or_else(|| elf_info.find_symbol("g_MetadataRegistrationPtr"))
            .map(|s| s.value);
        debug_log.push(format!("g_MetadataRegistration: {:?}", meta_reg_addr));

        let (types_array_va, types_count) = if let Some(addr) = meta_reg_addr {
            let foff = match elf_info.vaddr_to_file_offset(addr) {
                Some(o) => o as usize,
                None => {
                    debug_log.push(format!("vaddr_to_file_offset failed for 0x{:x}", addr));
                    return None;
                }
            };
            debug_log.push(format!("MetadataReg struct at file offset 0x{:x}", foff));
            match Self::find_types_in_metadata_reg(bytes, foff, elf_info, metadata, is_le, ptr_size) {
                Some(r) => {
                    debug_log.push(format!("find_types_in_metadata_reg: va=0x{:x} count={}", r.0, r.1));
                    r
                }
                None => {
                    debug_log.push("find_types_in_metadata_reg returned None, trying scan".to_string());
                    match Self::find_types_by_scan(bytes, elf_info, metadata, is_le, ptr_size) {
                        Some(r) => {
                            debug_log.push(format!("find_types_by_scan: va=0x{:x} count={}", r.0, r.1));
                            r
                        }
                        None => {
                            debug_log.push("find_types_by_scan also returned None".to_string());
                            return None;
                        }
                    }
                }
            }
        } else {
            debug_log.push("No g_MetadataRegistration symbol, scanning data segments".to_string());
            match Self::find_types_by_scan(bytes, elf_info, metadata, is_le, ptr_size) {
                Some(r) => {
                    debug_log.push(format!("find_types_by_scan: va=0x{:x} count={}", r.0, r.1));
                    r
                }
                None => {
                    debug_log.push("find_types_by_scan returned None".to_string());
                    return None;
                }
            }
        };

        // types_array_va points to array of Il2CppType* pointers
        let types_ptr_array_foff = elf_info.vaddr_to_file_offset(types_array_va)? as usize;
        debug_log.push(format!("types_array_va=0x{:x} foff=0x{:x} count={}", types_array_va, types_ptr_array_foff, types_count));

        // Determine actual array size by scanning for the highest valid pointer.
        // typesCount from the struct might be wrong — scan up to a reasonable limit.
        // Don't stop on consecutive nulls — there might be gaps in the array.
        let max_scan_limit = bytes.len().saturating_sub(types_ptr_array_foff) / ptr_size;
        let max_scan = std::cmp::min(max_scan_limit, 200000);
        let mut actual_count = 0usize;
        let mut max_valid_index = 0usize;
        let mut valid_total = 0usize;
        for i in 0..max_scan {
            let off = types_ptr_array_foff + i * ptr_size;
            if off + ptr_size > bytes.len() { break; }
            let ptr = if is_64 {
                crate::rva_resolver::read_u64(bytes, off, is_le)
            } else {
                crate::rva_resolver::read_u32(bytes, off, is_le) as u64
            };
            if ptr == 0 { continue; }
            if elf_info.vaddr_to_file_offset(ptr).is_some() {
                actual_count = i + 1;
                max_valid_index = i;
                valid_total += 1;
            }
        }
        let effective_count = actual_count;
        debug_log.push(format!("types array scan: effective_count={} max_valid_index={} valid_entries={}", effective_count, max_valid_index, valid_total));

        // Debug: check specific high indices from field type_index values
        for &dbg_i in &[29843, 31395, 35140] {
            let dbg_off = types_ptr_array_foff + dbg_i * ptr_size;
            if dbg_off + ptr_size <= bytes.len() {
                let dbg_ptr = if is_64 {
                    crate::rva_resolver::read_u64(bytes, dbg_off, is_le)
                } else {
                    crate::rva_resolver::read_u32(bytes, dbg_off, is_le) as u64
                };
                let dbg_foff = elf_info.vaddr_to_file_offset(dbg_ptr).map(|o| o as usize);
                let dbg_kind = dbg_foff.and_then(|o| {
                    if o + type_kind_offset + 1 <= bytes.len() { Some(bytes[o + type_kind_offset]) } else { None }
                });
                debug_log.push(format!("  CHECK type[{}]: ptr=0x{:x} foff={:?} kind={:?}", dbg_i, dbg_ptr, dbg_foff, dbg_kind));
            } else {
                debug_log.push(format!("  CHECK type[{}]: OUT OF BOUNDS (off=0x{:x} len=0x{:x})", dbg_i, dbg_off, bytes.len()));
            }
        }

        // Log first few pointers from the array
        for dbg_i in 0..std::cmp::min(effective_count, 3) {
            let dbg_off = types_ptr_array_foff + dbg_i * ptr_size;
            if dbg_off + ptr_size <= bytes.len() {
                let dbg_ptr = if is_64 {
                    crate::rva_resolver::read_u64(bytes, dbg_off, is_le)
                } else {
                    crate::rva_resolver::read_u32(bytes, dbg_off, is_le) as u64
                };
                let dbg_foff = elf_info.vaddr_to_file_offset(dbg_ptr).map(|o| o as usize);
                let dbg_kind = dbg_foff.and_then(|o| {
                    if o + type_kind_offset + 1 <= bytes.len() { Some(bytes[o + type_kind_offset]) } else { None }
                });
                debug_log.push(format!("  type[{}]: ptr=0x{:x} foff={:?} kind={:?}", dbg_i, dbg_ptr, dbg_foff, dbg_kind));
            }
        }

        let mut map = std::collections::HashMap::new();
        // TypeDef index → name (for resolving CLASS/VALUETYPE data)
        let mut td_names = std::collections::HashMap::new();
        for td in &metadata.types {
            if !td.name.is_empty() {
                let name = if td.namespace_name.is_empty() {
                    td.name.clone()
                } else {
                    format!("{}.{}", td.namespace_name, td.name)
                };
                td_names.insert(td.index, name);
            }
        }
        let primitive_names: [(u8, &str); 18] = [
            (1, "void"), (2, "bool"), (3, "char"), (4, "sbyte"), (5, "byte"),
            (6, "short"), (7, "ushort"), (8, "int"), (9, "uint"),
            (10, "long"), (11, "ulong"), (12, "float"), (13, "double"),
            (14, "string"), (15, "object"), (22, "TypedReference"),
            (24, "IntPtr"), (25, "UIntPtr"),
        ];

        for i in 0..effective_count {
            // Read the pointer from the array
            let ptr_entry_off = types_ptr_array_foff + i * ptr_size;
            if ptr_entry_off + ptr_size > bytes.len() {
                break;
            }
            let type_struct_va = if is_64 {
                crate::rva_resolver::read_u64(bytes, ptr_entry_off, is_le)
            } else {
                crate::rva_resolver::read_u32(bytes, ptr_entry_off, is_le) as u64
            };
            if type_struct_va == 0 {
                continue;
            }
            let type_foff = match elf_info.vaddr_to_file_offset(type_struct_va) {
                Some(o) => o as usize,
                None => continue,
            };
            if type_foff + ptr_size + 4 > bytes.len() {
                continue;
            }

            // Read type kind from bitfield
            let type_kind = bytes[type_foff + type_kind_offset];
            // Read data from union at offset +0
            let type_data = if is_64 {
                crate::rva_resolver::read_u64(bytes, type_foff + data_offset, is_le) as usize
            } else {
                crate::rva_resolver::read_u32(bytes, type_foff + data_offset, is_le) as usize
            };

            let name = match type_kind {
                // Primitives: 1-15, TYPEDBYREF(22), IntPtr(24), UIntPtr(25)
                1..=15 | 22 | 24 | 25 => {
                    primitive_names.iter()
                        .find(|(k, _)| *k == type_kind)
                        .map(|(_, n)| n.to_string())
                }
                // CLASS(0x10) / VALUETYPE(0x11) — data = TypeDefinitionIndex
                0x10 | 0x11 => td_names.get(&type_data).cloned(),
                // PTR(0x12) — data = Il2CppType*
                0x12 => {
                    let inner = Self::resolve_type_from_ptr(
                        bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size
                    );
                    Some(format!("{}*", inner))
                }
                // SZARRAY(0x14) — data = Il2CppType*
                0x14 => {
                    let inner = Self::resolve_type_from_ptr(
                        bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size
                    );
                    Some(format!("{}[]", inner))
                }
                // ARRAY(0x15) — data = Il2CppArrayType*
                0x15 => {
                    let inner = Self::resolve_type_from_ptr(
                        bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size
                    );
                    Some(format!("{}[...]", inner))
                }
                // GENERICINST(0x1C) — data = Il2CppGenericClass*
                0x1C => Some(format!("GENERICINST_{}", type_data)),
                // VAR(0x13) / MVAR(0x1E) — generic parameters
                0x13 => Some(format!("!{}", type_data)),
                0x1E => Some(format!("!!{}", type_data)),
                _ => None,
            };

            if let Some(n) = name {
                map.insert(i, n);
            }
        }

        debug_log.push(format!("Il2CppType resolved: {} types (of {} in array, effective={})", map.len(), types_count, effective_count));
        // Log some sample resolved entries
        let mut sample_keys: Vec<usize> = map.keys().copied().collect();
        sample_keys.sort();
        for &k in sample_keys.iter().take(5) {
            debug_log.push(format!("  type[{}] = {}", k, map.get(&k).unwrap()));
        }
        if sample_keys.len() > 5 {
            debug_log.push(format!("  ... max key = {}", sample_keys.last().unwrap()));
        }

        Some(map)
    }

    /// Resolve a type name from an Il2CppType* pointer (used for PTR/ARRAY inner types).
    fn resolve_type_from_ptr(
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        type_ptr_va: usize,
        type_kind_offset: usize,
        data_offset: usize,
        td_names: &std::collections::HashMap<usize, String>,
        is_64: bool,
        is_le: bool,
        ptr_size: usize,
    ) -> String {
        if type_ptr_va == 0 {
            return "?".to_string();
        }
        let foff = match elf_info.vaddr_to_file_offset(type_ptr_va as u64) {
            Some(o) => o as usize,
            None => return format!("T@0x{:x}", type_ptr_va),
        };
        if foff + ptr_size + 4 > lib_bytes.len() {
            return format!("T@0x{:x}", type_ptr_va);
        }
        let kind = lib_bytes[foff + type_kind_offset];
        let data = if is_64 {
            crate::rva_resolver::read_u64(lib_bytes, foff + data_offset, is_le) as usize
        } else {
            crate::rva_resolver::read_u32(lib_bytes, foff + data_offset, is_le) as usize
        };
        match kind {
            1 => "void".to_string(),
            2 => "bool".to_string(),
            3 => "char".to_string(),
            4 => "sbyte".to_string(),
            5 => "byte".to_string(),
            6 => "short".to_string(),
            7 => "ushort".to_string(),
            8 => "int".to_string(),
            9 => "uint".to_string(),
            10 => "long".to_string(),
            11 => "ulong".to_string(),
            12 => "float".to_string(),
            13 => "double".to_string(),
            14 => "string".to_string(),
            15 => "object".to_string(),
            0x10 | 0x11 => {
                td_names.get(&data).cloned().unwrap_or_else(|| format!("T{}", data))
            }
            0x12 => {
                let inner = Self::resolve_type_from_ptr(
                    lib_bytes, elf_info, data, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size
                );
                format!("{}*", inner)
            }
            0x14 => {
                let inner = Self::resolve_type_from_ptr(
                    lib_bytes, elf_info, data, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size
                );
                format!("{}[]", inner)
            }
            _ => format!("T{}(kind={})", data, kind),
        }
    }

    /// Find the types array pointer and count in the Il2CppMetadataRegistration struct.
    /// Uses known struct offsets first, then falls back to heuristic scan.
    fn find_types_in_metadata_reg(
        lib_bytes: &[u8],
        struct_foff: usize,
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        is_le: bool,
        ptr_size: usize,
    ) -> Option<(u64, usize)> {
        let expected_count = metadata.types.len();
        let struct_size = if elf_info.is_64bit { 256 } else { 128 };
        let end = (struct_foff + struct_size).min(lib_bytes.len());

        // Try known offsets for Il2CppMetadataRegistration.types / typesCount
        // Layout varies by version, try common offsets:
        // 64-bit: types at +48, typesCount at +56 (v29-v31)
        // 32-bit: types at +24, typesCount at +28
        let known_offsets: &[(usize, usize)] = if elf_info.is_64bit {
            &[(56, 48), (48, 56), (40, 32), (32, 40)]  // (count_off, ptr_off)
        } else {
            &[(28, 24), (24, 28), (20, 16), (16, 20)]
        };

        for &(count_off, ptr_off) in known_offsets {
            if struct_foff + count_off + ptr_size > lib_bytes.len() { continue; }
            if struct_foff + ptr_off + ptr_size > lib_bytes.len() { continue; }

            let count = if elf_info.is_64bit {
                crate::rva_resolver::read_u64(lib_bytes, struct_foff + count_off, is_le) as usize
            } else {
                crate::rva_resolver::read_u32(lib_bytes, struct_foff + count_off, is_le) as usize
            };
            let ptr = if elf_info.is_64bit {
                crate::rva_resolver::read_u64(lib_bytes, struct_foff + ptr_off, is_le)
            } else {
                crate::rva_resolver::read_u32(lib_bytes, struct_foff + ptr_off, is_le) as u64
            };

            if count > 0 && count < expected_count * 2 && count > expected_count / 2
                && ptr > 0x10000 && elf_info.vaddr_to_file_offset(ptr).is_some()
            {
                return Some((ptr, count));
            }
        }

        // Fallback: scan struct for any (count, pointer) or (pointer, count) pair
        let mut offset = struct_foff;
        while offset + ptr_size * 2 <= end {
            // Try (count, pointer)
            let val_a = if elf_info.is_64bit {
                crate::rva_resolver::read_u64(lib_bytes, offset, is_le) as usize
            } else {
                crate::rva_resolver::read_u32(lib_bytes, offset, is_le) as usize
            };
            let val_b = if elf_info.is_64bit {
                crate::rva_resolver::read_u64(lib_bytes, offset + ptr_size, is_le)
            } else {
                crate::rva_resolver::read_u32(lib_bytes, offset + ptr_size, is_le) as u64
            };

            // Check (count=a, pointer=b)
            if val_a > 0 && val_a < expected_count * 2 && val_a > expected_count / 2
                && val_b > 0x10000 && elf_info.vaddr_to_file_offset(val_b).is_some()
            {
                return Some((val_b, val_a));
            }
            // Check (pointer=a, count=b)
            if val_b > 0 && (val_b as usize) < expected_count * 2 && (val_b as usize) > expected_count / 2
                && val_a > 0x10000 && elf_info.vaddr_to_file_offset(val_a as u64).is_some()
            {
                return Some((val_a as u64, val_b as usize));
            }
            offset += ptr_size;
        }
        None
    }

    /// Scan all non-executable data segments for the types array pattern.
    /// Uses known struct offsets and validates by dereferencing the types pointer.
    fn find_types_by_scan(
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        is_le: bool,
        ptr_size: usize,
    ) -> Option<(u64, usize)> {
        let expected_count = metadata.types.len();

        // Scan all non-executable load segments (not just .data.rel.ro)
        let data_segments: Vec<_> = elf_info
            .load_segments()
            .into_iter()
            .filter(|s| (s.flags & 0x1) == 0 && s.filesz > 0)
            .collect();

        // Known offsets for types/typesCount in Il2CppMetadataRegistration
        let count_offsets: &[usize] = if elf_info.is_64bit {
            &[56, 48, 40, 32]
        } else {
            &[28, 24, 20, 16]
        };
        let ptr_offsets: &[usize] = if elf_info.is_64bit {
            &[48, 56, 32, 40]
        } else {
            &[24, 28, 16, 20]
        };

        for seg in &data_segments {
            let seg_start = seg.offset as usize;
            let seg_end = (seg_start + seg.filesz as usize).min(lib_bytes.len());
            if seg_end - seg_start < 64 {
                continue;
            }

            let mut pos = seg_start;
            while pos + 64 <= seg_end {
                // Try known offset pairs
                for (&coff, &poff) in count_offsets.iter().zip(ptr_offsets.iter()) {
                    if pos + coff + ptr_size > lib_bytes.len() || pos + poff + ptr_size > lib_bytes.len() {
                        continue;
                    }
                    let count = if elf_info.is_64bit {
                        crate::rva_resolver::read_u64(lib_bytes, pos + coff, is_le) as usize
                    } else {
                        crate::rva_resolver::read_u32(lib_bytes, pos + coff, is_le) as usize
                    };
                    let ptr = if elf_info.is_64bit {
                        crate::rva_resolver::read_u64(lib_bytes, pos + poff, is_le)
                    } else {
                        crate::rva_resolver::read_u32(lib_bytes, pos + poff, is_le) as u64
                    };

                    if count == 0 || count < expected_count / 2 || count > expected_count * 2 {
                        continue;
                    }
                    if ptr < 0x10000 {
                        continue;
                    }
                    let arr_foff = match elf_info.vaddr_to_file_offset(ptr) {
                        Some(o) => o as usize,
                        None => continue,
                    };

                    // Validate: dereference first few entries and check they point to
                    // valid Il2CppType structs (type_kind byte should be 1-30)
                    let check_count = std::cmp::min(count, 5);
                    let mut valid = 0usize;
                    for j in 0..check_count {
                        let entry_off = arr_foff + j * ptr_size;
                        if entry_off + ptr_size > lib_bytes.len() { break; }
                        let type_ptr = if elf_info.is_64bit {
                            crate::rva_resolver::read_u64(lib_bytes, entry_off, is_le)
                        } else {
                            crate::rva_resolver::read_u32(lib_bytes, entry_off, is_le) as u64
                        };
                        if type_ptr < 0x10000 { continue; }
                        let type_foff = match elf_info.vaddr_to_file_offset(type_ptr) {
                            Some(o) => o as usize,
                            None => continue,
                        };
                        let kind_off = if is_le { ptr_size + 2 } else { ptr_size + 1 };
                        if type_foff + kind_off + 1 > lib_bytes.len() { continue; }
                        let kind = lib_bytes[type_foff + kind_off];
                        if kind >= 1 && kind <= 30 {
                            valid += 1;
                        }
                    }
                    if valid >= 3 {
                        return Some((ptr, count));
                    }
                }
                pos += ptr_size;
            }
        }
        None
    }

    pub fn write(
        &self,
        metadata: &MetadataParseResult,
        output_path: &str,
        rva_result: &RvaResult,
    ) -> std::io::Result<usize> {
        self.write_with_elf(metadata, output_path, rva_result, None, None, &mut Vec::new())
    }

    pub fn write_with_elf(
        &self,
        metadata: &MetadataParseResult,
        output_path: &str,
        rva_result: &RvaResult,
        elf_info: Option<&ElfInfo>,
        lib_bytes: Option<&[u8]>,
        debug_log: &mut Vec<String>,
    ) -> std::io::Result<usize> {
        let file = std::fs::File::create(output_path)?;
        let mut w = BufWriter::new(file);
        let type_names = Self::build_type_name_map(metadata, elf_info, lib_bytes, debug_log);

        writeln!(w, "// Generated by IL2CPP X Rust metadata dumper")?;
        writeln!(w, "// Metadata version: {}", metadata.version)?;
        writeln!(
            w,
            "// RVA resolution: {}/{} methods ({}%)",
            rva_result.resolved_count(),
            rva_result.total_methods,
            (rva_result.resolution_rate() * 100.0) as u32
        )?;
        writeln!(w)?;

        let valid_images: Vec<&MetadataImage> = metadata
            .images
            .iter()
            .filter(|img| {
                img.type_count > 0
                    && img.type_start + img.type_count <= metadata.types.len()
            })
            .collect();

        let mut written: usize = 0;
        let mut seen = std::collections::HashSet::new();

        // Write types grouped by valid images
        for image in &valid_images {
            writeln!(w, "// Image {}: {}", image.index, safe_comment(&image.name))?;
            let start = image.type_start;
            let end = std::cmp::min(start + image.type_count, metadata.types.len());
            if start < end {
                for type_idx in start..end {
                    if !seen.insert(type_idx) {
                        continue;
                    }
                    let type_def = &metadata.types[type_idx];
                    if type_def.name.is_empty() {
                        continue;
                    }
                    self.write_type(&mut w, metadata, type_def, rva_result, &type_names)?;
                    written += 1;
                }
            }
        }

        // Write types not covered by any image
        let uncovered: Vec<usize> = (0..metadata.types.len())
            .filter(|i| !seen.contains(i))
            .collect();
        if !uncovered.is_empty() {
            writeln!(w, "// Uncovered types ({} not in any image)", uncovered.len())?;
            for type_idx in uncovered {
                let type_def = &metadata.types[type_idx];
                if type_def.name.is_empty() {
                    continue;
                }
                self.write_type(&mut w, metadata, type_def, rva_result, &type_names)?;
                written += 1;
            }
        }

        w.flush()?;
        Ok(written)
    }

    fn write_type(
        &self,
        w: &mut BufWriter<std::fs::File>,
        metadata: &MetadataParseResult,
        type_def: &MetadataTypeDefinition,
        rva_result: &RvaResult,
        type_names: &std::collections::HashMap<usize, String>,
    ) -> std::io::Result<()> {
        let namespace = sanitize_namespace(&type_def.namespace_name);
        let indent;
        if !namespace.is_empty() {
            writeln!(w, "namespace {}", namespace)?;
            writeln!(w, "{{")?;
            indent = "    ";
        } else {
            indent = "";
        }

        writeln!(w, "{}// TypeDefIndex: {}", indent, type_def.index)?;

        if self.include_rva_info {
            if let Some(image) = metadata
                .images
                .iter()
                .find(|img| type_def.index >= img.type_start && type_def.index < img.type_start + img.type_count)
            {
                writeln!(w, "{}// Image: {}", indent, image.name)?;
            }
        }

        writeln!(
            w,
            "{}public class {}",
            indent,
            sanitize_identifier(&type_def.name)
        )?;

        if self.include_inheritance {
            if let Some(image) = metadata
                .images
                .iter()
                .find(|img| type_def.index >= img.type_start && type_def.index < img.type_start + img.type_count)
            {
                writeln!(w, "{}    // Assembly: {}", indent, sanitize_identifier(&image.name))?;
            }
        }

        writeln!(w, "{}{{", indent)?;

        if self.include_rva_info {
            writeln!(
                w,
                "{}    // Fields: {}, Methods: {}, Properties: {}",
                indent, type_def.field_count, type_def.method_count, type_def.property_count
            )?;
            if let Some(type_rva) = rva_result.type_rvas.get(&type_def.index) {
                writeln!(
                    w,
                    "{}    // Resolved RVAs: {}/{}",
                    indent,
                    type_rva.methods.len(),
                    type_def.method_count
                )?;
            }
            writeln!(w)?;
        }

        // Fields
        self.write_fields(w, metadata, type_def, &format!("{}    ", indent), type_names)?;

        // Methods
        self.write_methods(w, metadata, type_def, &format!("{}    ", indent), rva_result, type_names)?;

        writeln!(w, "{}}}", indent)?;
        if !namespace.is_empty() {
            writeln!(w, "}}")?;
        }
        writeln!(w)?;
        Ok(())
    }

    fn write_fields(
        &self,
        w: &mut BufWriter<std::fs::File>,
        metadata: &MetadataParseResult,
        type_def: &MetadataTypeDefinition,
        indent: &str,
        type_names: &std::collections::HashMap<usize, String>,
    ) -> std::io::Result<()> {
        let start = type_def.field_start;
        if type_def.field_count == 0 || start >= metadata.fields.len() {
            return Ok(());
        }
        let end = std::cmp::min(start + type_def.field_count, metadata.fields.len());
        if start >= end {
            return Ok(());
        }

        writeln!(w, "{}// Fields", indent)?;
        for field_idx in start..end {
            let field = &metadata.fields[field_idx];
            let default_name = format!("field_{}", field_idx);
            let name = sanitize_identifier(if field.name.is_empty() {
                &default_name
            } else {
                &field.name
            });
            let type_name = resolve_type_name(field.type_index, type_names);
            writeln!(
                w,
                "{}public {} {};",
                indent, type_name, name
            )?;
        }
        writeln!(w)?;
        Ok(())
    }

    fn write_methods(
        &self,
        w: &mut BufWriter<std::fs::File>,
        metadata: &MetadataParseResult,
        type_def: &MetadataTypeDefinition,
        indent: &str,
        rva_result: &RvaResult,
        type_names: &std::collections::HashMap<usize, String>,
    ) -> std::io::Result<()> {
        let start = type_def.method_start;
        let end = std::cmp::min(start + type_def.method_count, metadata.methods.len());
        if start >= end {
            return Ok(());
        }

        writeln!(w, "{}// Methods", indent)?;
        for method_idx in start..end {
            let method = &metadata.methods[method_idx];
            let default_name = format!("method_{}", method_idx);
            let name = sanitize_method_name(if method.name.is_empty() {
                &default_name
            } else {
                &method.name
            });
            let params = build_parameter_list(metadata, method, type_names);
            let return_type = resolve_type_name(method.return_type, type_names);
            let rva_comment = if let Some(rva) = rva_result.method_rvas.get(&method_idx) {
                format!(" /* RVA: {}, Size: {} */", rva.hex_rva(), rva.hex_size())
            } else {
                String::new()
            };
            writeln!(
                w,
                "{}public {} {}({}) {{ }}{}",
                indent, return_type, name, params, rva_comment
            )?;
        }
        writeln!(w)?;
        Ok(())
    }
}

fn build_parameter_list(
    metadata: &MetadataParseResult,
    method: &MetadataMethodDefinition,
    type_names: &std::collections::HashMap<usize, String>,
) -> String {
    let start = method.parameter_start;
    let count = method.parameter_count;
    if count == 0 || start >= metadata.parameters.len() {
        return String::new();
    }
    let end = std::cmp::min(start + count, metadata.parameters.len());
    if start >= end {
        return String::new();
    }

    let parts: Vec<String> = (start..end)
        .map(|idx| {
            let param = &metadata.parameters[idx];
            let default_name = format!("param_{}", idx);
            let name = sanitize_identifier(if param.name.is_empty() {
                &default_name
            } else {
                &param.name
            });
            let type_name = resolve_type_name(param.type_index, type_names);
            format!("{} {}", type_name, name)
        })
        .collect();
    parts.join(", ")
}

fn sanitize_namespace(value: &str) -> String {
    value
        .split('.')
        .filter_map(|part| {
            let s = sanitize_identifier(part);
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn sanitize_method_name(value: &str) -> String {
    match value {
        ".ctor" => "ctor".to_string(),
        ".cctor" => "cctor".to_string(),
        _ => sanitize_identifier(value),
    }
}

fn sanitize_identifier(value: &str) -> String {
    if value.is_empty() {
        return "_".to_string();
    }
    let mut result = String::new();
    for (i, ch) in value.chars().enumerate() {
        let valid = ch == '_' || ch.is_alphanumeric();
        let output = if valid { ch } else { '_' };
        if i == 0 && output.is_ascii_digit() {
            result.push('_');
        }
        result.push(output);
    }
    let trimmed = result.trim_matches('_').to_string();
    if trimmed.is_empty() || CSHARP_KEYWORDS.iter().any(|&k| k == trimmed.as_str()) {
        format!("_{}", if trimmed.is_empty() { "item" } else { &trimmed })
    } else {
        trimmed
    }
}

fn resolve_type_name(
    type_index: usize,
    type_names: &std::collections::HashMap<usize, String>,
) -> String {
    if let Some(name) = type_names.get(&type_index) {
        return name.clone();
    }
    // Common IL2CPP type indices for primitives (approximate)
    match type_index {
        1 => "void".to_string(),
        2 => "bool".to_string(),
        3 => "char".to_string(),
        4 => "sbyte".to_string(),
        5 => "byte".to_string(),
        6 => "short".to_string(),
        7 => "ushort".to_string(),
        8 => "int".to_string(),
        9 => "uint".to_string(),
        10 => "long".to_string(),
        11 => "ulong".to_string(),
        12 => "float".to_string(),
        13 => "double".to_string(),
        14 => "string".to_string(),
        _ => format!("T{}", type_index),
    }
}

fn safe_comment(value: &str) -> String {
    value.replace('\n', " ").replace('\r', " ")
}

const CSHARP_KEYWORDS: &[&str] = &[
    "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
    "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
    "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
    "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock",
    "long", "namespace", "new", "null", "object", "operator", "out", "override", "params",
    "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short",
    "sizeof", "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true",
    "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual",
    "void", "volatile", "while",
];
