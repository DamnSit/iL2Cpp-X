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

        // Try multiple strategies to find the types array:
        // 1. Symbol-based: find g_MetadataRegistration symbol
        // 2. Pattern search: search for types_count value in data segments
        // 3. Full scan: scan data segments for valid Il2CppType** arrays
        let mut found: Option<(u64, usize)> = None;

        // Strategy 1: Symbol-based
        if found.is_none() {
            let meta_reg_addr = elf_info.find_symbol("g_MetadataRegistration")
                .or_else(|| elf_info.find_symbol("g_MetadataRegistrationPtr"))
                .map(|s| s.value);
            debug_log.push(format!("g_MetadataRegistration: {:?}", meta_reg_addr));

            if let Some(addr) = meta_reg_addr {
                if let Some(foff) = elf_info.vaddr_to_file_offset(addr) {
                    debug_log.push(format!("MetadataReg struct at file offset 0x{:x}", foff));
                    match Self::find_types_in_metadata_reg(bytes, foff as usize, elf_info, metadata, is_le, ptr_size) {
                        Some(r) => {
                            debug_log.push(format!("find_types_in_metadata_reg: va=0x{:x} count={}", r.0, r.1));
                            found = Some(r);
                        }
                        None => {
                            debug_log.push("find_types_in_metadata_reg returned None".to_string());
                        }
                    }
                }
            }
        }

        // Strategy 2: Pattern search — DISABLED
        // The pattern search finds too many false positives because random data
        // in .data.rel.ro can match 4 consecutive (count, pointer) pairs.
        // The scan (strategy 3) with 95% probe threshold and stride-based scoring
        // is much more reliable.
        if found.is_none() {
            debug_log.push("Pattern search disabled (scan handles this)".to_string());
        }

        // Strategy 3: Full scan
        if found.is_none() {
            debug_log.push("Trying full scan".to_string());
            match Self::find_types_by_scan(bytes, elf_info, metadata, is_le, ptr_size, debug_log) {
                Some(r) => {
                    debug_log.push(format!("find_types_by_scan: va=0x{:x} count={}", r.0, r.1));
                    found = Some(r);
                }
                None => {
                    debug_log.push("find_types_by_scan returned None".to_string());
                }
            }
        }

        let (types_array_va, types_count) = found?;

        // types_array_va points to array of Il2CppType* pointers
        let types_ptr_array_foff = elf_info.vaddr_to_file_offset(types_array_va)? as usize;
        debug_log.push(format!("types_array_va=0x{:x} foff=0x{:x} count={}", types_array_va, types_ptr_array_foff, types_count));

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
        let primitive_names: [(u8, &str); 30] = [
            (0x01, "void"), (0x02, "bool"), (0x03, "char"), (0x04, "sbyte"), (0x05, "byte"),
            (0x06, "short"), (0x07, "ushort"), (0x08, "int"), (0x09, "uint"),
            (0x0A, "long"), (0x0B, "ulong"), (0x0C, "float"), (0x0D, "double"),
            (0x0E, "string"), (0x0F, "void*"), (0x10, "ref"),
            (0x11, "ValueType"), (0x12, "class"), (0x13, "var"),
            (0x14, "array"), (0x15, "GenericInst"), (0x16, "TypedReference"),
            (0x18, "IntPtr"), (0x19, "UIntPtr"),
            (0x1B, "FnPtr"), (0x1C, "object"), (0x1D, "SZArray"),
            (0x1E, "MVar"), (0x1F, "CModReqd"), (0x20, "CModOpt"),
        ];

        // Compute image_base and td_size for CLASS/VALUETYPE v27+ type handle resolution.
        // For v27+, datapoint is a VA to the TypeDef entry in metadata.
        // image_base = VA of TypeDef[0], td_size = stride between consecutive TypeDefs.
        // Find two CLASS/VALUETYPE entries with large data to compute these.
        let mut image_base: usize = 0;
        let mut td_size: usize = 0;
        {
            let mut prev_large_data: Option<(usize, usize)> = None; // (array_index, data_value)
            let td_stride = 88usize; // v31 TypeDef stride — used as fallback
            for i in 0..types_count {
                let ptr_entry_off = types_ptr_array_foff + i * ptr_size;
                if ptr_entry_off + ptr_size > bytes.len() { break; }
                let type_struct_va = if is_64 {
                    crate::rva_resolver::read_u64(bytes, ptr_entry_off, is_le)
                } else {
                    crate::rva_resolver::read_u32(bytes, ptr_entry_off, is_le) as u64
                };
                if type_struct_va == 0 { continue; }
                let type_foff = match elf_info.vaddr_to_file_offset(type_struct_va) {
                    Some(o) => o as usize,
                    None => continue,
                };
                if type_foff + type_kind_offset + 1 > bytes.len() { continue; }
                let kind = bytes[type_foff + type_kind_offset];
                if kind != 0x11 && kind != 0x12 { continue; }
                let data = if is_64 {
                    crate::rva_resolver::read_u64(bytes, type_foff, is_le) as usize
                } else {
                    crate::rva_resolver::read_u32(bytes, type_foff, is_le) as usize
                };
                if data < 0x10000 { continue; }
                if let Some((prev_idx, prev_data)) = prev_large_data {
                    let idx_diff = i.saturating_sub(prev_idx);
                    if idx_diff > 0 {
                        td_size = (data - prev_data) / idx_diff;
                        image_base = prev_data - prev_idx * td_size;
                        debug_log.push(format!("  image_base=0x{:x} td_size={} (from entries {} and {})", image_base, td_size, prev_idx, i));
                        break;
                    }
                }
                prev_large_data = Some((i, data));
            }
            // Fallback: if we found one CLASS/VALUETYPE with large data but not two,
            // use the known TypeDef stride (88 for v31) to compute image_base.
            if image_base == 0 {
                if let Some((idx, data_val)) = prev_large_data {
                    if data_val >= 0x10000 && td_stride > 0 {
                        image_base = data_val - idx * td_stride;
                        td_size = td_stride;
                        debug_log.push(format!("  image_base=0x{:x} td_size={} (fallback from entry {}, known stride)", image_base, td_size, idx));
                    }
                }
            }
            if image_base == 0 {
                debug_log.push("  WARNING: could not compute image_base/td_size — CLASS/VALUETYPE types will show as T-indexes".to_string());
            }
        }

        for i in 0..types_count {
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
                // Primitives (Il2CppTypeEnum):
                // 0x01=Void, 0x02=Boolean, 0x03=Char, 0x04=I1, 0x05=U1,
                // 0x06=I2, 0x07=U2, 0x08=I4, 0x09=U4, 0x0A=I8, 0x0B=U8,
                // 0x0C=R4, 0x0D=R8, 0x0E=String,
                // 0x16=TypedByRef, 0x18=IntPtr, 0x19=UIntPtr
                0x01 => Some("void".to_string()),
                0x02 => Some("bool".to_string()),
                0x03 => Some("char".to_string()),
                0x04 => Some("sbyte".to_string()),
                0x05 => Some("byte".to_string()),
                0x06 => Some("short".to_string()),
                0x07 => Some("ushort".to_string()),
                0x08 => Some("int".to_string()),
                0x09 => Some("uint".to_string()),
                0x0A => Some("long".to_string()),
                0x0B => Some("ulong".to_string()),
                0x0C => Some("float".to_string()),
                0x0D => Some("double".to_string()),
                0x0E => Some("string".to_string()),
                0x16 => Some("TypedReference".to_string()),
                0x18 => Some("IntPtr".to_string()),
                0x19 => Some("UIntPtr".to_string()),
                // VALUETYPE(0x11) / CLASS(0x12) — data = TypeDefinitionIndex or type handle
                0x11 | 0x12 => {
                    Self::resolve_class_type(type_data, &td_names, elf_info, bytes, is_le, image_base, td_size)
                }
                // PTR(0x0F) — data = Il2CppType*
                0x0F => {
                    let inner = Self::resolve_type_from_ptr(
                        bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size, image_base, td_size, 0
                    );
                    Some(format!("{}*", inner))
                }
                // ByRef(0x10) — data = Il2CppType*
                0x10 => {
                    let inner = Self::resolve_type_from_ptr(
                        bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size, image_base, td_size, 0
                    );
                    Some(format!("{}&", inner))
                }
                // SZARRAY(0x1D) — data = Il2CppType*
                0x1D => {
                    let inner = Self::resolve_type_from_ptr(
                        bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size, image_base, td_size, 0
                    );
                    Some(format!("{}[]", inner))
                }
                // ARRAY(0x14) — data = Il2CppArrayType*, not Il2CppType*
                // Il2CppArrayType: +0: etype(Il2CppType*), +ptr_size: rank(u8)
                0x14 => {
                    if let Some(arr_foff) = elf_info.vaddr_to_file_offset(type_data as u64) {
                        let arr_foff = arr_foff as usize;
                        if arr_foff + ptr_size <= bytes.len() {
                            let etype_ptr = if is_64 {
                                crate::rva_resolver::read_u64(bytes, arr_foff, is_le) as usize
                            } else {
                                crate::rva_resolver::read_u32(bytes, arr_foff, is_le) as usize
                            };
                            let inner = Self::resolve_type_from_ptr(
                                bytes, elf_info, etype_ptr, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size, image_base, td_size, 0
                            );
                            let rank = if arr_foff + ptr_size + 1 <= bytes.len() { bytes[arr_foff + ptr_size] } else { 1 };
                            if rank > 1 {
                                Some(format!("{}[{}]", inner, ",".repeat(rank as usize - 1)))
                            } else {
                                Some(format!("{}[...]", inner))
                            }
                        } else {
                            Some("?[]".to_string())
                        }
                    } else {
                        Some("?[]".to_string())
                    }
                }
                // GENERICINST(0x15) — data = Il2CppGenericClass*
                0x15 => {
                    Self::resolve_generic_inst(bytes, elf_info, type_data, type_kind_offset, data_offset, &td_names, is_64, is_le, ptr_size, image_base, td_size, 0)
                }
                // VAR(0x13) / MVAR(0x1E) — generic parameters
                0x13 => Some(format!("!{}", type_data)),
                0x1E => Some(format!("!!{}", type_data)),
                // OBJECT(0x1C)
                0x1C => Some("object".to_string()),
                _ => None,
            };

            if let Some(n) = name {
                map.insert(i, n);
            }
        }

        debug_log.push(format!("Il2CppType resolved: {} types (of {} in array)", map.len(), types_count));
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

    /// Resolve CLASS/VALUETYPE type name from datapoint.
    /// For metadata v27+, datapoint is a type handle (VA pointer) to the TypeDef entry
    /// in the metadata blob. Compute index = (datapoint - image_base) / td_size.
    fn resolve_class_type(
        type_data: usize,
        td_names: &std::collections::HashMap<usize, String>,
        elf_info: &ElfInfo,
        lib_bytes: &[u8],
        is_le: bool,
        image_base: usize,
        td_size: usize,
    ) -> Option<String> {
        if type_data == 0 {
            return None;
        }
        // Small values are direct TypeDef indices
        if type_data < 0x10000 {
            return td_names.get(&type_data).cloned();
        }
        // Large values are type handles (VA pointers) to TypeDef entries in metadata.
        // Compute TypeDefIndex = (datapoint - image_base) / td_size
        if image_base > 0 && td_size > 0 && type_data >= image_base {
            let index = (type_data - image_base) / td_size;
            if let Some(name) = td_names.get(&index) {
                return Some(name.clone());
            }
        }
        // Last resort: return T{data} format
        Some(format!("T{}", type_data))
    }

    /// Resolve GENERICINST type from Il2CppGenericClass* pointer.
    /// Il2CppGenericClass layout (64-bit):
    ///   +0: typeDefinitionIndex (i32) or type handle pointer
    ///   +8: context (Il2CppGenericContext)
    ///         +0: class_inst (Il2CppGenericInst*)
    ///         +8: method_inst (Il2CppGenericInst*)
    /// Il2CppGenericInst layout:
    ///   +0: type_argc (usize)
    ///   +ptr_size: type_argv (Il2CppType*[])
    fn resolve_generic_inst(
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        generic_class_ptr: usize,
        type_kind_offset: usize,
        data_offset: usize,
        td_names: &std::collections::HashMap<usize, String>,
        is_64: bool,
        is_le: bool,
        ptr_size: usize,
        image_base: usize,
        td_size: usize,
        depth: usize,
    ) -> Option<String> {
        if generic_class_ptr == 0 {
            return None;
        }
        let foff = match elf_info.vaddr_to_file_offset(generic_class_ptr as u64) {
            Some(o) => o as usize,
            None => return Some(format!("GENERICINST@0x{:x}", generic_class_ptr)),
        };
        if foff + ptr_size * 3 > lib_bytes.len() {
            return Some(format!("GENERICINST@0x{:x}", generic_class_ptr));
        }
        // +0: typeDefinitionIndex or type handle
        let first_field = if is_64 {
            crate::rva_resolver::read_u64(lib_bytes, foff, is_le) as usize
        } else {
            crate::rva_resolver::read_u32(lib_bytes, foff, is_le) as usize
        };

        // Resolve base type name
        let base_name = if first_field < 0x10000 {
            td_names.get(&first_field).cloned().unwrap_or_else(|| format!("T{}", first_field))
        } else {
            Self::resolve_class_type(first_field, td_names, elf_info, lib_bytes, is_le, image_base, td_size)
            .unwrap_or_else(|| format!("T{}", first_field))
        };

        // +ptr_size: context (Il2CppGenericContext)
        // context.class_inst at +0, context.method_inst at +ptr_size
        let ctx_foff = foff + ptr_size;
        if ctx_foff + ptr_size * 2 > lib_bytes.len() {
            return Some(format!("{}<>", base_name));
        }

        // Try class_inst first, then method_inst
        let inst_ptr = if is_64 {
            let ci = crate::rva_resolver::read_u64(lib_bytes, ctx_foff, is_le);
            if ci != 0 { ci as usize } else {
                crate::rva_resolver::read_u64(lib_bytes, ctx_foff + ptr_size, is_le) as usize
            }
        } else {
            let ci = crate::rva_resolver::read_u32(lib_bytes, ctx_foff, is_le);
            if ci != 0 { ci as usize } else {
                crate::rva_resolver::read_u32(lib_bytes, ctx_foff + ptr_size, is_le) as usize
            }
        };

        if inst_ptr == 0 {
            return Some(format!("{}<>", base_name));
        }

        // Read Il2CppGenericInst: +0: type_argc, +ptr_size: type_argv[]
        let gi_foff = match elf_info.vaddr_to_file_offset(inst_ptr as u64) {
            Some(o) => o as usize,
            None => return Some(format!("{}<>", base_name)),
        };
        if gi_foff + ptr_size * 2 > lib_bytes.len() {
            return Some(format!("{}<>", base_name));
        }
        let type_argc = if is_64 {
            crate::rva_resolver::read_u64(lib_bytes, gi_foff, is_le) as usize
        } else {
            crate::rva_resolver::read_u32(lib_bytes, gi_foff, is_le) as usize
        };

        if type_argc == 0 || type_argc > 32 {
            return Some(format!("{}<>", base_name));
        }

        // Read type_argv pointers and resolve each
        let mut args = Vec::with_capacity(type_argc);
        for ai in 0..type_argc {
            let argv_off = gi_foff + ptr_size + ai * ptr_size;
            if argv_off + ptr_size > lib_bytes.len() { break; }
            let arg_ptr = if is_64 {
                crate::rva_resolver::read_u64(lib_bytes, argv_off, is_le) as usize
            } else {
                crate::rva_resolver::read_u32(lib_bytes, argv_off, is_le) as usize
            };
            let arg_name = Self::resolve_type_from_ptr(
                lib_bytes, elf_info, arg_ptr, type_kind_offset, data_offset,
                td_names, is_64, is_le, ptr_size, image_base, td_size, depth + 1
            );
            args.push(arg_name);
        }

        Some(format!("{}<{}>", base_name, args.join(", ")))
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
        image_base: usize,
        td_size: usize,
        depth: usize,
    ) -> String {
        if type_ptr_va == 0 || depth > 32 {
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
            0x01 => "void".to_string(),
            0x02 => "bool".to_string(),
            0x03 => "char".to_string(),
            0x04 => "sbyte".to_string(),
            0x05 => "byte".to_string(),
            0x06 => "short".to_string(),
            0x07 => "ushort".to_string(),
            0x08 => "int".to_string(),
            0x09 => "uint".to_string(),
            0x0A => "long".to_string(),
            0x0B => "ulong".to_string(),
            0x0C => "float".to_string(),
            0x0D => "double".to_string(),
            0x0E => "string".to_string(),
            0x1C => "object".to_string(),
            0x11 | 0x12 => {
                Self::resolve_class_type(data, td_names, elf_info, lib_bytes, is_le, image_base, td_size)
                    .unwrap_or_else(|| format!("T{}", data))
            }
            0x0F => {
                let inner = Self::resolve_type_from_ptr(
                    lib_bytes, elf_info, data, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size, image_base, td_size, depth + 1
                );
                format!("{}*", inner)
            }
            0x10 => {
                let inner = Self::resolve_type_from_ptr(
                    lib_bytes, elf_info, data, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size, image_base, td_size, depth + 1
                );
                format!("{}&", inner)
            }
            0x1D => {
                let inner = Self::resolve_type_from_ptr(
                    lib_bytes, elf_info, data, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size, image_base, td_size, depth + 1
                );
                format!("{}[]", inner)
            }
            // ARRAY(0x14) — data is Il2CppArrayType*, not Il2CppType*
            // Il2CppArrayType: +0: etype(Il2CppType*), +ptr_size: rank(u8), +ptr_size+1: numsizes, +ptr_size+2: numlobounds
            0x14 => {
                let arr_foff = match elf_info.vaddr_to_file_offset(data as u64) {
                    Some(o) => o as usize,
                    None => return format!("T@0x{:x}[...]", data),
                };
                if arr_foff + ptr_size <= lib_bytes.len() {
                    let etype_ptr = if is_64 {
                        crate::rva_resolver::read_u64(lib_bytes, arr_foff, is_le) as usize
                    } else {
                        crate::rva_resolver::read_u32(lib_bytes, arr_foff, is_le) as usize
                    };
                    let inner = Self::resolve_type_from_ptr(
                        lib_bytes, elf_info, etype_ptr, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size, image_base, td_size, depth + 1
                    );
                    // Read rank for multidimensional arrays
                    let rank = if arr_foff + ptr_size + 1 <= lib_bytes.len() { lib_bytes[arr_foff + ptr_size] } else { 1 };
                    if rank > 1 {
                        format!("{}[{}]", inner, ",".repeat(rank as usize - 1))
                    } else {
                        format!("{}[...]", inner)
                    }
                } else {
                    format!("?[]")
                }
            }
            0x15 => {
                Self::resolve_generic_inst(
                    lib_bytes, elf_info, data, type_kind_offset, data_offset, td_names, is_64, is_le, ptr_size, image_base, td_size, depth
                ).unwrap_or_else(|| format!("GENERICINST_{}", data))
            }
            0x13 => format!("!{}", data),
            0x1E => format!("!!{}", data),
            _ => format!("T{}(kind={})", data, kind),
        }
    }

    /// Find the types array pointer and count in the Il2CppMetadataRegistration struct.
    /// Uses known struct offsets first, then falls back to heuristic scan.
    /// Validates that the found array actually contains valid Il2CppType entries at
    /// metadata field type_index positions.
    fn find_types_in_metadata_reg(
        lib_bytes: &[u8],
        struct_foff: usize,
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        is_le: bool,
        ptr_size: usize,
    ) -> Option<(u64, usize)> {
        let expected_count = metadata.types.len();
        let type_kind_offset = if is_le { ptr_size + 2 } else { ptr_size + 1 };
        let struct_size = if elf_info.is_64bit { 256 } else { 128 };
        let end = (struct_foff + struct_size).min(lib_bytes.len());

        // Collect metadata field type indices for validation
        let mut meta_indices: Vec<usize> = Vec::new();
        for f in metadata.fields.iter().take(200) {
            if f.type_index > 0 && f.type_index < 200000 {
                meta_indices.push(f.type_index);
            }
        }
        for m in metadata.methods.iter().take(200) {
            if m.return_type > 0 && m.return_type < 200000 {
                meta_indices.push(m.return_type);
            }
        }
        meta_indices.sort_unstable();
        meta_indices.dedup();

        // Il2CppMetadataRegistration struct layout (pointer-sized fields):
        //   +48: types_count    +56: types (Il2CppType**)
        // 32-bit: +24/+28
        let known_offsets: &[(usize, usize)] = if elf_info.is_64bit {
            &[(48, 56), (56, 48), (40, 32), (32, 40)]  // (count_off, ptr_off)
        } else {
            &[(24, 28), (28, 24), (20, 16), (16, 20)]
        };

        for &(count_off, ptr_off) in known_offsets {
            if struct_foff + count_off + ptr_size > lib_bytes.len() { continue; }
            if struct_foff + ptr_off + ptr_size > lib_bytes.len() { continue; }

            let count = crate::rva_resolver::read_u32(lib_bytes, struct_foff + count_off, is_le) as usize;
            let ptr = if elf_info.is_64bit {
                crate::rva_resolver::read_u64(lib_bytes, struct_foff + ptr_off, is_le)
            } else {
                crate::rva_resolver::read_u32(lib_bytes, struct_foff + ptr_off, is_le) as u64
            };

            if count > 0 && count < expected_count * 8 && count > expected_count / 2
                && ptr > 0x10000
            {
                // Validate: entries at metadata field indices must be valid Il2CppType*
                if Self::validate_types_array(lib_bytes, elf_info, ptr, count, &meta_indices, type_kind_offset, is_le, ptr_size) {
                    return Some((ptr, count));
                }
            }
        }

        // Fallback: scan struct for any (count, pointer) or (pointer, count) pair
        let mut offset = struct_foff;
        while offset + ptr_size * 2 <= end {
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
            if val_a > 0 && val_a < expected_count * 8 && val_a > expected_count / 2
                && val_b > 0x10000
            {
                if Self::validate_types_array(lib_bytes, elf_info, val_b as u64, val_a, &meta_indices, type_kind_offset, is_le, ptr_size) {
                    return Some((val_b as u64, val_a));
                }
            }
            // Check (pointer=a, count=b)
            if val_b > 0 && (val_b as usize) < expected_count * 8 && (val_b as usize) > expected_count / 2
                && val_a > 0x10000
            {
                if Self::validate_types_array(lib_bytes, elf_info, val_a as u64, val_b as usize, &meta_indices, type_kind_offset, is_le, ptr_size) {
                    return Some((val_a as u64, val_b as usize));
                }
            }
            offset += ptr_size;
        }
        None
    }

    /// Validate that a candidate types array contains valid Il2CppType entries
    /// at metadata field/param type_index positions.
    fn validate_types_array(
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        array_va: u64,
        count: usize,
        meta_indices: &[usize],
        type_kind_offset: usize,
        is_le: bool,
        ptr_size: usize,
    ) -> bool {
        let arr_foff = match elf_info.vaddr_to_file_offset(array_va) {
            Some(o) => o as usize,
            None => return false,
        };
        if arr_foff + count * ptr_size > lib_bytes.len() {
            return false;
        }

        let check_limit = meta_indices.len().min(15);
        let mut matches = 0usize;
        let mut checked = 0usize;

        for &ti in meta_indices.iter().take(check_limit) {
            if ti >= count { continue; }
            checked += 1;
            let entry_off = arr_foff + ti * ptr_size;
            if entry_off + ptr_size > lib_bytes.len() { continue; }
            let type_ptr = crate::rva_resolver::read_pointer(lib_bytes, entry_off, ptr_size, is_le);
            if type_ptr == 0 || type_ptr < 0x10000 { continue; }
            let type_foff = match elf_info.vaddr_to_file_offset(type_ptr) {
                Some(o) => o as usize,
                None => continue,
            };
            if type_foff + type_kind_offset + 1 > lib_bytes.len() { continue; }
            let kind = lib_bytes[type_foff + type_kind_offset];
            if kind < 1 || kind > 0x1E { continue; }

            // For CLASS/VALUETYPE, data must look like a valid TypeDefIndex
            if kind == 0x11 || kind == 0x12 {
                let data = crate::rva_resolver::read_pointer(lib_bytes, type_foff, ptr_size, is_le) as i64;
                if data < 0 || data > 200000 {
                    continue;
                }
            }
            matches += 1;
        }

        checked >= 5 && matches * 10 >= checked * 8
    }

    /// Search for the types array by looking for types_count value in data segments.
    /// The MetadataRegistration struct has (count, pointer) pairs. We search for the
    /// known types_count value and check if the adjacent pointer is a valid types array.
    /// Search for MetadataRegistration by looking for (count, pointer) repeating
    /// pattern in raw (unpatched) bytes. Counts in .data.rel.ro are destroyed by
    /// relocations, so we search raw bytes for the structural pattern:
    /// 4+ consecutive pairs where even slots are small integers and odd slots are
    /// data VA pointers.
    fn find_types_by_pattern(
        raw_bytes: &[u8],
        patched_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        is_le: bool,
        ptr_size: usize,
        debug_log: &mut Vec<String>,
    ) -> Option<(u64, usize)> {
        let type_kind_offset = if is_le { ptr_size + 2 } else { ptr_size + 1 };
        let is_64 = elf_info.is_64bit;

        // Get data segment VA range for pointer validation
        let data_segs: Vec<_> = elf_info.load_segments().into_iter()
            .filter(|s| (s.flags & 0x1) == 0 && s.filesz > 0)
            .collect();

        let data_va_start = data_segs.iter().map(|s| s.vaddr).max().unwrap_or(0); // Use the HIGHEST data segment start
        let data_va_end = data_segs.iter().map(|s| s.vaddr + s.memsz).max().unwrap_or(0);

        // Scan .data.rel.ro segments for (count, pointer) pattern
        for seg in &data_segs {
            let seg_start = seg.offset as usize;
            let seg_end = (seg_start + seg.filesz as usize).min(raw_bytes.len());
            let seg_va = seg.vaddr;

            // Need at least 8 pairs (128 bytes) to form a MetadataRegistration
            let min_struct_size = 8 * ptr_size * 2; // 8 pairs of (count, pointer)

            for pos in (seg_start..seg_end.saturating_sub(min_struct_size)).step_by(ptr_size) {
                // Check if this could be the start of a MetadataRegistration struct.
                // Look for 4+ consecutive (count, pointer) pairs.
                let mut pairs_found = 0usize;

                for pair_idx in 0..8usize {
                    let count_off = pos + pair_idx * ptr_size * 2;
                    let ptr_off = count_off + ptr_size;

                    if ptr_off + ptr_size > raw_bytes.len() { break; }

                    // Read count (raw bytes — not relocated)
                    let count = if is_64 {
                        crate::rva_resolver::read_u64(raw_bytes, count_off, is_le)
                    } else {
                        crate::rva_resolver::read_u32(raw_bytes, count_off, is_le) as u64
                    };

                    // Read pointer (patched bytes — relocations applied)
                    let ptr = if is_64 {
                        crate::rva_resolver::read_u64(patched_bytes, ptr_off, is_le)
                    } else {
                        crate::rva_resolver::read_u32(patched_bytes, ptr_off, is_le) as u64
                    };

                    // Count should be a reasonable number (< 10M, nonzero)
                    if count == 0 || count > 10_000_000 { break; }

                    // Pointer should be in data VA range and map to a file offset
                    if ptr < data_va_start || ptr >= data_va_end { break; }
                    if elf_info.vaddr_to_file_offset(ptr).is_none() { break; }

                    pairs_found += 1;
                }

                if pairs_found < 4 { continue; }

                // Found a candidate! Read typesCount at +48 and types at +56 (64-bit)
                // MetadataRegistration layout: 8 (count, pointer) pairs = 16 fields
                // typesCount is at field index 6 (offset +6*8=+48), types at index 7 (+56)
                let types_count_off = pos + 6 * ptr_size;
                let types_ptr_off = pos + 7 * ptr_size;

                if types_ptr_off + ptr_size > raw_bytes.len() { continue; }

                let types_count = if is_64 {
                    crate::rva_resolver::read_u64(raw_bytes, types_count_off, is_le) as usize
                } else {
                    crate::rva_resolver::read_u32(raw_bytes, types_count_off, is_le) as usize
                };
                let types_ptr = if is_64 {
                    crate::rva_resolver::read_u64(patched_bytes, types_ptr_off, is_le)
                } else {
                    crate::rva_resolver::read_u32(patched_bytes, types_ptr_off, is_le) as u64
                };

                if types_count == 0 || types_count > 500_000 { continue; }
                if types_ptr < data_va_start || types_ptr >= data_va_end { continue; }

                let types_foff = match elf_info.vaddr_to_file_offset(types_ptr) {
                    Some(o) => o as usize,
                    None => continue,
                };

                // Validate: check entries across the types array
                let mut valid = 0usize;
                let mut checked = 0usize;
                let step = if types_count > 20 { types_count / 20 } else { 1 };
                for i in (0..types_count).step_by(step).take(20) {
                    let entry_off = types_foff + i * ptr_size;
                    if entry_off + ptr_size > patched_bytes.len() { continue; }
                    let type_ptr = crate::rva_resolver::read_pointer(patched_bytes, entry_off, ptr_size, is_le);
                    if type_ptr == 0 || type_ptr < 0x10000 { continue; }
                    let type_foff = match elf_info.vaddr_to_file_offset(type_ptr) {
                        Some(o) => o as usize,
                        None => continue,
                    };
                    if type_foff + type_kind_offset + 1 > patched_bytes.len() { continue; }
                    let kind = patched_bytes[type_foff + type_kind_offset];
                    if kind >= 1 && kind <= 0x24 {
                        valid += 1;
                    }
                    checked += 1;
                }

                if checked >= 10 && valid * 100 >= checked * 90 {
                    let mr_va = seg_va + (pos - seg_start) as u64;
                    debug_log.push(format!("  pattern: MR at va=0x{:x} typesCount={} types_ptr=0x{:x} valid={}/{}",
                        mr_va, types_count, types_ptr, valid, checked));
                    return Some((types_ptr, types_count));
                }
            }
        }
        debug_log.push("  pattern: no MetadataRegistration found".to_string());
        None
    }

    /// Scan data segments for the MetadataRegistration struct by looking for
    /// consecutive (count, pointer) pairs. The struct has 8 such pairs.
    /// Counts are int32_t (survive relocations), pointers are relocated.
    /// We find the struct, then read types_count at +48 and types ptr at +56.
    fn find_types_by_scan(
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        is_le: bool,
        ptr_size: usize,
        debug_log: &mut Vec<String>,
    ) -> Option<(u64, usize)> {
        let is_64 = elf_info.is_64bit;
        let type_kind_offset = if is_le { ptr_size + 2 } else { ptr_size + 1 };

        // Get data segment VA range for pointer validation
        let data_segs: Vec<_> = elf_info.load_segments().into_iter()
            .filter(|s| (s.flags & 0x1) == 0 && s.filesz > 0)
            .collect();
        let all_segs = elf_info.load_segments();

        let td_count = metadata.types.len(); // type_definitions_count
        debug_log.push(format!("  scan: td_count={}, searching for MR struct pattern", td_count));

        // Scan each data segment for the MetadataRegistration struct pattern.
        // The struct starts with 8 consecutive (count, pointer) pairs.
        // On 64-bit: each pair = int32_t count + 4 pad + 8 ptr = 16 bytes.
        // We scan for positions where multiple consecutive pairs match.
        for seg in &data_segs {
            let seg_start = seg.offset as usize;
            let seg_end = (seg_start + seg.filesz as usize).min(lib_bytes.len());
            let seg_va = seg.vaddr;

            let pair_size = ptr_size * 2; // 16 bytes on 64-bit
            let min_struct = pair_size * 4; // need at least 4 pairs

            for pos in (seg_start..seg_end.saturating_sub(min_struct)).step_by(ptr_size) {
                // Check up to 8 consecutive (count, pointer) pairs
                let mut pairs_ok = 0usize;
                for pi in 0..8usize {
                    let count_off = pos + pi * pair_size;
                    let ptr_off = count_off + ptr_size;
                    if ptr_off + ptr_size > lib_bytes.len() { break; }

                    // Read count (u32, survives relocations)
                    let count = crate::rva_resolver::read_u32(lib_bytes, count_off, is_le) as u64;
                    // Count should be reasonable: non-zero, < 10M
                    if count == 0 || count > 10_000_000 { break; }

                    // Read pointer (relocated, should be a data VA)
                    let ptr = if is_64 {
                        crate::rva_resolver::read_u64(lib_bytes, ptr_off, is_le)
                    } else {
                        crate::rva_resolver::read_u32(lib_bytes, ptr_off, is_le) as u64
                    };
                    // Pointer should be in a load segment
                    if ptr < 0x10000 { break; }
                    let mut in_segment = false;
                    for s in &all_segs {
                        if ptr >= s.vaddr && ptr < s.vaddr + s.memsz {
                            in_segment = true; break;
                        }
                    }
                    if !in_segment { break; }

                    pairs_ok += 1;
                }

                // Need at least 6 matching pairs to be confident
                if pairs_ok < 6 { continue; }

                // Found a candidate MR struct at `pos`.
                // MetadataRegistration layout (64-bit): 8 (count, pointer) pairs.
                // types_count at offset 48 = pair[6].count, types ptr at offset 56 = pair[6].ptr
                let types_count_off = pos + 6 * ptr_size;
                let types_ptr_off = types_count_off + ptr_size;
                if types_ptr_off + ptr_size > lib_bytes.len() { continue; }

                let types_count = crate::rva_resolver::read_u32(lib_bytes, types_count_off, is_le) as usize;
                let types_ptr = if is_64 {
                    crate::rva_resolver::read_u64(lib_bytes, types_ptr_off, is_le)
                } else {
                    crate::rva_resolver::read_u32(lib_bytes, types_ptr_off, is_le) as u64
                };

                // types_count must be plausible: at least td_count/4 and no more than 500K
                if types_count == 0 || types_count > 500_000 { continue; }
                if td_count > 0 && types_count < td_count / 4 { continue; }
                if types_ptr < 0x10000 { continue; }

                let types_foff = match elf_info.vaddr_to_file_offset(types_ptr) {
                    Some(o) => o as usize,
                    None => continue,
                };
                if types_foff + types_count * ptr_size > lib_bytes.len() { continue; }

                // Validate: sample entries from the types array should be
                // valid Il2CppType structs. Check for kind diversity (multiple
                // different kind values) and consistent stride.
                if types_foff + 5 * ptr_size > lib_bytes.len() { continue; }

                let mut valid = 0usize;
                let mut checked = 0usize;
                let mut kind_set = std::collections::HashSet::new();
                let mut prev_ptr = 0u64;
                let mut strides = Vec::new();
                let step = if types_count > 100 { types_count / 20 } else { 1 };

                for i in (0..types_count).step_by(step).take(20) {
                    let entry_off = types_foff + i * ptr_size;
                    if entry_off + ptr_size > lib_bytes.len() { break; }
                    let type_ptr = if is_64 {
                        crate::rva_resolver::read_u64(lib_bytes, entry_off, is_le)
                    } else {
                        crate::rva_resolver::read_u32(lib_bytes, entry_off, is_le) as u64
                    };
                    if type_ptr == 0 || type_ptr < 0x10000 { checked += 1; continue; }
                    let type_foff = match elf_info.vaddr_to_file_offset(type_ptr) {
                        Some(o) => o as usize,
                        None => { checked += 1; continue; },
                    };
                    if type_foff + type_kind_offset + 1 > lib_bytes.len() { checked += 1; continue; }
                    let kind = lib_bytes[type_foff + type_kind_offset];
                    if kind >= 1 && kind <= 0x1E {
                        valid += 1;
                        kind_set.insert(kind);
                    }
                    if prev_ptr > 0 && type_ptr > prev_ptr {
                        strides.push(type_ptr - prev_ptr);
                    }
                    prev_ptr = type_ptr;
                    checked += 1;
                }

                // Require: most entries valid, 3+ distinct kind values, consistent stride
                let stride_ok = if strides.len() >= 2 {
                    strides[0] >= 8 && strides[0] <= 64 && strides.iter().all(|&s| s == strides[0])
                } else if strides.len() == 1 {
                    strides[0] >= 8 && strides[0] <= 64
                } else {
                    false
                };

                if checked >= 15 && valid * 100 >= checked * 80 && kind_set.len() >= 3 && stride_ok {
                    let mr_va = seg_va + (pos - seg_start) as u64;
                    let types_va = elf_info.file_offset_to_vaddr(types_foff as u64)
                        .unwrap_or(seg_va + (types_foff as u64 - seg.offset));
                    debug_log.push(format!("  scan: MR at va=0x{:x} pairs={} types_count={} types_ptr=0x{:x} stride={} kinds={} valid={}/{}",
                        mr_va, pairs_ok, types_count, types_ptr, strides[0], kind_set.len(), valid, checked));
                    return Some((types_va, types_count));
                }
            }
        }

        debug_log.push("  scan: no valid MetadataRegistration found".to_string());
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

        // Build byval_type_index → FQCN map for parent resolution
        let mut byval_to_name: std::collections::HashMap<i32, String> = std::collections::HashMap::new();
        for t in &metadata.types {
            let fqcn = if !t.namespace_name.is_empty() {
                format!("{}.{}", t.namespace_name, t.name)
            } else {
                t.name.clone()
            };
            byval_to_name.entry(t.byval_type_index).or_insert(fqcn);
        }

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
                    self.write_type(&mut w, metadata, type_def, rva_result, &type_names, &byval_to_name)?;
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
                self.write_type(&mut w, metadata, type_def, rva_result, &type_names, &byval_to_name)?;
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
        byval_to_name: &std::collections::HashMap<i32, String>,
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

        // Determine type kind from flags and bitfield
        let is_enum = (type_def.bitfield & 2) != 0;
        let is_value_type = (type_def.bitfield & 1) != 0;
        let is_interface = (type_def.flags & 0x20) != 0;
        let is_abstract = (type_def.flags & 0x80) != 0;
        let is_sealed = (type_def.flags & 0x100) != 0;

        let (kind, modifiers) = if is_enum {
            ("enum", "public ")
        } else if is_interface {
            ("interface", "public ")
        } else if is_value_type {
            ("struct", if is_sealed { "public " } else { "public " })
        } else if is_abstract && is_sealed {
            ("class", "public static ")
        } else if is_abstract {
            ("class", "public abstract ")
        } else if is_sealed {
            ("class", "public sealed ")
        } else {
            ("class", "public ")
        };

        // Resolve parent class (skip System.Object, System.ValueType, System.Enum as implicit parents)
        let parent_name = if type_def.parent_index > 0 {
            byval_to_name.get(&type_def.parent_index).cloned()
        } else {
            None
        };
        let skip_parent = |name: &str| {
            name == "System.Object" || name == "System.ValueType" || name == "System.Enum"
        };

        if let Some(ref parent) = parent_name {
            if !skip_parent(parent) {
                writeln!(
                    w,
                    "{}{}{} {} : {}",
                    indent, modifiers, kind,
                    sanitize_identifier(&type_def.name),
                    parent
                )?;
            } else {
                writeln!(
                    w,
                    "{}{}{} {}",
                    indent, modifiers, kind,
                    sanitize_identifier(&type_def.name)
                )?;
            }
        } else {
            writeln!(
                w,
                "{}{}{} {}",
                indent, modifiers, kind,
                sanitize_identifier(&type_def.name)
            )?;
        }

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
