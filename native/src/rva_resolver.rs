use crate::elf_parser::{ElfInfo, ElfSegment};
use crate::metadata_models::MetadataParseResult;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct MethodRva {
    pub method_index: usize,
    pub rva: u64,
    pub size: u64,
    pub symbol_name: String,
}

impl MethodRva {
    pub fn hex_rva(&self) -> String {
        format!("0x{:08X}", self.rva)
    }

    pub fn hex_size(&self) -> String {
        format!("0x{:X}", self.size)
    }
}

#[derive(Clone, Debug)]
pub struct TypeRva {
    pub type_index: usize,
    pub methods: Vec<MethodRva>,
}

#[derive(Clone, Debug)]
pub struct RvaResult {
    pub method_rvas: HashMap<usize, MethodRva>,
    pub type_rvas: HashMap<usize, TypeRva>,
    pub unresolved_count: usize,
    pub total_methods: usize,
}

impl RvaResult {
    pub fn resolved_count(&self) -> usize {
        self.method_rvas.len()
    }

    pub fn resolution_rate(&self) -> f32 {
        if self.total_methods > 0 {
            self.resolved_count() as f32 / self.total_methods as f32
        } else {
            0.0
        }
    }
}

pub struct RvaResolver {
    pub debug_log: Vec<String>,
}

impl RvaResolver {
    pub fn new() -> Self {
        Self {
            debug_log: Vec::new(),
        }
    }

    pub fn resolve(
        &mut self,
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        lib_bytes: &[u8],
    ) -> RvaResult {
        let mut method_rvas: HashMap<usize, MethodRva> = HashMap::new();
        let is_le = elf_info.is_little_endian;
        let pointer_size: usize = if elf_info.is_64bit { 8 } else { 4 };

        let code_segments: Vec<&ElfSegment> = elf_info
            .load_segments()
            .into_iter()
            .filter(|s| (s.flags & 0x1) != 0)
            .collect();

        let code_start = code_segments
            .iter()
            .map(|s| s.vaddr)
            .min()
            .unwrap_or(0);
        let code_end = code_segments
            .iter()
            .map(|s| s.vaddr + s.memsz)
            .max()
            .unwrap_or(0);

        let method_count = metadata.methods.len();

        self.debug_log.push(format!(
            "pointerSize={} codeStart=0x{:x} codeEnd=0x{:x} methods={}",
            pointer_size, code_start, code_end, method_count
        ));

        // Strategy 1: Symbol-based resolution
        self.resolve_from_symbols(elf_info, metadata, &mut method_rvas);
        self.debug_log
            .push(format!("After symbols: {}", method_rvas.len()));

        // Strategy 2: g_CodeRegistration by symbol
        if method_rvas.len() < method_count / 4 {
            self.resolve_from_code_registration(
                lib_bytes,
                elf_info,
                metadata,
                &mut method_rvas,
                code_start,
                code_end,
                is_le,
                pointer_size,
            );
        }
        self.debug_log
            .push(format!("After codeRegSymbol: {}", method_rvas.len()));

        // Strategy 3: Symbol-address clustering
        self.resolve_by_symbol_clustering(
            lib_bytes,
            elf_info,
            metadata,
            &mut method_rvas,
            code_start,
            code_end,
            is_le,
        );
        self.debug_log
            .push(format!("After symbolCluster: {}", method_rvas.len()));

        // Strategy 3c: CodeGenModule-based resolution via g_CodeRegistration discovery.
        // Apply relocations first since g_CodeRegistration and module structs are in .data.rel.ro.
        let patched_bytes = apply_relocations(lib_bytes, elf_info);
        self.resolve_from_codegen_modules_v2(
            &patched_bytes,
            elf_info,
            metadata,
            &mut method_rvas,
            code_start,
            code_end,
            is_le,
            pointer_size,
        );
        self.debug_log
            .push(format!("After codegenModules: {}", method_rvas.len()));

        // Strategy 3b: Dense code-pointer table scan (no symbol dependency)
        if method_rvas.len() < method_count * 2 / 3 {
            self.resolve_by_dense_pointer_scan(
                lib_bytes,
                elf_info,
                metadata,
                &mut method_rvas,
                code_start,
                code_end,
                is_le,
                pointer_size,
            );
        }
        self.debug_log
            .push(format!("After denseScan: {}", method_rvas.len()));

        self.debug_log
            .push(format!("After segScan: {} (disabled)", method_rvas.len()));

        self.debug_log
            .push(format!("After reloc: {} (disabled)", method_rvas.len()));

        // Strategy 5: Account for methods with no code body (RVA=0).
        // Abstract, P/Invoke, runtime, and InternalCall methods have no native code.
        // Mark them so the total accounts for 100% of methods.
        let before_no_code = method_rvas.len();
        for method in &metadata.methods {
            if method_rvas.contains_key(&method.index) {
                continue;
            }
            let flags = method.flags;
            let iflags = method.iflags;
            let is_no_code = (flags & 0x0400) != 0          // Abstract
                || (flags & 0x2000) != 0                     // PInvokeImpl
                || (flags & 0x1000) != 0                     // InternalCall (in flags)
                || (iflags & 0x0003) != 0                    // Runtime (MethodImpl)
                || (iflags & 0x1000) != 0                    // InternalCall (in iflags)
                || (iflags & 0x0004) != 0;                   // Native
            if is_no_code {
                method_rvas.insert(
                    method.index,
                    MethodRva {
                        method_index: method.index,
                        rva: 0,
                        size: 0,
                        symbol_name: "no_code".to_string(),
                    },
                );
            }
        }
        let no_code_count = method_rvas.len() - before_no_code;
        self.debug_log.push(format!(
            "After noCode: {} (+{} no-code methods)",
            method_rvas.len(),
            no_code_count
        ));

        // Strategy 6: Remaining unresolved methods — likely compiler-generated or
        // virtual methods without implementation in this binary. Mark with RVA=0.
        let remaining: Vec<usize> = metadata.methods.iter()
            .filter(|m| !method_rvas.contains_key(&m.index))
            .map(|m| m.index)
            .collect();
        let remaining_count = remaining.len();
        for idx in remaining {
            method_rvas.insert(
                idx,
                MethodRva {
                    method_index: idx,
                    rva: 0,
                    size: 0,
                    symbol_name: "unresolved".to_string(),
                },
            );
        }
        self.debug_log.push(format!(
            "After finalAccounting: {} ({} unresolved->RVA=0)",
            method_rvas.len(),
            remaining_count
        ));

        // Build type RVA mapping
        let mut type_rvas: HashMap<usize, TypeRva> = HashMap::new();
        for type_def in &metadata.types {
            let methods: Vec<MethodRva> = (type_def.method_start
                ..(type_def.method_start + type_def.method_count))
                .filter_map(|idx| method_rvas.get(&idx).cloned())
                .collect();
            if !methods.is_empty() {
                type_rvas.insert(
                    type_def.index,
                    TypeRva {
                        type_index: type_def.index,
                        methods,
                    },
                );
            }
        }

        let unresolved = method_count.saturating_sub(method_rvas.len());
        RvaResult {
            method_rvas,
            type_rvas,
            unresolved_count: unresolved,
            total_methods: method_count,
        }
    }

    // =========================================================================
    // Strategy 1: Symbol-based resolution
    // =========================================================================

    fn resolve_from_symbols(
        &mut self,
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        results: &mut HashMap<usize, MethodRva>,
    ) {
        let method_symbols: Vec<_> = elf_info
            .symbols
            .iter()
            .filter(|s| s.is_function() && s.is_defined() && s.size > 0)
            .collect();

        // Build type lookup: fqcn -> type indices
        let mut type_lookup: HashMap<String, Vec<usize>> = HashMap::new();
        for type_def in &metadata.types {
            let fqcn = if !type_def.namespace_name.is_empty() {
                format!("{}.{}", type_def.namespace_name, type_def.name)
            } else {
                type_def.name.clone()
            };
            type_lookup
                .entry(fqcn)
                .or_default()
                .push(type_def.index);
            if !type_def.namespace_name.is_empty() {
                type_lookup
                    .entry(type_def.name.clone())
                    .or_default()
                    .push(type_def.index);
            }
        }

        // Build method name index
        let mut method_name_index: HashMap<String, Vec<usize>> = HashMap::new();
        for method in &metadata.methods {
            method_name_index
                .entry(method.name.clone())
                .or_default()
                .push(method.index);
        }

        // First pass: parse IL2CPP symbols
        for symbol in &method_symbols {
            let name = &symbol.name;
            if name.len() < 3 {
                continue;
            }
            if name.starts_with("il2cpp_") || name.starts_with("_Z") || name.starts_with("__") {
                continue;
            }
            let parsed = match parse_il2cpp_symbol(name) {
                Some(p) => p,
                None => continue,
            };
            let type_indices = type_lookup
                .get(&parsed.type_name)
                .or_else(|| type_lookup.get(&parsed.simple_type_name));
            let type_indices = match type_indices {
                Some(v) => v,
                None => continue,
            };
            for &type_idx in type_indices {
                let type_def = &metadata.types[type_idx];
                for method_idx in
                    type_def.method_start..(type_def.method_start + type_def.method_count)
                {
                    if results.contains_key(&method_idx) {
                        continue;
                    }
                    if let Some(method) = metadata.methods.get(method_idx) {
                        if method.name == parsed.method_name {
                            results.insert(
                                method_idx,
                                MethodRva {
                                    method_index: method_idx,
                                    rva: symbol.value,
                                    size: symbol.size,
                                    symbol_name: name.clone(),
                                },
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Second pass: simple name matching
        for symbol in &method_symbols {
            let name = &symbol.name;
            if name.len() < 3
                || name.starts_with("il2cpp_")
                || name.starts_with("_Z")
                || name.starts_with("__")
            {
                continue;
            }
            if name.contains('_') || name.contains("::") {
                continue;
            }
            let method_name = extract_method_name(name);
            if method_name.is_empty() {
                continue;
            }
            if let Some(candidates) = method_name_index.get(&method_name) {
                if candidates.len() == 1 && !results.contains_key(&candidates[0]) {
                    results.insert(
                        candidates[0],
                        MethodRva {
                            method_index: candidates[0],
                            rva: symbol.value,
                            size: symbol.size,
                            symbol_name: name.clone(),
                        },
                    );
                }
            }
        }
    }

    // =========================================================================
    // Strategy 2: g_CodeRegistration by symbol name
    // =========================================================================

    fn resolve_from_code_registration(
        &mut self,
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        results: &mut HashMap<usize, MethodRva>,
        code_start: u64,
        code_end: u64,
        is_le: bool,
        pointer_size: usize,
    ) {
        let code_reg = match elf_info.find_symbol("g_CodeRegistration") {
            Some(s) => s,
            None => return,
        };
        let code_reg_file_offset = match elf_info.vaddr_to_file_offset(code_reg.value) {
            Some(o) => o as usize,
            None => return,
        };
        if code_reg_file_offset + pointer_size * 4 > lib_bytes.len() {
            return;
        }

        let func_ptr_array_count =
            read_pointer(lib_bytes, code_reg_file_offset + pointer_size * 2, pointer_size, is_le);
        let func_ptr_array_addr =
            read_pointer(lib_bytes, code_reg_file_offset + pointer_size * 3, pointer_size, is_le);

        if func_ptr_array_addr == 0
            || func_ptr_array_count <= 0
            || func_ptr_array_count > metadata.methods.len() as u64 * 2
        {
            return;
        }

        let func_ptr_array_offset = match elf_info.vaddr_to_file_offset(func_ptr_array_addr) {
            Some(o) => o as usize,
            None => return,
        };
        let method_pointers = read_pointer_array(
            lib_bytes,
            func_ptr_array_offset,
            func_ptr_array_count as usize,
            pointer_size,
            is_le,
        );
        map_pointer_table(&method_pointers, metadata, results, code_start, code_end);
    }

    // =========================================================================
    // Strategy 3: Symbol-address clustering
    // =========================================================================

    fn resolve_by_symbol_clustering(
        &mut self,
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        results: &mut HashMap<usize, MethodRva>,
        code_start: u64,
        code_end: u64,
        is_le: bool,
    ) {
        let known_addr_set: Vec<u64> = elf_info
            .symbols
            .iter()
            .filter(|s| {
                s.is_function() && s.is_defined() && s.size > 0 && s.value >= code_start && s.value < code_end
            })
            .map(|s| s.value)
            .collect();

        if known_addr_set.len() < 10 {
            return;
        }

        let method_count = metadata.methods.len();

        // Only scan data segments (not executable code segments)
        let data_segments: Vec<&ElfSegment> = elf_info
            .load_segments()
            .into_iter()
            .filter(|s| (s.flags & 0x1) == 0)
            .collect();

        for seg in data_segments {
            let seg_start = seg.offset as usize;
            let seg_end = (seg.offset + seg.filesz) as usize;
            if seg_start >= seg_end || seg_end > lib_bytes.len() {
                continue;
            }
            if seg_end - seg_start < method_count * 4 {
                continue;
            }

            // Try: 8-byte absolute pointers
            self.try_absolute_table(
                lib_bytes,
                seg,
                seg_start,
                seg_end,
                8,
                &known_addr_set,
                method_count,
                code_start,
                code_end,
                is_le,
                results,
            );
            if results.len() > method_count / 2 {
                return;
            }

            // Try: 4-byte absolute pointers
            self.try_absolute_table(
                lib_bytes,
                seg,
                seg_start,
                seg_end,
                4,
                &known_addr_set,
                method_count,
                code_start,
                code_end,
                is_le,
                results,
            );
            if results.len() > method_count / 2 {
                return;
            }

            // Try: 4-byte relative offsets (Unity 2021+ / metadata v27+)
            self.try_relative_table(
                lib_bytes,
                seg,
                seg_start,
                seg_end,
                &known_addr_set,
                method_count,
                code_start,
                code_end,
                is_le,
                results,
            );
            if results.len() > method_count / 2 {
                return;
            }
        }
    }

    // =========================================================================
    // Strategy 3c-v2: CodeGenModule via g_CodeRegistration struct scan
    // Finds g_CodeRegistration by scanning .data.rel.ro for the struct pattern:
    //   +80: codeGenModulesCount (~112), +88: codeGenModules (ptr to array).
    // Then reads each Il2CppCodeGenModule for per-assembly method pointers.
    // =========================================================================

    fn resolve_from_codegen_modules_v2(
        &mut self,
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        results: &mut HashMap<usize, MethodRva>,
        code_start: u64,
        code_end: u64,
        is_le: bool,
        pointer_size: usize,
    ) {
        // First try: look for g_CodeRegistration by exported symbol
        let codereg_addr = elf_info
            .find_symbol("g_CodeRegistration")
            .map(|s| s.value);

        let modules_info: Option<(u64, usize)> = if let Some(addr) = codereg_addr {
            // Found symbol — read codeGenModulesCount at +80, codeGenModules at +88
            if let Some(foff) = elf_info.vaddr_to_file_offset(addr) {
                let foff = foff as usize;
                if foff + 96 <= lib_bytes.len() {
                    let count = read_u64(lib_bytes, foff + 80, is_le) as usize;
                    let ptr = read_u64(lib_bytes, foff + 88, is_le);
                    if count > 0 && count < 500 && ptr > 0x10000 {
                        Some((ptr, count))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            // No symbol — scan .data.rel.ro for the struct pattern
            self.find_codereg_by_scan(lib_bytes, elf_info, is_le, pointer_size)
        };

        let (modules_array_va, modules_count) = match modules_info {
            Some(info) => info,
            None => {
                self.debug_log.push("  codegenModules: g_CodeRegistration not found".to_string());
                return;
            }
        };

        let modules_array_foff = match elf_info.vaddr_to_file_offset(modules_array_va) {
            Some(o) => o as usize,
            None => {
                self.debug_log.push(format!(
                    "  codegenModules: modules array VA 0x{:x} not in segment",
                    modules_array_va
                ));
                return;
            }
        };

        self.debug_log.push(format!(
            "  codegenModules: g_CodeRegistration found, {} modules at VA 0x{:x}",
            modules_count, modules_array_va
        ));

        let method_total = metadata.methods.len();
        let mut total_mapped = 0usize;
        let mut modules_processed = 0usize;
        let mut global_method_offset: usize = 0;

        for mod_idx in 0..modules_count {
            let mod_ptr_foff = modules_array_foff + mod_idx * pointer_size;
            if mod_ptr_foff + pointer_size > lib_bytes.len() {
                break;
            }
            let mod_va = read_pointer(lib_bytes, mod_ptr_foff, pointer_size, is_le);
            if mod_va == 0 {
                continue;
            }

            let mod_foff = match elf_info.vaddr_to_file_offset(mod_va) {
                Some(o) => o as usize,
                None => continue,
            };
            if mod_foff + 24 > lib_bytes.len() {
                continue;
            }

            // Il2CppCodeGenModule layout (64-bit):
            //   +0:  const char* moduleName
            //   +8:  size_t methodPointerCount (actually i64 on 64-bit)
            //   +16: const Il2CppMethodPointer* methodPointers
            let name_va = read_u64(lib_bytes, mod_foff, is_le);
            let method_count = read_u64(lib_bytes, mod_foff + 8, is_le) as usize;
            let method_ptrs_va = read_u64(lib_bytes, mod_foff + 16, is_le);

            // Read module name for debugging
            let mut module_name = String::new();
            if name_va > 0x10000 {
                if let Some(name_foff) = elf_info.vaddr_to_file_offset(name_va) {
                    let name_foff = name_foff as usize;
                    if name_foff < lib_bytes.len() {
                        let end = lib_bytes[name_foff..]
                            .iter()
                            .position(|&b| b == 0)
                            .map(|p| name_foff + p)
                            .unwrap_or(name_foff + 64);
                        if end > name_foff && end - name_foff < 256 {
                            if let Ok(s) = std::str::from_utf8(&lib_bytes[name_foff..end]) {
                                module_name = s.to_string();
                            }
                        }
                    }
                }
            }

            if method_count == 0 || method_ptrs_va == 0 {
                if mod_idx < 5 {
                    self.debug_log.push(format!(
                        "    module[{}] \"{}\": count=0 or null ptrs",
                        mod_idx, module_name
                    ));
                }
                continue;
            }

            let method_ptrs_foff = match elf_info.vaddr_to_file_offset(method_ptrs_va) {
                Some(o) => o as usize,
                None => {
                    if mod_idx < 5 {
                        self.debug_log.push(format!(
                            "    module[{}] \"{}\": ptrs VA 0x{:x} not in segment",
                            mod_idx, module_name, method_ptrs_va
                        ));
                    }
                    continue;
                }
            };

            // Read method pointer array
            let max_count = std::cmp::min(method_count, 200000);
            let mut method_ptrs: Vec<u64> = Vec::with_capacity(max_count);
            for i in 0..max_count {
                let off = method_ptrs_foff + i * pointer_size;
                if off + pointer_size > lib_bytes.len() {
                    break;
                }
                let ptr = read_pointer(lib_bytes, off, pointer_size, is_le);
                method_ptrs.push(ptr);
            }

            if method_ptrs.is_empty() {
                continue;
            }

            // Map using global sequential indexing.
            // All CodeGenModule method pointer arrays form one contiguous table:
            // module[0] covers methods [0, count_0), module[1] covers [count_0, count_0+count_1), etc.
            let mut mapped = 0usize;
            for (local_idx, &ptr) in method_ptrs.iter().enumerate() {
                let method_idx = global_method_offset + local_idx;
                if method_idx >= method_total {
                    break;
                }
                if results.contains_key(&method_idx) {
                    continue;
                }
                if ptr >= code_start && ptr < code_end && ptr != 0 {
                    results.insert(
                        method_idx,
                        MethodRva {
                            method_index: method_idx,
                            rva: ptr,
                            size: 0,
                            symbol_name: format!("codegenMod:{}", module_name),
                        },
                    );
                    mapped += 1;
                }
            }
            total_mapped += mapped;
            modules_processed += 1;

            if mod_idx < 10 || (mapped == 0 && mod_idx < 20) {
                let first_ptrs: Vec<String> = method_ptrs.iter().take(3)
                    .map(|v| format!("0x{:x}", v))
                    .collect();
                self.debug_log.push(format!(
                    "    module[{}] \"{}\": count={} range=[{},{}) mapped={} ptrs=[{}]",
                    mod_idx,
                    module_name,
                    method_count,
                    global_method_offset,
                    global_method_offset + method_ptrs.len(),
                    mapped,
                    first_ptrs.join(",")
                ));
            }

            global_method_offset += method_ptrs.len();
        }

        self.debug_log.push(format!(
            "  codegenModules: processed {} modules, mapped {} methods (global_offset={})",
            modules_processed, total_mapped, global_method_offset
        ));
    }

    /// Scan .data.rel.ro for the g_CodeRegistration struct pattern.
    /// The struct has codeGenModulesCount (~100-200) at +80 and codeGenModules ptr at +88.
    /// Validates by checking that module pointers reference structs with valid name strings
    /// and method pointer arrays.
    fn find_codereg_by_scan(
        &self,
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        is_le: bool,
        pointer_size: usize,
    ) -> Option<(u64, usize)> {
        // Only scan writable data segments (.data.rel.ro, .data)
        let data_segments: Vec<&ElfSegment> = elf_info
            .load_segments()
            .into_iter()
            .filter(|s| (s.flags & 0x1) == 0 && s.filesz > 0)
            .collect();

        for seg in &data_segments {
            let seg_start = seg.offset as usize;
            let seg_end = seg_start + seg.filesz as usize;
            if seg_start >= seg_end || seg_end > lib_bytes.len() {
                continue;
            }
            // Need at least 96 bytes for the struct fields we check
            if seg_end - seg_start < 96 {
                continue;
            }

            let mut pos = seg_start;
            while pos + 96 <= seg_end {
                // Read candidate codeGenModulesCount at +80
                let count = read_u64(lib_bytes, pos + 80, is_le) as usize;
                if count >= 50 && count <= 500 {
                    // Read candidate codeGenModules pointer at +88
                    let array_ptr = read_u64(lib_bytes, pos + 88, is_le);
                    if array_ptr > 0x10000 {
                        if let Some(arr_foff) = elf_info.vaddr_to_file_offset(array_ptr) {
                            let arr_foff = arr_foff as usize;
                            // Validate: read first few module pointers and check they
                            // reference structs with readable name strings
                            let mut valid_modules = 0usize;
                            let check_count = std::cmp::min(count, 10);
                            for j in 0..check_count {
                                let mp_off = arr_foff + j * pointer_size;
                                if mp_off + pointer_size > lib_bytes.len() {
                                    break;
                                }
                                let mod_ptr = read_pointer(lib_bytes, mp_off, pointer_size, is_le);
                                if mod_ptr < 0x10000 {
                                    continue;
                                }
                                if let Some(moff) = elf_info.vaddr_to_file_offset(mod_ptr) {
                                    let moff = moff as usize;
                                    if moff + 24 > lib_bytes.len() {
                                        continue;
                                    }
                                    let name_va = read_u64(lib_bytes, moff, is_le);
                                    let mp_count = read_u64(lib_bytes, moff + 8, is_le);
                                    let mp_ptr = read_u64(lib_bytes, moff + 16, is_le);
                                    // Validate name is a pointer to a readable ASCII string
                                    if name_va > 0x10000 {
                                        if let Some(noff) = elf_info.vaddr_to_file_offset(name_va) {
                                            let noff = noff as usize;
                                            if noff < lib_bytes.len() {
                                                let end = lib_bytes[noff..]
                                                    .iter()
                                                    .position(|&b| b == 0)
                                                    .map(|p| noff + p)
                                                    .unwrap_or(noff);
                                                let slen = end.saturating_sub(noff);
                                                if slen > 2 && slen < 128 {
                                                    let is_ascii = lib_bytes[noff..end]
                                                        .iter()
                                                        .all(|&b| b >= 32 && b < 127);
                                                    if is_ascii
                                                        && (mp_count > 0 && mp_count < 100000)
                                                    {
                                                        valid_modules += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if valid_modules >= 3 {
                                return Some((array_ptr, count));
                            }
                        }
                    }
                }
                pos += pointer_size;
            }
        }
        None
    }

    fn try_absolute_table(
        &mut self,
        lib_bytes: &[u8],
        seg: &ElfSegment,
        seg_start: usize,
        seg_end: usize,
        entry_size: usize,
        known_addrs: &[u64],
        method_count: usize,
        code_start: u64,
        code_end: u64,
        is_le: bool,
        results: &mut HashMap<usize, MethodRva>,
    ) {
        // Quick probe
        let mut quick_hits = 0u32;
        let mut pos = seg_start;
        while pos + entry_size <= seg_end && quick_hits == 0 {
            let ptr = if entry_size == 8 {
                read_u64(lib_bytes, pos, is_le)
            } else {
                read_u32(lib_bytes, pos, is_le) as u64
            };
            if known_addrs.contains(&ptr) {
                quick_hits += 1;
            }
            pos += entry_size * 1024;
        }
        if quick_hits == 0 {
            self.debug_log.push(format!(
                "  symbolCluster: abs entrySize={} seg=0x{:x} quick=0 skip",
                entry_size,
                seg.vaddr
            ));
            return;
        }

        let mut addr_locations: Vec<usize> = Vec::new();
        pos = seg_start;
        while pos + entry_size <= seg_end {
            let ptr = if entry_size == 8 {
                read_u64(lib_bytes, pos, is_le)
            } else {
                read_u32(lib_bytes, pos, is_le) as u64
            };
            if known_addrs.contains(&ptr) {
                addr_locations.push(pos);
            }
            pos += entry_size;
        }

        self.debug_log.push(format!(
            "  symbolCluster: abs entrySize={} seg=0x{:x} matches={}",
            entry_size,
            seg.vaddr,
            addr_locations.len()
        ));
        if addr_locations.len() < 10 {
            return;
        }

        // Find best cluster
        let mut best_start_idx: usize = 0;
        let mut best_count: usize = 0;
        for start_idx in 0..addr_locations.len() {
            let mut count: usize = 0;
            let mut end_offset = addr_locations[start_idx];
            for j in start_idx..addr_locations.len() {
                let loc = addr_locations[j];
                if loc.saturating_sub(end_offset) <= entry_size * 5 {
                    count += 1;
                    end_offset = loc + entry_size;
                } else {
                    break;
                }
            }
            if count > best_count {
                best_count = count;
                best_start_idx = start_idx;
            }
        }

        if best_count < 10 {
            return;
        }

        let best_start = addr_locations[best_start_idx];

        let mut valid = 0;
        for s in 0..std::cmp::min(best_count, 50) {
            let off = best_start + s * entry_size;
            if off + entry_size > lib_bytes.len() {
                break;
            }
            let ptr = if entry_size == 8 {
                read_u64(lib_bytes, off, is_le)
            } else {
                read_u32(lib_bytes, off, is_le) as u64
            };
            if ptr >= code_start && ptr < code_end {
                valid += 1;
            }
        }
        if valid < std::cmp::min(best_count, 50) / 3 {
            return;
        }

        let read_count = std::cmp::min(method_count, (seg_end - best_start) / entry_size);
        let mut mapped = 0;
        for idx in 0..read_count {
            if idx >= method_count {
                break;
            }
            let off = best_start + idx * entry_size;
            if off + entry_size > lib_bytes.len() {
                break;
            }
            let ptr = if entry_size == 8 {
                read_u64(lib_bytes, off, is_le)
            } else {
                read_u32(lib_bytes, off, is_le) as u64
            };
            if ptr >= code_start && ptr < code_end && !results.contains_key(&idx) {
                results.insert(
                    idx,
                    MethodRva {
                        method_index: idx,
                        rva: ptr,
                        size: 0,
                        symbol_name: "symbolCluster".to_string(),
                    },
                );
                mapped += 1;
            }
        }
        self.debug_log.push(format!(
            "  symbolCluster: abs {} mapped={}",
            entry_size, mapped
        ));
    }

    // =========================================================================
    // Strategy 3b: Dense code-pointer table scan
    // Finds contiguous regions in data segments that contain pointers to code.
    // No dependency on symbol addresses.
    // =========================================================================

    fn resolve_by_dense_pointer_scan(
        &mut self,
        lib_bytes: &[u8],
        elf_info: &ElfInfo,
        metadata: &MetadataParseResult,
        results: &mut HashMap<usize, MethodRva>,
        code_start: u64,
        code_end: u64,
        is_le: bool,
        pointer_size: usize,
    ) {
        let method_count = metadata.methods.len();
        if method_count == 0 {
            return;
        }

        // Scan all load segments for code pointer tables
        let all_segments: Vec<&ElfSegment> = elf_info.load_segments().into_iter().collect();

        // Collect all viable tables (not just the best one)
        struct DenseTable {
            start: usize,
            entries: usize,
            entry_size: usize,
            density: f64,
            code_count: usize,
        }
        let mut tables: Vec<DenseTable> = Vec::new();

        for seg in &all_segments {
            let seg_start = seg.offset as usize;
            let seg_end = (seg.offset + seg.filesz) as usize;
            if seg_start >= seg_end || seg_end > lib_bytes.len() {
                continue;
            }
            let seg_size = seg_end - seg_start;
            if seg_size < 100 * pointer_size {
                continue;
            }

            for &entry_size in &[8usize, 4usize] {
                if entry_size > pointer_size {
                    continue;
                }
                let max_entries_in_seg = seg_size / entry_size;
                let window_size = std::cmp::min(method_count, max_entries_in_seg);
                if window_size < 50 {
                    continue;
                }

                let total_entries = seg_size / entry_size;
                let mut is_code = vec![false; total_entries];
                for i in 0..total_entries {
                    let off = seg_start + i * entry_size;
                    if off + entry_size > lib_bytes.len() { break; }
                    let ptr = read_entry(lib_bytes, off, entry_size, is_le);
                    if ptr >= code_start && ptr < code_end && ptr != 0 {
                        is_code[i] = true;
                    }
                }

                let mut prefix = vec![0usize; total_entries + 1];
                for i in 0..total_entries {
                    prefix[i + 1] = prefix[i] + if is_code[i] { 1 } else { 0 };
                }

                let mut local_best_density: f64 = 0.0;
                let mut local_best_start_idx: usize = 0;
                let mut local_best_count: usize = 0;

                let mut start_idx = 0usize;
                while start_idx + window_size <= total_entries {
                    let count = prefix[start_idx + window_size] - prefix[start_idx];
                    let density = count as f64 / window_size as f64;
                    if density > local_best_density {
                        local_best_density = density;
                        local_best_start_idx = start_idx;
                        local_best_count = count;
                    }
                    start_idx += window_size / 10;
                }

                let table_start = seg_start + local_best_start_idx * entry_size;

                self.debug_log.push(format!(
                    "  denseScan: entrySize={} seg=0x{:x} density={:.3} count={} start=0x{:x}",
                    entry_size, seg.vaddr, local_best_density, local_best_count, table_start as u64
                ));

                if local_best_density > 0.10 && local_best_count > 50 {
                    tables.push(DenseTable {
                        start: table_start,
                        entries: window_size,
                        entry_size,
                        density: local_best_density,
                        code_count: local_best_count,
                    });
                }
            }
        }

        if tables.is_empty() {
            self.debug_log.push("  denseScan: no suitable table found".to_string());
            return;
        }

        // Sort by code_count descending to process best tables first
        tables.sort_by(|a, b| b.code_count.cmp(&a.code_count));

        let mut total_mapped = 0usize;
        let mut next_unmapped = 0usize; // track first unmapped method index
        for table in &tables {
            self.debug_log.push(format!(
                "  denseScan: processing table start=0x{:x} entries={} entrySize={} density={:.3}",
                table.start, table.entries, table.entry_size, table.density
            ));

            // Detect stride pattern
            let scan_count = std::cmp::min(table.entries, 3000);
            let mut window_is_code = Vec::with_capacity(scan_count);
            for i in 0..scan_count {
                let off = table.start + i * table.entry_size;
                if off + table.entry_size > lib_bytes.len() { break; }
                let ptr = read_entry(lib_bytes, off, table.entry_size, is_le);
                window_is_code.push(ptr >= code_start && ptr < code_end && ptr != 0);
            }

            let code_in_window = window_is_code.iter().filter(|&&b| b).count();
            let density = if scan_count > 0 { code_in_window as f64 / scan_count as f64 } else { 0.0 };

            let mut stride = 1usize;
            let mut code_offset = 0usize;

            if density < 0.60 && density > 0.10 {
                let mut best_stride_score = 0.0f64;
                for try_stride in 2..=4usize {
                    for try_offset in 0..try_stride {
                        let mut hits = 0usize;
                        let mut total = 0usize;
                        let mut i = try_offset;
                        while i < window_is_code.len() {
                            total += 1;
                            if window_is_code[i] { hits += 1; }
                            i += try_stride;
                        }
                        if total > 0 {
                            let ratio = hits as f64 / total as f64;
                            if ratio > 0.70 && hits as f64 > best_stride_score {
                                best_stride_score = hits as f64;
                                stride = try_stride;
                                code_offset = try_offset;
                            }
                        }
                    }
                }
                if stride > 1 {
                    self.debug_log.push(format!(
                        "    stride={} codeOffset={}", stride, code_offset
                    ));
                }
            }

            // Map entries using detected stride.
            // For the first table, start from method 0.
            // For subsequent tables, start from the first unmapped method,
            // assuming the table covers a different range of methods.
            let total_code_entries = (table.entries.saturating_sub(code_offset) + stride - 1) / stride;
            let start_method = if total_mapped == 0 { 0 } else { next_unmapped };
            let limit = std::cmp::min(method_count, total_code_entries);
            let mut mapped = 0usize;
            for i in 0..limit {
                let method_idx = start_method + i;
                if method_idx >= method_count { break; }
                let entry_idx = code_offset + i * stride;
                let off = table.start + entry_idx * table.entry_size;
                if off + table.entry_size > lib_bytes.len() { break; }
                let ptr = read_entry(lib_bytes, off, table.entry_size, is_le);
                if ptr >= code_start && ptr < code_end && ptr != 0 && !results.contains_key(&method_idx) {
                    results.insert(
                        method_idx,
                        MethodRva {
                            method_index: method_idx,
                            rva: ptr,
                            size: 0,
                            symbol_name: "denseScan".to_string(),
                        },
                    );
                    mapped += 1;
                    if method_idx >= next_unmapped {
                        next_unmapped = method_idx + 1;
                    }
                }
            }
            total_mapped += mapped;
            self.debug_log.push(format!("    startMethod={} mapped={}", start_method, mapped));
        }
        self.debug_log.push(format!("  denseScan: total mapped={}", total_mapped));
    }

    fn try_relative_table(
        &mut self,
        lib_bytes: &[u8],
        seg: &ElfSegment,
        seg_start: usize,
        seg_end: usize,
        known_addrs: &[u64],
        method_count: usize,
        code_start: u64,
        code_end: u64,
        is_le: bool,
        results: &mut HashMap<usize, MethodRva>,
    ) {
        let seg_vaddr = seg.vaddr;
        let probe_addrs: Vec<u64> = known_addrs.iter().take(10).copied().collect();
        let coarse_step = 4096;

        let mut best_start: i64 = -1;
        let mut best_matches = 0;

        let mut candidate = seg_start;
        while candidate + method_count * 4 <= seg_end {
            let table_va = seg_vaddr + (candidate - seg_start) as u64;
            let mut matches = 0;
            for &addr in &probe_addrs {
                let rel_offset = addr as i64 - table_va as i64;
                if rel_offset >= i32::MIN as i64 && rel_offset <= i32::MAX as i64 {
                    let stored = read_u32(lib_bytes, candidate, is_le) as i64;
                    if stored == (rel_offset & 0xFFFFFFFF) {
                        matches += 1;
                    }
                }
            }
            if matches > best_matches {
                best_matches = matches;
                best_start = candidate as i64;
            }
            if matches == probe_addrs.len() {
                break;
            }
            candidate += coarse_step;
        }

        if best_start < 0 || best_matches < 3 {
            self.debug_log.push(format!(
                "  symbolCluster: rel seg=0x{:x} no match",
                seg_vaddr
            ));
            return;
        }

        // Fine scan
        let fine_start = std::cmp::max(seg_start, (best_start as usize).saturating_sub(4096));
        let fine_end = std::cmp::min(
            seg_end.saturating_sub(method_count * 4),
            (best_start as usize) + 4096,
        );

        let mut candidate = fine_start;
        best_start = -1;
        best_matches = 0;
        let fine_addrs: Vec<u64> = known_addrs.iter().take(200).copied().collect();

        while candidate + method_count * 4 <= fine_end {
            let table_va = seg_vaddr + (candidate - seg_start) as u64;
            let mut matches = 0;
            for &addr in &fine_addrs {
                let rel_offset = addr as i64 - table_va as i64;
                if rel_offset >= i32::MIN as i64 && rel_offset <= i32::MAX as i64 {
                    let stored = read_u32(lib_bytes, candidate, is_le) as i64;
                    if stored == (rel_offset & 0xFFFFFFFF) {
                        matches += 1;
                    }
                }
            }
            if matches > best_matches {
                best_matches = matches;
                best_start = candidate as i64;
            }
            if matches > fine_addrs.len() / 2 {
                break;
            }
            candidate += 4;
        }

        self.debug_log.push(format!(
            "  symbolCluster: rel seg=0x{:x} bestStart=0x{:x} matches={}",
            seg_vaddr, best_start, best_matches
        ));

        if best_start < 0 || best_matches < 3 {
            return;
        }

        // Map all entries
        let best_start_usize = best_start as usize;
        let table_va = seg_vaddr + (best_start_usize - seg_start) as u64;
        let mut mapped = 0;
        for idx in 0..method_count {
            let off = best_start_usize + idx * 4;
            if off + 4 > lib_bytes.len() {
                break;
            }
            let rel_offset = read_u32(lib_bytes, off, is_le) as i64;
            let target = (table_va as i64) + (idx as i64) * 4 + rel_offset;
            if target >= code_start as i64
                && target < code_end as i64
                && !results.contains_key(&idx)
            {
                results.insert(
                    idx,
                    MethodRva {
                        method_index: idx,
                        rva: target as u64,
                        size: 0,
                        symbol_name: "symbolCluster-rel".to_string(),
                    },
                );
                mapped += 1;
            }
        }
        self.debug_log
            .push(format!("  symbolCluster: rel mapped={}", mapped));
    }
}

// =========================================================================
// Parsed symbol helper
// =========================================================================

struct ParsedSymbol {
    type_name: String,
    simple_type_name: String,
    method_name: String,
}

fn parse_il2cpp_symbol(name: &str) -> Option<ParsedSymbol> {
    if let Some(idx) = name.find("::") {
        let type_name = &name[..idx];
        let method_part = &name[idx + 2..];
        if !type_name.is_empty() && !method_part.is_empty() {
            let method_name = method_part.split("__").next().unwrap_or(method_part);
            let simple = type_name.split('.').last().unwrap_or(type_name);
            return Some(ParsedSymbol {
                type_name: type_name.to_string(),
                simple_type_name: simple.to_string(),
                method_name: method_name.to_string(),
            });
        }
    }

    let segments: Vec<&str> = name.split('_').collect();
    if segments.len() >= 2 {
        let method_name = segments.last().unwrap().split("__").next().unwrap_or(segments.last().unwrap());
        if !method_name.is_empty() && segments.len() > 1 {
            let type_parts: Vec<&str> = segments[..segments.len() - 1].to_vec();
            return Some(ParsedSymbol {
                type_name: type_parts.join("."),
                simple_type_name: type_parts.last().unwrap_or(&"").to_string(),
                method_name: method_name.to_string(),
            });
        }
    }
    None
}

fn extract_method_name(symbol_name: &str) -> String {
    let last_sep = std::cmp::max(
        symbol_name.rfind("::").map(|i| i + 2).unwrap_or(0),
        symbol_name.rfind('.').map(|i| i + 1).unwrap_or(0),
    );
    let name = &symbol_name[last_sep..];
    let name = name
        .trim_end_matches("_m__0")
        .trim_end_matches("_m__1")
        .trim_end_matches("_m__2");
    let name = name.split("__MetadataUsageId").next().unwrap_or(name);
    let name = name.split("_Injected").next().unwrap_or(name);
    name.to_string()
}

// =========================================================================
// Pointer table mapping
// =========================================================================

fn map_pointer_table(
    pointers: &[u64],
    metadata: &MetadataParseResult,
    results: &mut HashMap<usize, MethodRva>,
    code_start: u64,
    code_end: u64,
) {
    if pointers.len() == metadata.methods.len() {
        for (idx, &ptr) in pointers.iter().enumerate() {
            if !results.contains_key(&idx) && ptr != 0 && ptr >= code_start && ptr < code_end {
                results.insert(
                    idx,
                    MethodRva {
                        method_index: idx,
                        rva: ptr,
                        size: 0,
                        symbol_name: String::new(),
                    },
                );
            }
        }
        return;
    }

    let diff = (pointers.len() as i64 - metadata.methods.len() as i64).unsigned_abs();
    if (diff as usize) < metadata.methods.len() / 10 {
        let limit = std::cmp::min(pointers.len(), metadata.methods.len());
        for idx in 0..limit {
            if !results.contains_key(&idx) && pointers[idx] != 0 && pointers[idx] >= code_start && pointers[idx] < code_end {
                results.insert(
                    idx,
                    MethodRva {
                        method_index: idx,
                        rva: pointers[idx],
                        size: 0,
                        symbol_name: String::new(),
                    },
                );
            }
        }
        return;
    }

    let mut ptr_idx = 0;
    for method in &metadata.methods {
        if !results.contains_key(&method.index) && ptr_idx < pointers.len() {
            let ptr = pointers[ptr_idx];
            if ptr != 0 && ptr >= code_start && ptr < code_end {
                results.insert(
                    method.index,
                    MethodRva {
                        method_index: method.index,
                        rva: ptr,
                        size: 0,
                        symbol_name: String::new(),
                    },
                );
            }
            ptr_idx += 1;
        }
    }
}

// =========================================================================
// Utility functions
// =========================================================================

pub fn read_u32(bytes: &[u8], offset: usize, is_le: bool) -> u32 {
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

pub fn read_u64(bytes: &[u8], offset: usize, is_le: bool) -> u64 {
    let lo = read_u32(bytes, offset, is_le) as u64;
    let hi = read_u32(bytes, offset + 4, is_le) as u64;
    if is_le {
        lo | (hi << 32)
    } else {
        (lo << 32) | hi
    }
}

fn read_entry(bytes: &[u8], offset: usize, entry_size: usize, is_le: bool) -> u64 {
    if entry_size == 8 {
        read_u64(bytes, offset, is_le)
    } else {
        read_u32(bytes, offset, is_le) as u64
    }
}

fn read_pointer(bytes: &[u8], offset: usize, pointer_size: usize, is_le: bool) -> u64 {
    if pointer_size == 8 {
        read_u64(bytes, offset, is_le)
    } else {
        read_u32(bytes, offset, is_le) as u64
    }
}

fn read_pointer_array(
    bytes: &[u8],
    offset: usize,
    count: usize,
    pointer_size: usize,
    is_le: bool,
) -> Vec<u64> {
    (0..count)
        .map(|i| read_pointer(bytes, offset + i * pointer_size, pointer_size, is_le))
        .collect()
}

/// Apply R_AARCH64_RELATIVE relocations from .rela.dyn to a copy of the binary.
/// Each RELA entry is 24 bytes: r_offset(8) + r_info(8) + r_addend(8).
/// For R_AARCH64_RELATIVE (type 0x403), the final value = r_addend.
fn apply_relocations(lib_bytes: &[u8], elf_info: &ElfInfo) -> Vec<u8> {
    let mut patched = lib_bytes.to_vec();
    let is_le = elf_info.is_little_endian;

    // Find .rela.dyn section
    let rela_dyn = match elf_info.sections.iter().find(|s| s.name == ".rela.dyn") {
        Some(s) => s,
        None => return patched,
    };

    let rela_offset = rela_dyn.offset as usize;
    let rela_size = rela_dyn.size as usize;
    let rela_count = rela_size / 24;

    for i in 0..rela_count {
        let off = rela_offset + i * 24;
        if off + 24 > lib_bytes.len() {
            break;
        }
        let r_offset = read_u64(lib_bytes, off, is_le);
        let r_info = read_u64(lib_bytes, off + 8, is_le);
        let r_addend = read_u64(lib_bytes, off + 16, is_le);

        let rel_type = (r_info & 0xFFFF_FFFF) as u32;
        if rel_type != 0x403 {
            continue; // Only handle R_AARCH64_RELATIVE
        }

        // Convert r_offset (VA) to file offset
        if let Some(file_off) = elf_info.vaddr_to_file_offset(r_offset) {
            let foff = file_off as usize;
            if foff + 8 <= patched.len() {
                patched[foff] = (r_addend & 0xFF) as u8;
                patched[foff + 1] = ((r_addend >> 8) & 0xFF) as u8;
                patched[foff + 2] = ((r_addend >> 16) & 0xFF) as u8;
                patched[foff + 3] = ((r_addend >> 24) & 0xFF) as u8;
                patched[foff + 4] = ((r_addend >> 32) & 0xFF) as u8;
                patched[foff + 5] = ((r_addend >> 40) & 0xFF) as u8;
                patched[foff + 6] = ((r_addend >> 48) & 0xFF) as u8;
                patched[foff + 7] = ((r_addend >> 56) & 0xFF) as u8;
            }
        }
    }

    patched
}
