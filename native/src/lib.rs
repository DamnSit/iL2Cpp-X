mod binary_reader;
mod dump_cs_writer;
mod elf_parser;
mod jni_bridge;
mod json_writers;
mod metadata_models;
pub mod metadata_parser;
mod rva_resolver;

use elf_parser::ElfParser;
use metadata_parser::MetadataParser;
use rva_resolver::RvaResolver;

/// Main dump function — parses ELF + metadata, resolves RVA, writes output files.
/// Returns a DumpResult with log lines and stats.
pub fn dump(
    lib_path: &str,
    metadata_path: &str,
    output_dir: &str,
    include_rva_info: bool,
    include_inheritance: bool,
    generate_summary: bool,
    max_string_literals: usize,
) -> DumpResult {
    let mut log: Vec<String> = Vec::new();
    log.push("IL2CPP X Rust native dumper".to_string());
    log.push(format!("libil2cpp: {}", lib_path));
    log.push(format!("metadata: {}", metadata_path));
    log.push(format!("output: {}", output_dir));

    // Validate inputs
    if !std::path::Path::new(lib_path).exists() {
        return DumpResult {
            success: false,
            log: vec!["libil2cpp.so tidak ditemukan".to_string()],
            types_count: 0,
            methods_count: 0,
            rva_resolved: 0,
            rva_total: 0,
        };
    }
    if !std::path::Path::new(metadata_path).exists() {
        return DumpResult {
            success: false,
            log: vec!["global-metadata.dat tidak ditemukan".to_string()],
            types_count: 0,
            methods_count: 0,
            rva_resolved: 0,
            rva_total: 0,
        };
    }

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        return DumpResult {
            success: false,
            log: vec![format!("Gagal membuat output dir: {}", e)],
            types_count: 0,
            methods_count: 0,
            rva_resolved: 0,
            rva_total: 0,
        };
    }

    // Parse metadata
    let metadata = match MetadataParser::new().parse_file(metadata_path) {
        Ok(m) => m,
        Err(e) => {
            return DumpResult {
                success: false,
                log: vec![format!("Gagal parse metadata: {}", e)],
                types_count: 0,
                methods_count: 0,
                rva_resolved: 0,
                rva_total: 0,
            };
        }
    };

    log.push(format!("metadata magic: 0x{:X}", metadata.magic));
    log.push(format!("metadata version: {}", metadata.version));
    log.push(format!("metadata file size: {}", metadata.file_size));
    log.push(format!(
        "exported string literals: {}",
        metadata.string_literals.len()
    ));
    log.push(format!("images: {}", metadata.images.len()));
    log.push(format!("types: {}", metadata.types.len()));
    log.push(format!("fields: {}", metadata.fields.len()));
    log.push(format!("methods: {}", metadata.methods.len()));
    log.push(format!("parameters: {}", metadata.parameters.len()));

    // Parse ELF
    let elf_info = match ElfParser::new().parse_file(lib_path) {
        Ok(e) => e,
        Err(e) => {
            return DumpResult {
                success: false,
                log: vec![format!("Gagal parse ELF: {}", e)],
                types_count: 0,
                methods_count: 0,
                rva_resolved: 0,
                rva_total: 0,
            };
        }
    };

    log.push(format!(
        "ELF: {}, {}",
        if elf_info.is_64bit { "64-bit" } else { "32-bit" },
        if elf_info.is_little_endian { "LE" } else { "BE" }
    ));
    log.push(format!(
        "ELF segments: {}, sections: {}",
        elf_info.segments.len(),
        elf_info.sections.len()
    ));
    log.push(format!(
        "ELF symbols: {} ({} functions)",
        elf_info.symbols.len(),
        elf_info.symbols.iter().filter(|s| s.is_function() && s.is_defined()).count()
    ));

    let code_segments: Vec<_> = elf_info
        .load_segments()
        .into_iter()
        .filter(|s| (s.flags & 0x1) != 0)
        .collect();
    let code_start = code_segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    let code_end = code_segments
        .iter()
        .map(|s| s.vaddr + s.memsz)
        .max()
        .unwrap_or(0);
    log.push(format!(
        "Code range: 0x{:x} - 0x{:x}",
        code_start, code_end
    ));

    for seg in &elf_info.segments {
        log.push(format!(
            "  Segment: type={} flags=0x{:x} vaddr=0x{:x} filesz={} memsz={}",
            seg.segment_type, seg.flags, seg.vaddr, seg.filesz, seg.memsz
        ));
    }
    for sec in elf_info.sections.iter().take(29) {
        log.push(format!(
            "  Section: name='{}' type={} flags=0x{:x} addr=0x{:x} offset=0x{:x} size={}",
            sec.name, sec.section_type, sec.flags, sec.addr, sec.offset, sec.size
        ));
    }

    // Read lib bytes for RVA resolver
    let lib_bytes = match std::fs::read(lib_path) {
        Ok(b) => b,
        Err(e) => {
            return DumpResult {
                success: false,
                log: vec![format!("Gagal baca libil2cpp: {}", e)],
                types_count: 0,
                methods_count: 0,
                rva_resolved: 0,
                rva_total: 0,
            };
        }
    };

    // Resolve RVA
    let mut rva_resolver = RvaResolver::new();
    let rva_result = rva_resolver.resolve(&elf_info, &metadata, &lib_bytes);
    log.push(format!(
        "RVA resolved: {}/{} methods ({}%)",
        rva_result.resolved_count(),
        rva_result.total_methods,
        (rva_result.resolution_rate() * 100.0) as u32
    ));
    log.push(format!("Types with RVA: {}", rva_result.type_rvas.len()));
    for line in &rva_resolver.debug_log {
        log.push(format!("  [RVA] {}", line));
    }

    // Write output files

    if generate_summary {
        let path = format!("{}/metadata_summary.json", output_dir);
        if let Err(e) = json_writers::write_summary(&metadata, &path) {
            log.push(format!("Gagal tulis summary: {}", e));
        } else {
            log.push(format!("wrote: {}", path));
        }
    }

    let rva_path = format!("{}/rva_report.json", output_dir);
    if let Err(e) = json_writers::write_rva_report(&rva_result, &metadata, &rva_path) {
        log.push(format!("Gagal tulis RVA report: {}", e));
    } else {
        log.push(format!("wrote: {}", rva_path));
    }

    let sl_path = format!("{}/stringliteral.json", output_dir);
    if let Err(e) =
        json_writers::write_string_literals(&metadata, &sl_path, max_string_literals)
    {
        log.push(format!("Gagal tulis string literals: {}", e));
    } else {
        log.push(format!("wrote: {}", sl_path));
    }

    let dump_cs_path = format!("{}/dump.cs", output_dir);
    let writer = dump_cs_writer::DumpCsWriter {
        include_rva_info,
        include_inheritance,
    };
    match writer.write_with_elf(&metadata, &dump_cs_path, &rva_result, Some(&elf_info), Some(&lib_bytes)) {
        Ok(count) => {
            log.push(format!("dump.cs types written: {}", count));
            log.push(format!("wrote: {}", dump_cs_path));
        }
        Err(e) => {
            log.push(format!("Gagal tulis dump.cs: {}", e));
        }
    }

    let log_path = format!("{}/engine_log.txt", output_dir);
    let _ = json_writers::write_log(&log, &log_path);

    let types_count = metadata.types.len();
    let methods_count = metadata.methods.len();

    DumpResult {
        success: true,
        log,
        types_count,
        methods_count,
        rva_resolved: rva_result.resolved_count(),
        rva_total: rva_result.total_methods,
    }
}

/// Result of a dump operation
pub struct DumpResult {
    pub success: bool,
    pub log: Vec<String>,
    pub types_count: usize,
    pub methods_count: usize,
    pub rva_resolved: usize,
    pub rva_total: usize,
}

