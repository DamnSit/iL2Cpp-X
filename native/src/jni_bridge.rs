use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::elf_parser::ElfParser;
use crate::metadata_parser::MetadataParser;
use crate::rva_resolver::RvaResolver;
use crate::dump_cs_writer::DumpCsWriter;
use crate::json_writers;

/// Core dump function - works on any platform
pub fn dump_native(
    lib_path: &str,
    metadata_path: &str,
    output_dir: &str,
    include_rva_info: bool,
) -> String {
    // Parse metadata
    let metadata = match MetadataParser::new().parse_file(metadata_path) {
        Ok(m) => m,
        Err(e) => return format!(r#"{{"success":false,"error":"{}"}}"#, escape_json(&e.to_string())),
    };

    // Parse ELF
    let elf_info = match ElfParser::new().parse_file(lib_path) {
        Ok(e) => e,
        Err(e) => return format!(r#"{{"success":false,"error":"{}"}}"#, escape_json(&e.to_string())),
    };

    // Read lib bytes for RVA resolver
    let lib_bytes = match std::fs::read(lib_path) {
        Ok(b) => b,
        Err(e) => return format!(r#"{{"success":false,"error":"{}"}}"#, escape_json(&e.to_string())),
    };

    // Resolve RVA
    let mut resolver = RvaResolver::new();
    let rva_result = resolver.resolve(&elf_info, &metadata, &lib_bytes);

    // Create output dir
    let _ = std::fs::create_dir_all(output_dir);

    // Build log
    let mut log_lines = Vec::new();
    log_lines.push("IL2CPP X Rust native dumper".to_string());
    log_lines.push(format!("libil2cpp: {} ({} bytes)", lib_path, lib_bytes.len()));
    log_lines.push(format!("metadata: {} ({} bytes)", metadata_path, metadata.file_size));
    log_lines.push(format!("output: {}", output_dir));
    log_lines.push(format!("ELF: {} {}, {} symbols",
        if elf_info.is_64bit { "64-bit" } else { "32-bit" },
        if elf_info.is_little_endian { "LE" } else { "BE" },
        elf_info.symbols.len()));
    log_lines.push(format!("metadata version: {}", metadata.version));
    log_lines.push(format!("RVA resolved: {}/{} methods ({}%)",
        rva_result.resolved_count(), rva_result.total_methods,
        (rva_result.resolution_rate() * 100.0) as u32));
    for line in &resolver.debug_log {
        log_lines.push(format!("  [RVA] {}", line));
    }

    // Write summary
    let summary_path = format!("{}/metadata_summary.json", output_dir);
    let _ = json_writers::write_summary(&metadata, &summary_path);

    // Write RVA report
    let rva_path = format!("{}/rva_report.json", output_dir);
    let _ = json_writers::write_rva_report(&rva_result, &metadata, &rva_path);

    // Write string literals
    let sl_path = format!("{}/stringliteral.json", output_dir);
    let _ = json_writers::write_string_literals(&metadata, &sl_path);

    // Write dump.cs
    let dump_cs_path = format!("{}/dump.cs", output_dir);
    let writer = DumpCsWriter {
        include_rva_info,
        include_inheritance: true,
    };
    let types_written = match writer.write(&metadata, &dump_cs_path, &rva_result) {
        Ok(n) => n,
        Err(e) => {
            log_lines.push(format!("dump.cs write error: {}", e));
            0
        }
    };

    // Write log
    let log_path = format!("{}/engine_log.txt", output_dir);
    let _ = json_writers::write_log(&log_lines, &log_path);

    format!(
        r#"{{"success":true,"types":{},"methods":{},"resolvedMethods":{},"typesWritten":{},"resolutionRate":{}}}"#,
        metadata.types.len(),
        metadata.methods.len(),
        rva_result.resolved_count(),
        types_written,
        (rva_result.resolution_rate() * 100.0) as u32
    )
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r")
}

// C FFI functions (works for direct .so loading without JNI framework)
#[no_mangle]
pub extern "C" fn il2cpp_dump(
    lib_path: *const c_char,
    metadata_path: *const c_char,
    output_dir: *const c_char,
    include_rva_info: bool,
) -> *mut c_char {
    let lib_path = unsafe { CStr::from_ptr(lib_path) }.to_str().unwrap_or("");
    let metadata_path = unsafe { CStr::from_ptr(metadata_path) }.to_str().unwrap_or("");
    let output_dir = unsafe { CStr::from_ptr(output_dir) }.to_str().unwrap_or("");

    let result = dump_native(lib_path, metadata_path, output_dir, include_rva_info);
    CString::new(result).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn il2cpp_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}

// JNI bridge for Android
#[cfg(target_os = "android")]
mod android {
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::jstring;

    #[no_mangle]
    pub extern "system" fn Java_com_xuo_il2cppx_engine_NativeDumper_nativeDump(
        mut env: JNIEnv,
        _class: JClass,
        lib_path: JString,
        metadata_path: JString,
        output_dir: JString,
        include_rva: bool,
    ) -> jstring {
        let lib_path: String = env.get_string(&lib_path).unwrap().into();
        let metadata_path: String = env.get_string(&metadata_path).unwrap().into();
        let output_dir: String = env.get_string(&output_dir).unwrap().into();

        let result = super::dump_native(&lib_path, &metadata_path, &output_dir, include_rva);
        let output = env.new_string(&result).unwrap();
        output.into_raw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_native_missing_files() {
        let result = dump_native("/nonexistent/lib.so", "/nonexistent/meta.dat", "/tmp/out", true);
        assert!(result.contains("success"));
        assert!(result.contains("false"));
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json("line\nbreak"), "line\\nbreak");
    }
}
