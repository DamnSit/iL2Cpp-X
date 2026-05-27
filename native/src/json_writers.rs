use std::io::{BufWriter, Write};

use crate::metadata_models::*;
use crate::rva_resolver::RvaResult;

pub fn write_summary(metadata: &MetadataParseResult, path: &str) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut w = BufWriter::new(file);

    writeln!(w, "{{")?;
    writeln!(w, "  \"magic\": \"0x{:X}\",", metadata.magic)?;
    writeln!(w, "  \"version\": {},", metadata.version)?;
    writeln!(w, "  \"fileSize\": {},", metadata.file_size)?;
    writeln!(
        w,
        "  \"stringLiteralCountExported\": {},",
        metadata.string_literals.len()
    )?;
    writeln!(w, "  \"tables\": [")?;

    for (i, range) in metadata.ranges.iter().enumerate() {
        write!(w, "    {{")?;
        write!(w, "\"name\": \"{}\"", json_escape(&range.name))?;
        write!(w, ", \"offset\": {}", range.offset)?;
        write!(w, ", \"size\": {}", range.size)?;
        write!(w, ", \"countPair\": {}", range.count_pair())?;
        write!(w, "}}")?;
        if i < metadata.ranges.len() - 1 {
            write!(w, ",")?;
        }
        writeln!(w)?;
    }

    writeln!(w, "  ]")?;
    writeln!(w, "}}")?;
    w.flush()
}

pub fn write_string_literals(
    metadata: &MetadataParseResult,
    path: &str,
    max_count: usize,
) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut w = BufWriter::new(file);
    let limit = if max_count == 0 { metadata.string_literals.len() } else { max_count.min(metadata.string_literals.len()) };

    writeln!(w, "[")?;
    for (i, lit) in metadata.string_literals.iter().take(limit).enumerate() {
        write!(w, "  {{")?;
        write!(w, "\"index\": {}", lit.index)?;
        write!(w, ", \"dataIndex\": {}", lit.data_index)?;
        write!(w, ", \"length\": {}", lit.length)?;
        write!(w, ", \"value\": \"{}\"", json_escape(&lit.value))?;
        write!(w, "}}")?;
        if i < limit - 1 {
            write!(w, ",")?;
        }
        writeln!(w)?;
    }
    writeln!(w, "]")?;
    w.flush()
}

pub fn write_rva_report(
    rva_result: &RvaResult,
    metadata: &MetadataParseResult,
    path: &str,
) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut w = BufWriter::new(file);

    writeln!(w, "{{")?;
    writeln!(w, "  \"totalMethods\": {},", rva_result.total_methods)?;
    writeln!(w, "  \"resolvedMethods\": {},", rva_result.resolved_count())?;
    writeln!(
        w,
        "  \"unresolvedMethods\": {},",
        rva_result.unresolved_count
    )?;
    writeln!(
        w,
        "  \"resolutionRate\": {},",
        (rva_result.resolution_rate() * 100.0) as u32
    )?;
    writeln!(
        w,
        "  \"typesWithRva\": {},",
        rva_result.type_rvas.len()
    )?;
    writeln!(w, "  \"methods\": [")?;

    let mut count = 0;
    for (index, method) in metadata.methods.iter().enumerate() {
        if let Some(rva) = rva_result.method_rvas.get(&index) {
            if count > 0 {
                writeln!(w, ",")?;
            }
            write!(w, "    {{")?;
            write!(w, "\"index\": {}", index)?;
            write!(w, ", \"name\": \"{}\"", json_escape(&method.name))?;
            write!(w, ", \"rva\": \"{}\"", rva.hex_rva())?;
            write!(w, ", \"size\": {}", rva.size)?;
            write!(
                w,
                ", \"symbol\": \"{}\"",
                json_escape(&rva.symbol_name)
            )?;
            write!(w, "}}")?;
            count += 1;
        }
    }
    writeln!(w)?;
    writeln!(w, "  ]")?;
    writeln!(w, "}}")?;
    w.flush()
}

pub fn write_log(lines: &[String], path: &str) -> std::io::Result<()> {
    let mut content = lines.join("\n");
    content.push('\n');
    std::fs::write(path, content)
}

fn json_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ if (ch as u32) < 0x20 => {
                result.push_str(&format!("\\u{:04x}", ch as u32));
            }
            _ => result.push(ch),
        }
    }
    result
}
