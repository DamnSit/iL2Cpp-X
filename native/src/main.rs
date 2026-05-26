use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: il2cpp_dump <libil2cpp.so> <global-metadata.dat> [output_dir]");
        eprintln!("       il2cpp_dump --diagnose <global-metadata.dat>");
        std::process::exit(1);
    }

    if args[1] == "--diagnose" {
        diagnose_metadata(&args[2]);
        return;
    }

    let lib_path = &args[1];
    let metadata_path = &args[2];
    let output_dir = if args.len() > 3 {
        &args[3]
    } else {
        "dump_output"
    };

    println!("IL2CPP X Rust dumper");
    println!("libil2cpp: {}", lib_path);
    println!("metadata:  {}", metadata_path);
    println!("output:    {}", output_dir);
    println!();

    let result = il2cpp_native::dump(lib_path, metadata_path, output_dir, true, true, true, 10000);

    for line in &result.log {
        println!("{}", line);
    }

    if result.success {
        println!();
        println!("SUCCESS: {} types, {} methods, RVA {}/{} ({}%)",
            result.types_count,
            result.methods_count,
            result.rva_resolved,
            result.rva_total,
            if result.rva_total > 0 { result.rva_resolved * 100 / result.rva_total } else { 0 }
        );
    } else {
        println!();
        println!("FAILED");
        std::process::exit(1);
    }
}

fn diagnose_metadata(path: &str) {
    use il2cpp_native::metadata_parser::MetadataParser;

    let result = MetadataParser::new().parse_file(path).expect("Failed to parse metadata");
    println!("Metadata version: {} ({}-byte strings)", result.version,
        if result.string_offsets.is_empty() { "null-term" } else { "varint" });
    println!("Types: {}", result.types.len());
    println!("Images: {}", result.images.len());
    println!("Methods: {}", result.methods.len());
    println!("Fields: {}", result.fields.len());
    println!("Parameters: {}", result.parameters.len());

    println!("\n--- Images (first 10) ---");
    for img in result.images.iter().take(10) {
        println!("  Image {}: name=\"{}\" typeStart={} typeCount={}", img.index, img.name, img.type_start, img.type_count);
    }

    println!("\n--- Types (first 10) ---");
    for t in result.types.iter().take(10) {
        println!("  Type {}: name=\"{}\" ns=\"{}\" methods={} fields={}", t.index, t.name, t.namespace_name, t.method_count, t.field_count);
    }

    // Count images with valid type ranges
    let valid_images: Vec<_> = result.images.iter()
        .filter(|img| img.type_start + img.type_count <= result.types.len() && img.type_count > 0)
        .collect();
    println!("\nImages with valid type ranges: {}", valid_images.len());
    let total_types_covered: usize = valid_images.iter().map(|i| i.type_count).sum();
    println!("Total types covered by images: {}", total_types_covered);

    // Check if image type ranges overlap
    let mut seen = std::collections::HashSet::new();
    let mut overlapping = 0;
    for img in &valid_images {
        for idx in img.type_start..(img.type_start + img.type_count) {
            if !seen.insert(idx) {
                overlapping += 1;
            }
        }
    }
    println!("Overlapping type indices: {}", overlapping);
    println!("Unique type indices covered: {}", seen.len());
}
