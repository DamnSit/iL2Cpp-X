use crate::binary_reader::BinaryReader;
use crate::metadata_models::*;

const METADATA_MAGIC: u32 = 0xFAB11BAF;
const HEADER_MIN_SIZE: usize = 16;
const STRING_LITERAL_ENTRY_SIZE: usize = 8;
const MAX_STRING_LITERAL_EXPORT: usize = 5000;

const HEADER_RANGE_NAMES: &[&str] = &[
    "stringLiteral",                    // 0
    "stringLiteralData",                // 1
    "string",                           // 2
    "events",                           // 3
    "properties",                       // 4
    "methods",                          // 5
    "parameterDefaultValues",           // 6
    "fieldDefaultValues",               // 7
    "fieldAndParameterDefaultValueData",// 8
    "fieldMarshaledSizes",              // 9
    "parameters",                       // 10
    "fields",                           // 11
    "genericParameters",                // 12
    "genericParameterConstraints",      // 13
    "genericContainers",                // 14
    "nestedTypes",                      // 15
    "interfaces",                       // 16
    "vtableMethods",                    // 17
    "interfaceOffsets",                 // 18
    "typeDefinitions",                  // 19
    "rgctxEntries",                     // 20
    "images",                           // 21
    "assemblies",                       // 22
    "metadataUsageLists",               // 23
    "metadataUsagePairs",               // 24
    "fieldRefs",                        // 25
    "referencedAssemblies",             // 26
    "attributesInfo",                   // 27
    "attributeTypes",                   // 28
    "unresolvedVirtualCallParameterTypes",  // 29
    "unresolvedVirtualCallParameterRanges", // 30
    "windowsRuntimeTypeNames",          // 31
    "windowsRuntimeStrings",            // 32
    "exportedTypeDefinitions",          // 33
];

/// Version-dependent configuration for struct strides and field offsets.
struct VersionConfig {
    type_def_size: usize,
    type_field_start: usize,
    type_method_start: usize,
    type_property_start: usize,
    type_method_count: usize,
    type_property_count: usize,
    type_field_count: usize,

    method_def_size: usize,
    method_return_type: usize,
    method_parameter_start: usize,
    method_token: usize,
    method_param_count: usize,
    method_flags: usize,
    method_iflags: usize,

    field_def_size: usize,
    param_def_size: usize,
    param_type_index: usize,

    image_def_size: usize,
    image_name_offset: usize,
    image_type_start_offset: usize,
    image_type_count_offset: usize,

    use_varint_strings: bool,
    header_range_count: usize,
}

/// Detect the stride for a metadata table by testing candidate strides.
/// Returns the stride that produces the best combined score of valid strings + unique names + reasonable count.
fn detect_stride(
    reader: &BinaryReader,
    ranges: &[MetadataRange],
    table_name: &str,
    candidates: &[usize],
    use_varint: bool,
) -> usize {
    let table_range = match ranges.iter().find(|r| r.name == table_name) {
        Some(r) => r,
        None => return candidates[0],
    };
    if table_range.size == 0 {
        return candidates[0];
    }

    let string_range = match ranges.iter().find(|r| r.name == "string") {
        Some(r) => r,
        None => return candidates[0],
    };

    let mut best_stride = candidates[0];
    let mut best_score = 0i32;

    for &stride in candidates {
        if table_range.size % stride != 0 {
            continue;
        }
        let count = table_range.size / stride;
        if count < 2 {
            continue;
        }
        let sample = std::cmp::min(count, 50);
        let mut valid = 0i32;
        let mut unique_names = std::collections::HashSet::new();
        for i in 0..sample {
            let offset = table_range.offset + i * stride;
            if offset + 4 > reader.size() {
                break;
            }
            let name_idx = reader.read_i32_le(offset).unwrap_or(0);
            unique_names.insert(name_idx);
            if is_valid_string_index(reader, string_range, name_idx, use_varint) {
                valid += 1;
            }
        }
        // Score combines: valid string ratio + uniqueness ratio
        // Unique names are important — with wrong stride, consecutive entries share nameIndex
        let score = valid * 2 + unique_names.len() as i32;
        if score > best_score {
            best_score = score;
            best_stride = stride;
        }
    }

    best_stride
}

/// Check if a string index points to a valid non-empty string.
fn is_valid_string_index(
    reader: &BinaryReader,
    string_range: &MetadataRange,
    idx: i32,
    use_varint: bool,
) -> bool {
    if idx < 0 || string_range.size == 0 {
        return false;
    }
    let idx = idx as usize;
    if idx >= string_range.size {
        return false;
    }
    let abs = string_range.offset + idx;
    if abs >= reader.size() {
        return false;
    }
    if use_varint {
        match reader.read_uleb128(abs) {
            Some((len, _)) if len > 0 => {
                let s_start = abs + 1; // at least 1 byte consumed
                s_start + (len as usize) <= reader.size()
            }
            _ => false,
        }
    } else {
        // Check that the first two bytes look like a real string (not just any non-null byte)
        let b0 = match reader.read_u8(abs) {
            Some(b) if b != 0 => b,
            _ => return false,
        };
        // First byte should be a letter, underscore, or '<' (common in IL2CPP names)
        if !(b0.is_ascii_alphabetic() || b0 == b'_' || b0 == b'<') {
            return false;
        }
        // Second byte should be non-null (strings are at least 2 chars for stride detection)
        match reader.read_u8(abs + 1) {
            Some(b) if b != 0 => true,
            _ => false,
        }
    }
}

/// Detect the TypeDef field offsets by analyzing the data.
/// Returns (field_start, method_start, property_start, method_count, property_count, field_count).
fn detect_type_offsets(
    reader: &BinaryReader,
    ranges: &[MetadataRange],
    type_range: &MetadataRange,
    stride: usize,
    version: u32,
) -> (usize, usize, usize, usize, usize, usize) {
    // Known layouts by version range (from Cpp2IL analysis)
    // (field_start, method_start, property_start, method_count_offset, property_count_offset, field_count_offset)
    // These are the MOST COMMON layouts. We validate them below.
    let candidates: Vec<(usize, usize, usize, usize, usize, usize)> = match stride {
        // (field_start, method_start, property_start, method_count_offset, property_count_offset, field_count_offset)
        64 => vec![
            (28, 32, 40, 48, 50, 52), // v16-v23 stride 64
        ],
        72 => vec![
            (28, 32, 40, 48, 50, 52), // v16-v23 stride 72
        ],
        80 => vec![
            (28, 32, 40, 56, 58, 60), // v16-v23 stride 80
        ],
        88 => vec![
            (32, 36, 44, 64, 66, 68), // v31 stride 88 confirmed
        ],
        96 => vec![
            (32, 36, 44, 64, 66, 68), // v24-v30
            (52, 56, 64, 72, 74, 76),
        ],
        104 => vec![
            (52, 56, 64, 72, 74, 76), // v27-v28
        ],
        112 => vec![
            (52, 56, 64, 72, 74, 76), // v29-v30
        ],
        120 => vec![
            (52, 56, 64, 72, 74, 76), // v31-v32
        ],
        128 => vec![
            (52, 56, 64, 72, 74, 76), // v33-v34
        ],
        136 => vec![
            (52, 56, 64, 72, 74, 76), // v35+
        ],
        _ => vec![
            (52, 56, 64, 72, 74, 76), // default
            (28, 32, 40, 48, 50, 52), // compact
            (32, 36, 44, 64, 66, 68),
        ],
    };

    let string_range = match ranges.iter().find(|r| r.name == "string") {
        Some(r) => r,
        None => return candidates[0],
    };

    // For each candidate layout, check if the namespaceIndex at +4 produces valid strings
    // and if method_count values are reasonable (< 1000 for most types)
    let mut best = candidates[0];
    let mut best_score = 0i32;

    for &(fs, ms, ps, mc, pc, fc) in &candidates {
        if fs + 4 > stride || ms + 4 > stride || ps + 4 > stride
            || mc + 2 > stride || pc + 2 > stride || fc + 2 > stride
        {
            continue;
        }

        let sample = std::cmp::min(type_range.size / stride, 100);
        let mut score = 0i32;

        for i in 0..sample {
            let offset = type_range.offset + i * stride;

            // Check namespaceIndex at +4
            let ns_idx = reader.read_i32_le(offset + 4).unwrap_or(0);
            if ns_idx >= 0 && (ns_idx as usize) < string_range.size {
                score += 1;
            }

            // Check method_count is reasonable
            let method_count = reader.read_u16_le(offset + mc).unwrap_or(0xFFFF);
            if method_count < 1000 {
                score += 2;
            }

            // Check field_count is reasonable
            let field_count = reader.read_u16_le(offset + fc).unwrap_or(0xFFFF);
            if field_count < 5000 {
                score += 1;
            }
        }

        if score > best_score {
            best_score = score;
            best = (fs, ms, ps, mc, pc, fc);
        }
    }

    best
}

pub struct MetadataParser;

impl MetadataParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_file(&self, path: &str) -> std::io::Result<MetadataParseResult> {
        let reader = BinaryReader::from_file(path)?;
        self.parse_reader(&reader)
    }

    pub fn parse_reader(&self, reader: &BinaryReader) -> std::io::Result<MetadataParseResult> {
        if reader.size() < HEADER_MIN_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("global-metadata.dat terlalu kecil: {} bytes", reader.size()),
            ));
        }

        let magic = reader.read_u32_le(0).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Gagal membaca magic")
        })?;
        if magic != METADATA_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Magic metadata tidak valid: 0x{:x}", magic),
            ));
        }

        let version = reader.read_u32_le(4).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Gagal membaca version")
        })?;

        let use_varint = version >= 33;
        let header_range_count = if version >= 24 { 34 } else { 24 };

        let ranges = read_header_ranges(reader, header_range_count)?;
        validate_ranges(reader, &ranges)?;

        // Auto-detect strides
        let type_def_size = detect_stride(
            reader, &ranges, "typeDefinitions",
            &[64, 72, 80, 88, 96, 104, 112, 120, 128, 136],
            use_varint,
        );
        let method_def_size = detect_stride(
            reader, &ranges, "methods",
            &[24, 28, 32, 36, 40, 44],
            use_varint,
        );
        let field_def_size = detect_stride(
            reader, &ranges, "fields",
            &[8, 12, 16],
            use_varint,
        );
        let param_def_size = detect_stride(
            reader, &ranges, "parameters",
            &[8, 12, 16],
            use_varint,
        );
        let image_def_size = detect_stride(
            reader, &ranges, "images",
            &[24, 32, 40, 48, 56, 64],
            use_varint,
        );

        // Detect TypeDef field offsets
        let type_range = ranges.iter().find(|r| r.name == "typeDefinitions");
        let (type_field_start, type_method_start, type_property_start,
             type_method_count, type_property_count, type_field_count) =
            if let Some(tr) = type_range {
                detect_type_offsets(reader, &ranges, tr, type_def_size, version)
            } else {
                (52, 56, 64, 72, 74, 76)
            };

        // ImageDef name offset detection: find which i32 offset has valid string indices
        let image_name_offset = detect_image_name_offset(reader, &ranges, image_def_size);
        let (image_type_start_offset, image_type_count_offset) =
            detect_image_type_offsets(reader, &ranges, image_def_size, image_name_offset);

        // MethodDef field offsets
        let method_range = ranges.iter().find(|r| r.name == "methods");
        let (method_return_type, method_parameter_start, method_token,
             method_param_count, method_flags, method_iflags) =
            if let Some(mr) = method_range {
                detect_method_offsets(reader, &ranges, mr, method_def_size, version)
            } else {
                (8, 12, 32, 24, 26, 28)
            };

        // ParameterDef type_index offset:
        // stride 8:  nameIndex(+0), typeIndex(+4)
        // stride 12: nameIndex(+0), token(+4), typeIndex(+8)
        // stride 16: nameIndex(+0), token(+4), typeIndex(+8), extra(+12)
        let param_type_index = match param_def_size {
            8 => 4,
            _ => 8, // 12 and 16 both have typeIndex at +8
        };

        let config = VersionConfig {
            type_def_size,
            type_field_start,
            type_method_start,
            type_property_start,
            type_method_count,
            type_property_count,
            type_field_count,
            method_def_size,
            method_return_type,
            method_parameter_start,
            method_token,
            method_param_count,
            method_flags,
            method_iflags,
            field_def_size,
            param_def_size,
            param_type_index,
            image_def_size,
            image_name_offset,
            image_type_start_offset,
            image_type_count_offset,
            use_varint_strings: use_varint,
            header_range_count,
        };

        let string_literals = read_string_literals(reader, &ranges);
        let string_offsets = if use_varint {
            build_string_offsets(reader, &ranges)
        } else {
            Vec::new()
        };
        let images = read_images(reader, &ranges, &config);
        let types = read_types(reader, &ranges, &config);
        let fields = read_fields(reader, &ranges, &config);
        let methods = read_methods(reader, &ranges, &config);
        let parameters = read_parameters(reader, &ranges, &config);

        Ok(MetadataParseResult {
            magic,
            version,
            file_size: reader.size(),
            ranges,
            string_literals,
            images,
            types,
            fields,
            methods,
            parameters,
            string_offsets,
        })
    }
}

/// Read a null-terminated string at absolute offset, return it if it looks like an image name.
fn read_nt_string_at(reader: &BinaryReader, abs_offset: usize) -> Option<String> {
    if abs_offset >= reader.size() {
        return None;
    }
    let mut len = 0;
    while len < 256 && abs_offset + len < reader.size() {
        match reader.read_u8(abs_offset + len) {
            Some(0) | None => break,
            _ => len += 1,
        }
    }
    if len < 2 {
        return None;
    }
    reader.utf8_string(abs_offset, len)
}

/// Score a string as a plausible image/assembly name.
/// Names like "Assembly-CSharp.dll", "mscorlib.dll", "UnityEngine.dll" score high.
fn score_image_name(s: &str) -> i32 {
    if s.is_empty() {
        return 0;
    }
    let mut score = 0i32;
    // Contains a dot (like ".dll") is a strong signal
    if s.contains('.') {
        score += 10;
    }
    // Contains a hyphen (like "Assembly-CSharp")
    if s.contains('-') {
        score += 5;
    }
    // Length between 3 and 80 is reasonable
    if s.len() >= 3 && s.len() <= 80 {
        score += 3;
    }
    // All alphanumeric + common chars
    if s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_') {
        score += 2;
    }
    score
}

/// Detect the ImageDef nameIndex offset by finding which i32 field produces the best image names.
fn detect_image_name_offset(
    reader: &BinaryReader,
    ranges: &[MetadataRange],
    stride: usize,
) -> usize {
    let image_range = match ranges.iter().find(|r| r.name == "images") {
        Some(r) => r,
        None => return 0,
    };
    let string_range = match ranges.iter().find(|r| r.name == "string") {
        Some(r) => r,
        None => return 0,
    };
    let count = image_range.size / stride;
    if count < 2 {
        return 0;
    }

    let mut best_offset = 0usize;
    let mut best_score = 0i32;

    for off in (0..stride).step_by(4) {
        let mut total_score = 0i32;
        for i in 0..std::cmp::min(count, 30) {
            let base = image_range.offset + i * stride;
            let idx = reader.read_i32_le(base + off).unwrap_or(0);
            if idx > 0 && (idx as usize) < string_range.size {
                let abs = string_range.offset + idx as usize;
                if let Some(s) = read_nt_string_at(reader, abs) {
                    total_score += score_image_name(&s);
                }
            }
        }
        if total_score > best_score {
            best_score = total_score;
            best_offset = off;
        }
    }
    best_offset
}

/// Detect the ImageDef typeStart and typeCount offsets.
fn detect_image_type_offsets(
    reader: &BinaryReader,
    ranges: &[MetadataRange],
    stride: usize,
    name_offset: usize,
) -> (usize, usize) {
    let image_range = match ranges.iter().find(|r| r.name == "images") {
        Some(r) => r,
        None => return (8, 12),
    };
    let count = image_range.size / stride;
    if count < 3 {
        return (8, 12);
    }

    // typeStart should be sequential (0, X, Y, Z...) and typeCount should be > 0 for most images
    let mut best = (8usize, 12usize);
    let mut best_score = 0i32;

    for ts_off in (0..stride).step_by(4) {
        if ts_off == name_offset {
            continue;
        }
        for tc_off in (ts_off + 4..stride).step_by(4) {
            if tc_off == name_offset || tc_off == ts_off {
                continue;
            }
            let mut score = 0i32;
            let mut prev_end: i32 = -1;
            for i in 0..std::cmp::min(count, 30) {
                let base = image_range.offset + i * stride;
                let ts = reader.read_i32_le(base + ts_off).unwrap_or(-1);
                let tc = reader.read_i32_le(base + tc_off).unwrap_or(0);
                // typeStart should be >= previous end (sequential)
                if ts >= 0 && tc > 0 && tc < 100000 {
                    score += 2;
                    if ts >= prev_end {
                        score += 1;
                    }
                    prev_end = ts + tc;
                }
            }
            if score > best_score {
                best_score = score;
                best = (ts_off, tc_off);
            }
        }
    }
    best
}

/// Detect MethodDef field offsets by testing candidate layouts.
/// Returns (return_type, parameter_start, token, param_count, flags, iflags).
fn detect_method_offsets(
    reader: &BinaryReader,
    ranges: &[MetadataRange],
    method_range: &MetadataRange,
    stride: usize,
    _version: u32,
) -> (usize, usize, usize, usize, usize, usize) {
    let param_range = ranges.iter().find(|r| r.name == "parameters");
    let param_size = param_range.map(|r| r.size).unwrap_or(0);

    // Candidate layouts: (return_type, parameter_start, token, param_count, flags, iflags)
    let candidates: Vec<(usize, usize, usize, usize, usize, usize)> = match stride {
        24..=28 => vec![
            (8, 12, 24, 18, 20, 22), // v16-v23 standard
        ],
        30..=32 => vec![
            (8, 12, 28, 20, 22, 24), // v24-v30 standard (4-byte genericContainerIndex)
        ],
        34..=36 => vec![
            // 64-bit genericContainerIndex at +16 (8 bytes)
            (8, 12, 32, 24, 26, 28),
            // 4-byte genericContainerIndex at +16 + extra field at end
            (8, 12, 32, 20, 22, 24),
        ],
        _ => vec![
            (8, 12, 32, 24, 26, 28), // 64-bit genericContainerIndex
            (8, 12, 32, 20, 22, 24), // 4-byte genericContainerIndex
        ],
    };

    let count = method_range.size / stride;
    if count < 2 {
        return candidates[0];
    }

    let sample = std::cmp::min(count, 200);
    let mut best = candidates[0];
    let mut best_score = 0i32;

    for &(rt, ps, _tk, pc, _fl, _ifl) in &candidates {
        if ps + 4 > stride || pc + 2 > stride {
            continue;
        }
        let mut score = 0i32;
        for i in 0..sample {
            let offset = method_range.offset + i * stride;
            // Check parameterCount is reasonable
            let param_count = reader.read_u16_le(offset + pc).unwrap_or(0xFFFF);
            if param_count < 200 {
                score += 2;
            }
            // Check parameterStart is within parameter table range
            let param_start = reader.read_i32_le(offset + ps).unwrap_or(-1);
            if param_start >= 0 && (param_start as usize) < param_size {
                score += 2;
            }
        }
        if score > best_score {
            best_score = score;
            best = (rt, ps, _tk, pc, _fl, _ifl);
        }
    }

    best
}

fn read_header_ranges(reader: &BinaryReader, count: usize) -> std::io::Result<Vec<MetadataRange>> {
    let mut ranges = Vec::new();
    let mut offset = 8;
    let limit = std::cmp::min(count, HEADER_RANGE_NAMES.len());

    for name_index in 0..limit {
        if offset + 8 > reader.size() {
            break;
        }
        let table_offset = reader.read_i32_le(offset).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Gagal membaca range offset")
        })? as usize;
        let table_size = reader.read_i32_le(offset + 4).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Gagal membaca range size")
        })? as usize;

        ranges.push(MetadataRange {
            name: HEADER_RANGE_NAMES[name_index].to_string(),
            offset: table_offset,
            size: table_size,
        });

        offset += 8;
    }

    Ok(ranges)
}

fn validate_ranges(reader: &BinaryReader, ranges: &[MetadataRange]) -> std::io::Result<()> {
    for range in ranges {
        if range.offset == 0 && range.size == 0 {
            continue;
        }
        if !reader.is_valid_range(range.offset, range.size) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Table {} keluar batas: offset={} size={} file={}", range.name, range.offset, range.size, reader.size()),
            ));
        }
    }
    Ok(())
}

/// Build a lookup table of byte offsets for each string in the string pool (v33+ varint format).
fn build_string_offsets(reader: &BinaryReader, ranges: &[MetadataRange]) -> Vec<u32> {
    let string_range = match ranges.iter().find(|r| r.name == "string") {
        Some(r) => r,
        None => return Vec::new(),
    };
    if string_range.size == 0 {
        return Vec::new();
    }

    let mut offsets = Vec::new();
    let mut pos = string_range.offset;
    let end = string_range.offset + string_range.size;

    while pos < end {
        offsets.push((pos - string_range.offset) as u32);
        match reader.read_uleb128(pos) {
            Some((length, consumed)) => {
                pos += consumed + length as usize;
            }
            None => break,
        }
    }
    offsets
}

fn read_metadata_string(
    reader: &BinaryReader,
    ranges: &[MetadataRange],
    string_index: usize,
    use_varint: bool,
) -> String {
    let string_range = match ranges.iter().find(|r| r.name == "string") {
        Some(r) => r,
        None => return String::new(),
    };
    if string_range.size == 0 {
        return String::new();
    }

    if use_varint {
        if string_index >= string_range.size {
            return String::new();
        }
        let absolute_offset = string_range.offset + string_index;
        match reader.read_uleb128(absolute_offset) {
            Some((length, consumed)) => {
                reader.utf8_string(absolute_offset + consumed, length as usize).unwrap_or_default()
            }
            None => String::new(),
        }
    } else {
        if string_index >= string_range.size {
            return String::new();
        }
        let absolute_offset = string_range.offset + string_index;
        let mut length = 0;
        while length < string_range.size - string_index {
            match reader.read_u8(absolute_offset + length) {
                Some(0) | None => break,
                _ => length += 1,
            }
        }
        reader.utf8_string(absolute_offset, length).unwrap_or_default()
    }
}

fn read_images(reader: &BinaryReader, ranges: &[MetadataRange], config: &VersionConfig) -> Vec<MetadataImage> {
    let image_range = match ranges.iter().find(|r| r.name == "images") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let count = image_range.size / config.image_def_size;
    let mut images = Vec::with_capacity(count);
    for index in 0..count {
        let offset = image_range.offset + index * config.image_def_size;
        if offset + config.image_def_size > reader.size() { break; }
        let raw_type_start = reader.read_i32_le(offset + config.image_type_start_offset).unwrap_or(0);
        let raw_type_count = reader.read_i32_le(offset + config.image_type_count_offset).unwrap_or(0);
        let type_start = if raw_type_start >= 0 { raw_type_start as usize } else { 0 };
        let type_count = if raw_type_count > 0 { raw_type_count as usize } else { 0 };
        let name_index = reader.read_i32_le(offset + config.image_name_offset).unwrap_or(0) as usize;
        images.push(MetadataImage {
            index,
            name: read_metadata_string(reader, ranges, name_index, config.use_varint_strings),
            type_start,
            type_count,
        });
    }
    images
}

fn read_types(reader: &BinaryReader, ranges: &[MetadataRange], config: &VersionConfig) -> Vec<MetadataTypeDefinition> {
    let type_range = match ranges.iter().find(|r| r.name == "typeDefinitions") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let count = type_range.size / config.type_def_size;
    let mut types = Vec::with_capacity(count);
    for index in 0..count {
        let offset = type_range.offset + index * config.type_def_size;
        if offset + config.type_def_size > reader.size() { break; }
        let name_idx = reader.read_i32_le(offset).unwrap_or(0) as usize;
        let ns_idx = reader.read_i32_le(offset + 4).unwrap_or(0) as usize;
        types.push(MetadataTypeDefinition {
            index,
            name: read_metadata_string(reader, ranges, name_idx, config.use_varint_strings),
            namespace_name: read_metadata_string(reader, ranges, ns_idx, config.use_varint_strings),
            field_start: reader.read_i32_le(offset + config.type_field_start).unwrap_or(0) as usize,
            method_start: reader.read_i32_le(offset + config.type_method_start).unwrap_or(0) as usize,
            property_start: reader.read_i32_le(offset + config.type_property_start).unwrap_or(0) as usize,
            method_count: reader.read_u16_le(offset + config.type_method_count).unwrap_or(0) as usize,
            property_count: reader.read_u16_le(offset + config.type_property_count).unwrap_or(0) as usize,
            field_count: reader.read_u16_le(offset + config.type_field_count).unwrap_or(0) as usize,
        });
    }
    types
}

fn read_fields(reader: &BinaryReader, ranges: &[MetadataRange], config: &VersionConfig) -> Vec<MetadataFieldDefinition> {
    let field_range = match ranges.iter().find(|r| r.name == "fields") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let count = field_range.size / config.field_def_size;
    let mut fields = Vec::with_capacity(count);
    for index in 0..count {
        let offset = field_range.offset + index * config.field_def_size;
        if offset + config.field_def_size > reader.size() { break; }
        let name_idx = reader.read_i32_le(offset).unwrap_or(0) as usize;
        fields.push(MetadataFieldDefinition {
            index,
            name: read_metadata_string(reader, ranges, name_idx, config.use_varint_strings),
            type_index: reader.read_i32_le(offset + 4).unwrap_or(0) as usize,
        });
    }
    fields
}

fn read_methods(reader: &BinaryReader, ranges: &[MetadataRange], config: &VersionConfig) -> Vec<MetadataMethodDefinition> {
    let method_range = match ranges.iter().find(|r| r.name == "methods") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let count = method_range.size / config.method_def_size;
    let mut methods = Vec::with_capacity(count);
    for index in 0..count {
        let offset = method_range.offset + index * config.method_def_size;
        if offset + config.method_def_size > reader.size() { break; }
        let name_idx = reader.read_i32_le(offset).unwrap_or(0) as usize;
        methods.push(MetadataMethodDefinition {
            index,
            name: read_metadata_string(reader, ranges, name_idx, config.use_varint_strings),
            return_type: reader.read_i32_le(offset + config.method_return_type).unwrap_or(0) as usize,
            parameter_start: reader.read_i32_le(offset + config.method_parameter_start).unwrap_or(0) as usize,
            parameter_count: reader.read_u16_le(offset + config.method_param_count).unwrap_or(0) as usize,
            token: reader.read_u32_le(offset + config.method_token).unwrap_or(0),
            flags: reader.read_u16_le(offset + config.method_flags).unwrap_or(0),
            iflags: reader.read_u16_le(offset + config.method_iflags).unwrap_or(0),
        });
    }
    methods
}

fn read_parameters(reader: &BinaryReader, ranges: &[MetadataRange], config: &VersionConfig) -> Vec<MetadataParameterDefinition> {
    let param_range = match ranges.iter().find(|r| r.name == "parameters") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let count = param_range.size / config.param_def_size;
    let mut parameters = Vec::with_capacity(count);
    for index in 0..count {
        let offset = param_range.offset + index * config.param_def_size;
        if offset + config.param_def_size > reader.size() { break; }
        let name_idx = reader.read_i32_le(offset).unwrap_or(0) as usize;
        parameters.push(MetadataParameterDefinition {
            index,
            name: read_metadata_string(reader, ranges, name_idx, config.use_varint_strings),
            type_index: reader.read_i32_le(offset + config.param_type_index).unwrap_or(0) as usize,
        });
    }
    parameters
}

fn read_string_literals(reader: &BinaryReader, ranges: &[MetadataRange]) -> Vec<StringLiteral> {
    let literal_range = match ranges.iter().find(|r| r.name == "stringLiteral") {
        Some(r) => r,
        None => return Vec::new(),
    };
    let data_range = match ranges.iter().find(|r| r.name == "stringLiteralData") {
        Some(r) => r,
        None => return Vec::new(),
    };
    if literal_range.size == 0 || data_range.size == 0 {
        return Vec::new();
    }

    let count = literal_range.size / STRING_LITERAL_ENTRY_SIZE;
    let limit = std::cmp::min(count, MAX_STRING_LITERAL_EXPORT);
    let mut result = Vec::with_capacity(limit);

    for index in 0..limit {
        let entry_offset = literal_range.offset + index * STRING_LITERAL_ENTRY_SIZE;
        let length = reader.read_i32_le(entry_offset).unwrap_or(0) as usize;
        let data_index = reader.read_i32_le(entry_offset + 4).unwrap_or(0) as usize;
        let value = if length > 0 && data_index + length <= data_range.size {
            reader.utf8_string(data_range.offset + data_index, length).unwrap_or_default()
        } else {
            String::new()
        };
        result.push(StringLiteral {
            index,
            data_index,
            length,
            value,
        });
    }
    result
}
