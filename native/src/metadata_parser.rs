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

fn version_config(version: u32) -> VersionConfig {
    // TypeDef offsets
    let (type_def_size, type_field_start, type_method_start, type_property_start,
         type_method_count, type_property_count, type_field_count) = match version {
        16..=19 => (64,  56, 60, 68, 80, 82, 84),
        20..=22 => (72,  56, 60, 68, 80, 82, 84),
        23      => (80,  56, 60, 68, 80, 82, 84),
        24..=26 => (96,  52, 56, 64, 72, 74, 76),
        27..=28 => (104, 52, 56, 64, 72, 74, 76),
        29..=30 => (112, 52, 56, 64, 72, 74, 76),
        31..=32 => (120, 52, 56, 64, 72, 74, 76),
        33..=34 => (128, 52, 56, 64, 72, 74, 76),
        _       => (136, 52, 56, 64, 72, 74, 76), // v35+
    };

    // MethodDef offsets
    let (method_def_size, method_return_type, method_parameter_start,
         method_token, method_param_count, method_flags, method_iflags) = match version {
        16..=23 => (28, 8, 12, 24, 18, 20, 22),
        24..=30 => (32, 8, 12, 28, 20, 22, 24),
        31..=32 => (36, 8, 12, 32, 20, 22, 24),
        _       => (40, 8, 12, 32, 20, 22, 24), // v33+
    };

    // FieldDef
    let field_def_size = if version >= 33 { 16 } else { 12 };

    // ParameterDef
    let (param_def_size, param_type_index) = if version >= 24 {
        (16, 12)
    } else {
        (8, 4)
    };

    // ImageDef
    let (image_def_size, image_name_offset, image_type_start_offset, image_type_count_offset) = if version >= 31 {
        (64, 16, 8, 12)
    } else if version >= 24 {
        (40, 0, 8, 12)
    } else {
        (32, 0, 8, 12)
    };

    let use_varint_strings = version >= 33;
    let header_range_count = if version >= 24 { 34 } else { 24 };

    VersionConfig {
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
        use_varint_strings,
        header_range_count,
    }
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

        let config = version_config(version);
        let ranges = read_header_ranges(reader, config.header_range_count)?;
        validate_ranges(reader, &ranges)?;

        let string_literals = read_string_literals(reader, &ranges);
        let string_offsets = if config.use_varint_strings {
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
/// For v16-v32 (null-terminated), the string_index IS the byte offset, so no table is needed.
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
    if string_index == 0 || string_range.size == 0 {
        return String::new();
    }

    if use_varint {
        // v33+: string_index is a byte offset into the string pool.
        // Each entry is ULEB128 length prefix followed by that many bytes of string data.
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
        // v16-v32: null-terminated string at byte offset.
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
