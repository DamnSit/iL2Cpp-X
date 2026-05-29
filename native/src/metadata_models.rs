#[derive(Clone, Debug)]
pub struct MetadataRange {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

impl MetadataRange {
    pub fn count_pair(&self) -> usize {
        self.size / 8
    }
}

#[derive(Clone, Debug)]
pub struct MetadataImage {
    pub index: usize,
    pub name: String,
    pub type_start: usize,
    pub type_count: usize,
}

#[derive(Clone, Debug)]
pub struct MetadataTypeDefinition {
    pub index: usize,
    pub name: String,
    pub namespace_name: String,
    pub byval_type_index: i32,
    pub field_start: usize,
    pub method_start: usize,
    pub property_start: usize,
    pub field_count: usize,
    pub method_count: usize,
    pub property_count: usize,
    pub parent_index: i32,
    pub flags: u32,
    pub bitfield: u32,
}

#[derive(Clone, Debug)]
pub struct MetadataFieldDefinition {
    pub index: usize,
    pub name: String,
    pub type_index: usize,
}

#[derive(Clone, Debug)]
pub struct MetadataMethodDefinition {
    pub index: usize,
    pub name: String,
    pub return_type: usize,
    pub parameter_start: usize,
    pub parameter_count: usize,
    pub token: u32,
    pub flags: u16,
    pub iflags: u16,
}

#[derive(Clone, Debug)]
pub struct MetadataParameterDefinition {
    pub index: usize,
    pub name: String,
    pub type_index: usize,
}

#[derive(Clone, Debug)]
pub struct StringLiteral {
    pub index: usize,
    pub data_index: usize,
    pub length: usize,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct MetadataParseResult {
    pub magic: u32,
    pub version: u32,
    pub file_size: usize,
    pub ranges: Vec<MetadataRange>,
    pub string_literals: Vec<StringLiteral>,
    pub images: Vec<MetadataImage>,
    pub types: Vec<MetadataTypeDefinition>,
    pub fields: Vec<MetadataFieldDefinition>,
    pub methods: Vec<MetadataMethodDefinition>,
    pub parameters: Vec<MetadataParameterDefinition>,
    pub string_offsets: Vec<u32>,
    pub field_default_values: std::collections::HashMap<usize, String>,
}
