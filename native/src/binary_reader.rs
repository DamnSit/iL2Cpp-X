use std::io::Read;

pub struct BinaryReader {
    data: Vec<u8>,
}

impl BinaryReader {
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(Self { data })
    }

    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        if offset < self.data.len() {
            Some(self.data[offset])
        } else {
            None
        }
    }

    pub fn read_u16_le(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.data.len() {
            Some(u16::from_le_bytes([self.data[offset], self.data[offset + 1]]))
        } else {
            None
        }
    }

    pub fn read_i32_le(&self, offset: usize) -> Option<i32> {
        if offset + 4 <= self.data.len() {
            Some(i32::from_le_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]))
        } else {
            None
        }
    }

    pub fn read_u32_le(&self, offset: usize) -> Option<u32> {
        self.read_i32_le(offset).map(|v| v as u32)
    }

    pub fn bytes(&self, offset: usize, length: usize) -> Option<&[u8]> {
        if offset + length <= self.data.len() {
            Some(&self.data[offset..offset + length])
        } else {
            None
        }
    }

    pub fn utf8_string(&self, offset: usize, length: usize) -> Option<String> {
        let raw = self.bytes(offset, length)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..end]).to_string())
    }

    pub fn is_valid_range(&self, offset: usize, length: usize) -> bool {
        offset + length <= self.data.len()
    }

    /// Read a ULEB128-encoded unsigned integer. Returns (value, bytes_consumed).
    pub fn read_uleb128(&self, offset: usize) -> Option<(u32, usize)> {
        let mut result: u32 = 0;
        let mut shift = 0u32;
        let mut pos = offset;
        loop {
            let byte = self.read_u8(pos)?;
            result |= ((byte & 0x7F) as u32) << shift;
            pos += 1;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some((result, pos - offset));
            }
            if shift > 35 {
                return None;
            }
        }
    }

    /// Read a signed LEB128-encoded integer. Returns (value, bytes_consumed).
    pub fn read_leb128_signed(&self, offset: usize) -> Option<(i32, usize)> {
        let mut result: i32 = 0;
        let mut shift = 0u32;
        let mut pos = offset;
        loop {
            let byte = self.read_u8(pos)?;
            result |= ((byte & 0x7F) as i32) << shift;
            pos += 1;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 32 && (byte & 0x40) != 0 {
                    result |= !0i32 << shift;
                }
                return Some((result, pos - offset));
            }
            if shift > 35 {
                return None;
            }
        }
    }
}
