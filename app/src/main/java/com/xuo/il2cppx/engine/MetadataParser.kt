package com.xuo.il2cppx.engine

import java.io.File

class MetadataParser {
    fun parse(file: File, onProgress: ProgressCallback? = null): MetadataParseResult {
        val reader = BinaryReader.fromFile(file)
        require(reader.size >= HEADER_MIN_SIZE) { "global-metadata.dat terlalu kecil: ${reader.size} bytes" }

        onProgress?.onProgress(DumpProgress("Membaca header", 0.05f))
        val magic = reader.uint32(0)
        require(magic == METADATA_MAGIC) {
            "Magic metadata tidak valid: 0x${magic.toString(16)}. File bukan global-metadata.dat IL2CPP valid."
        }

        val version = reader.int32(4)
        onProgress?.onProgress(DumpProgress("Membaca ranges", 0.1f))
        val ranges = readHeaderRanges(reader)
        validateRanges(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing string literals", 0.2f))
        val stringLiterals = readStringLiterals(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing images", 0.3f))
        val images = readImages(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing type definitions", 0.4f, "${ranges.firstOrNull { it.name == "typeDefinitions" }?.size?.div(88) ?: 0} types"))
        val types = readTypes(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing fields", 0.6f))
        val fields = readFields(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing methods", 0.75f))
        val methods = readMethods(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing parameters", 0.9f))
        val parameters = readParameters(reader, ranges)

        return MetadataParseResult(
            magic = magic,
            version = version,
            fileSize = reader.size,
            ranges = ranges,
            stringLiterals = stringLiterals,
            images = images,
            types = types,
            fields = fields,
            methods = methods,
            parameters = parameters
        )
    }

    private fun readHeaderRanges(reader: BinaryReader): List<MetadataRange> {
        val ranges = mutableListOf<MetadataRange>()
        var offset = 8
        var nameIndex = 0
        while (offset + 8 <= reader.size && nameIndex < HEADER_RANGE_NAMES.size) {
            val tableOffset = reader.int32(offset)
            val tableSize = reader.int32(offset + 4)
            ranges += MetadataRange(
                name = HEADER_RANGE_NAMES[nameIndex],
                offset = tableOffset,
                size = tableSize
            )
            offset += 8
            nameIndex++
        }
        return ranges
    }

    private fun validateRanges(reader: BinaryReader, ranges: List<MetadataRange>) {
        ranges.forEach { range ->
            if (range.offset == 0 && range.size == 0) return@forEach
            require(reader.isValidRange(range.offset, range.size)) {
                "Table ${range.name} keluar batas file: offset=${range.offset} size=${range.size} file=${reader.size}"
            }
        }
    }

    private fun readImages(reader: BinaryReader, ranges: List<MetadataRange>): List<MetadataImage> {
        val imageRange = ranges.firstOrNull { it.name == "images" } ?: return emptyList()
        val count = imageRange.size / IMAGE_DEFINITION_SIZE
        return List(count) { index ->
            val offset = imageRange.offset + index * IMAGE_DEFINITION_SIZE
            MetadataImage(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                typeStart = reader.int32(offset + 8),
                typeCount = reader.int32(offset + 12)
            )
        }
    }

    private fun readTypes(reader: BinaryReader, ranges: List<MetadataRange>): List<MetadataTypeDefinition> {
        val typeRange = ranges.firstOrNull { it.name == "typeDefinitions" } ?: return emptyList()
        val count = typeRange.size / TYPE_DEFINITION_SIZE
        return List(count) { index ->
            val offset = typeRange.offset + index * TYPE_DEFINITION_SIZE
            MetadataTypeDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                namespaceName = readMetadataString(reader, ranges, reader.int32(offset + 4)),
                fieldStart = reader.int32(offset + 32),
                methodStart = reader.int32(offset + 36),
                propertyStart = reader.int32(offset + 44),
                methodCount = reader.uint16(offset + 64),
                propertyCount = reader.uint16(offset + 66),
                fieldCount = reader.uint16(offset + 68)
            )
        }
    }

    private fun readFields(reader: BinaryReader, ranges: List<MetadataRange>): List<MetadataFieldDefinition> {
        val fieldRange = ranges.firstOrNull { it.name == "fields" } ?: return emptyList()
        val count = fieldRange.size / FIELD_DEFINITION_SIZE
        return List(count) { index ->
            val offset = fieldRange.offset + index * FIELD_DEFINITION_SIZE
            MetadataFieldDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                typeIndex = reader.int32(offset + 4)
            )
        }
    }

    private fun readMethods(reader: BinaryReader, ranges: List<MetadataRange>): List<MetadataMethodDefinition> {
        val methodRange = ranges.firstOrNull { it.name == "methods" } ?: return emptyList()
        val count = methodRange.size / METHOD_DEFINITION_SIZE

        return List(count) { index ->
            val offset = methodRange.offset + index * METHOD_DEFINITION_SIZE
            MetadataMethodDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                returnType = reader.int32(offset + 8),
                parameterStart = reader.int32(offset + 16),
                parameterCount = reader.uint16(offset + 34)
            )
        }
    }

    private fun readParameters(reader: BinaryReader, ranges: List<MetadataRange>): List<MetadataParameterDefinition> {
        val parameterRange = ranges.firstOrNull { it.name == "parameters" } ?: return emptyList()
        val count = parameterRange.size / PARAMETER_DEFINITION_SIZE
        return List(count) { index ->
            val offset = parameterRange.offset + index * PARAMETER_DEFINITION_SIZE
            MetadataParameterDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                typeIndex = reader.int32(offset + 12)
            )
        }
    }

    private fun readMetadataString(reader: BinaryReader, ranges: List<MetadataRange>, stringIndex: Int): String {
        val stringRange = ranges.firstOrNull { it.name == "string" } ?: return ""
        if (stringIndex < 0 || stringIndex >= stringRange.size) return ""
        val absoluteOffset = stringRange.offset + stringIndex
        var length = 0
        while (length < stringRange.size - stringIndex && reader.bytes(absoluteOffset + length, 1)[0].toInt() != 0) {
            length++
        }
        return reader.utf8(absoluteOffset, length)
    }

    private fun readStringLiterals(reader: BinaryReader, ranges: List<MetadataRange>): List<StringLiteral> {
        val literalRange = ranges.firstOrNull { it.name == "stringLiteral" } ?: return emptyList()
        val dataRange = ranges.firstOrNull { it.name == "stringLiteralData" } ?: return emptyList()
        if (literalRange.size <= 0 || dataRange.size <= 0) return emptyList()

        val count = literalRange.size / STRING_LITERAL_ENTRY_SIZE
        val result = ArrayList<StringLiteral>(count.coerceAtMost(MAX_STRING_LITERAL_EXPORT))
        repeat(count.coerceAtMost(MAX_STRING_LITERAL_EXPORT)) { index ->
            val entryOffset = literalRange.offset + index * STRING_LITERAL_ENTRY_SIZE
            val length = reader.int32(entryOffset)
            val dataIndex = reader.int32(entryOffset + 4)
            val value = if (length >= 0 && dataIndex >= 0 && dataIndex + length <= dataRange.size) {
                reader.utf8(dataRange.offset + dataIndex, length)
            } else {
                ""
            }
            result += StringLiteral(
                index = index,
                dataIndex = dataIndex,
                length = length,
                value = value
            )
        }
        return result
    }

    private companion object {
        const val METADATA_MAGIC = 0xFAB11BAFL
        const val HEADER_MIN_SIZE = 16
        const val STRING_LITERAL_ENTRY_SIZE = 8
        const val MAX_STRING_LITERAL_EXPORT = 5000
        const val IMAGE_DEFINITION_SIZE = 40
        const val TYPE_DEFINITION_SIZE = 88
        const val FIELD_DEFINITION_SIZE = 12
        const val METHOD_DEFINITION_SIZE = 36
        const val PARAMETER_DEFINITION_SIZE = 16

        val HEADER_RANGE_NAMES = listOf(
            "stringLiteral",
            "stringLiteralData",
            "string",
            "events",
            "properties",
            "methods",
            "parameterDefaultValues",
            "fieldDefaultValues",
            "fieldAndParameterDefaultValueData",
            "fieldMarshaledSizes",
            "parameters",
            "fields",
            "genericParameters",
            "genericParameterConstraints",
            "genericContainers",
            "nestedTypes",
            "interfaces",
            "vtableMethods",
            "interfaceOffsets",
            "typeDefinitions",
            "rgctxEntries",
            "images",
            "assemblies",
            "metadataUsageLists",
            "metadataUsagePairs",
            "fieldRefs",
            "referencedAssemblies",
            "attributesInfo",
            "attributeTypes",
            "unresolvedVirtualCallParameterTypes",
            "unresolvedVirtualCallParameterRanges",
            "windowsRuntimeTypeNames",
            "windowsRuntimeStrings",
            "exportedTypeDefinitions"
        )
    }
}
