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

        // Auto-detect strides
        onProgress?.onProgress(DumpProgress("Deteksi layout metadata", 0.15f))
        val stringRange = ranges.firstOrNull { it.name == "string" }

        val imageDefSize = detectStride(reader, ranges, "images", listOf(24, 32, 40, 48, 56, 64))
        val imageNameOffset = detectImageNameOffset(reader, ranges, imageDefSize, stringRange)
        val (imageTypeStartOffset, imageTypeCountOffset) = detectImageTypeOffsets(reader, ranges, imageDefSize, imageNameOffset)

        val typeDefSize = detectStride(reader, ranges, "typeDefinitions", listOf(64, 72, 80, 88, 96, 104, 112, 120, 128, 136))
        val typeOffsets = detectTypeOffsets(reader, ranges, typeDefSize, stringRange)

        val methodDefSize = detectStride(reader, ranges, "methods", listOf(24, 28, 32, 36, 40, 44))
        val methodOffsets = detectMethodOffsets(reader, ranges, methodDefSize, stringRange)

        val fieldDefSize = detectStride(reader, ranges, "fields", listOf(8, 12, 16))
        val paramDefSize = detectStride(reader, ranges, "parameters", listOf(8, 12, 16))
        val paramTypeIndexOffset = if (paramDefSize == 8) 4 else 8

        onProgress?.onProgress(DumpProgress("Parsing string literals", 0.2f))
        val stringLiterals = readStringLiterals(reader, ranges)
        onProgress?.onProgress(DumpProgress("Parsing images", 0.3f))
        val images = readImages(reader, ranges, imageDefSize, imageNameOffset, imageTypeStartOffset, imageTypeCountOffset)
        onProgress?.onProgress(DumpProgress("Parsing type definitions", 0.4f, "${ranges.firstOrNull { it.name == "typeDefinitions" }?.size?.div(typeDefSize) ?: 0} types"))
        val types = readTypes(reader, ranges, typeDefSize, typeOffsets, stringRange)
        onProgress?.onProgress(DumpProgress("Parsing fields", 0.6f))
        val fields = readFields(reader, ranges, fieldDefSize)
        onProgress?.onProgress(DumpProgress("Parsing methods", 0.75f))
        val methods = readMethods(reader, ranges, methodDefSize, methodOffsets)
        onProgress?.onProgress(DumpProgress("Parsing parameters", 0.9f))
        val parameters = readParameters(reader, ranges, paramDefSize, paramTypeIndexOffset)

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

    // =========================================================================
    // Auto-detection helpers
    // =========================================================================

    private fun detectStride(reader: BinaryReader, ranges: List<MetadataRange>, tableName: String, candidates: List<Int>): Int {
        val tableRange = ranges.firstOrNull { it.name == tableName } ?: return candidates[0]
        if (tableRange.size == 0) return candidates[0]
        val stringRange = ranges.firstOrNull { it.name == "string" }

        var bestStride = candidates[0]
        var bestScore = 0

        for (stride in candidates) {
            if (tableRange.size % stride != 0) continue
            val count = tableRange.size / stride
            if (count < 2) continue
            val sample = minOf(count, 50)
            var valid = 0
            val uniqueNames = HashSet<Int>()
            for (i in 0 until sample) {
                val offset = tableRange.offset + i * stride
                if (offset + 4 > reader.size) break
                val nameIdx = reader.int32(offset)
                uniqueNames.add(nameIdx)
                if (stringRange != null && isValidStringIndex(reader, stringRange, nameIdx)) {
                    valid++
                }
            }
            val score = valid * 2 + uniqueNames.size
            if (score > bestScore) {
                bestScore = score
                bestStride = stride
            }
        }
        return bestStride
    }

    private fun isValidStringIndex(reader: BinaryReader, stringRange: MetadataRange, idx: Int): Boolean {
        if (idx < 0 || stringRange.size == 0) return false
        if (idx >= stringRange.size) return false
        val abs = stringRange.offset + idx
        if (abs + 1 >= reader.size) return false
        val b0 = reader.bytes(abs, 1)[0].toInt() and 0xFF
        if (b0 == 0) return false
        // First byte should be letter, underscore, or '<'
        if (!b0.toChar().isLetter() && b0 != '_'.code && b0 != '<'.code) return false
        val b1 = reader.bytes(abs + 1, 1)[0].toInt() and 0xFF
        return b1 != 0
    }

    private fun readNtString(reader: BinaryReader, absOffset: Int): String? {
        if (absOffset < 0 || absOffset >= reader.size) return null
        var len = 0
        while (len < 256 && absOffset + len < reader.size) {
            val b = reader.bytes(absOffset + len, 1)[0].toInt() and 0xFF
            if (b == 0) break
            len++
        }
        if (len < 2) return null
        return reader.utf8(absOffset, len)
    }

    private fun scoreImageName(s: String): Int {
        if (s.isEmpty()) return 0
        var score = 0
        if ('.' in s) score += 10
        if ('-' in s) score += 5
        if (s.length in 3..80) score += 3
        if (s.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }) score += 2
        return score
    }

    private fun detectImageNameOffset(reader: BinaryReader, ranges: List<MetadataRange>, stride: Int, stringRange: MetadataRange?): Int {
        val imageRange = ranges.firstOrNull { it.name == "images" } ?: return 0
        if (stringRange == null) return 0
        val count = imageRange.size / stride
        if (count < 2) return 0

        var bestOffset = 0
        var bestScore = 0

        for (off in 0 until stride step 4) {
            var totalScore = 0
            for (i in 0 until minOf(count, 30)) {
                val base = imageRange.offset + i * stride
                val idx = reader.int32(base + off)
                if (idx > 0 && idx < stringRange.size) {
                    val abs = stringRange.offset + idx
                    val s = readNtString(reader, abs)
                    if (s != null) totalScore += scoreImageName(s)
                }
            }
            if (totalScore > bestScore) {
                bestScore = totalScore
                bestOffset = off
            }
        }
        return bestOffset
    }

    private fun detectImageTypeOffsets(reader: BinaryReader, ranges: List<MetadataRange>, stride: Int, nameOffset: Int): Pair<Int, Int> {
        val imageRange = ranges.firstOrNull { it.name == "images" } ?: return Pair(8, 12)
        val count = imageRange.size / stride
        if (count < 3) return Pair(8, 12)

        var best = Pair(8, 12)
        var bestScore = 0

        for (tsOff in 0 until stride step 4) {
            if (tsOff == nameOffset) continue
            for (tcOff in (tsOff + 4) until stride step 4) {
                if (tcOff == nameOffset || tcOff == tsOff) continue
                var score = 0
                var prevEnd = -1
                for (i in 0 until minOf(count, 30)) {
                    val base = imageRange.offset + i * stride
                    val ts = reader.int32(base + tsOff)
                    val tc = reader.int32(base + tcOff)
                    if (ts >= 0 && tc > 0 && tc < 100000) {
                        score += 2
                        if (ts >= prevEnd) score += 1
                        prevEnd = ts + tc
                    }
                }
                if (score > bestScore) {
                    bestScore = score
                    best = Pair(tsOff, tcOff)
                }
            }
        }
        return best
    }

    data class TypeOffsets(
        val fieldStart: Int,
        val methodStart: Int,
        val propertyStart: Int,
        val methodCount: Int,
        val propertyCount: Int,
        val fieldCount: Int
    )

    private fun detectTypeOffsets(reader: BinaryReader, ranges: List<MetadataRange>, stride: Int, stringRange: MetadataRange?): TypeOffsets {
        val typeRange = ranges.firstOrNull { it.name == "typeDefinitions" } ?: return TypeOffsets(32, 36, 44, 64, 66, 68)
        if (stringRange == null) return TypeOffsets(32, 36, 44, 64, 66, 68)

        // Known layouts by stride
        val candidates = when (stride) {
            64 -> listOf(TypeOffsets(28, 32, 40, 48, 50, 52))
            72 -> listOf(TypeOffsets(28, 32, 40, 48, 50, 52))
            80 -> listOf(TypeOffsets(28, 32, 40, 56, 58, 60))
            88 -> listOf(TypeOffsets(32, 36, 44, 64, 66, 68))
            96 -> listOf(TypeOffsets(32, 36, 44, 64, 66, 68), TypeOffsets(52, 56, 64, 72, 74, 76))
            104 -> listOf(TypeOffsets(52, 56, 64, 72, 74, 76))
            112 -> listOf(TypeOffsets(52, 56, 64, 72, 74, 76))
            120 -> listOf(TypeOffsets(52, 56, 64, 72, 74, 76))
            128 -> listOf(TypeOffsets(52, 56, 64, 72, 74, 76))
            136 -> listOf(TypeOffsets(52, 56, 64, 72, 74, 76))
            else -> listOf(TypeOffsets(52, 56, 64, 72, 74, 76), TypeOffsets(32, 36, 44, 64, 66, 68))
        }

        val sample = minOf(typeRange.size / stride, 100)
        var best = candidates[0]
        var bestScore = 0

        for (c in candidates) {
            if (c.fieldStart + 4 > stride || c.methodStart + 4 > stride || c.propertyStart + 4 > stride
                || c.methodCount + 2 > stride || c.propertyCount + 2 > stride || c.fieldCount + 2 > stride) continue

            var score = 0
            for (i in 0 until sample) {
                val offset = typeRange.offset + i * stride
                // namespaceIndex at +4 should be valid string
                val nsIdx = reader.int32(offset + 4)
                if (nsIdx in 0 until stringRange.size) score++
                // methodCount reasonable
                val mc = reader.uint16(offset + c.methodCount)
                if (mc < 1000) score += 2
                // fieldCount reasonable
                val fc = reader.uint16(offset + c.fieldCount)
                if (fc < 5000) score++
            }
            if (score > bestScore) {
                bestScore = score
                best = c
            }
        }
        return best
    }

    data class MethodOffsets(
        val returnType: Int,
        val parameterStart: Int,
        val token: Int,
        val parameterCount: Int,
        val flags: Int,
        val iflags: Int
    )

    private fun detectMethodOffsets(reader: BinaryReader, ranges: List<MetadataRange>, stride: Int, stringRange: MetadataRange?): MethodOffsets {
        val methodRange = ranges.firstOrNull { it.name == "methods" } ?: return defaultMethodOffsets(stride)
        val paramRange = ranges.firstOrNull { it.name == "parameters" }
        val paramSize = paramRange?.size ?: 0

        val candidates = when (stride) {
            in 24..28 -> listOf(MethodOffsets(8, 12, 24, 18, 20, 22))
            in 30..32 -> listOf(MethodOffsets(8, 12, 28, 20, 22, 24))
            in 34..36 -> listOf(
                MethodOffsets(8, 12, 32, 24, 26, 28), // 64-bit genericContainerIndex
                MethodOffsets(8, 12, 32, 20, 22, 24), // 4-byte genericContainerIndex
            )
            else -> listOf(
                MethodOffsets(8, 12, 32, 24, 26, 28),
                MethodOffsets(8, 12, 32, 20, 22, 24),
            )
        }

        if (candidates.size == 1) return candidates[0]

        val count = methodRange.size / stride
        val sample = minOf(count, 200)
        var best = candidates[0]
        var bestScore = 0

        for (c in candidates) {
            if (c.parameterStart + 4 > stride || c.parameterCount + 2 > stride) continue
            var score = 0
            for (i in 0 until sample) {
                val offset = methodRange.offset + i * stride
                val pc = reader.uint16(offset + c.parameterCount)
                if (pc < 200) score += 2
                val ps = reader.int32(offset + c.parameterStart)
                if (ps in 0 until paramSize) score += 2
            }
            if (score > bestScore) {
                bestScore = score
                best = c
            }
        }
        return best
    }

    private fun defaultMethodOffsets(stride: Int): MethodOffsets = when (stride) {
        in 24..28 -> MethodOffsets(8, 12, 24, 18, 20, 22)
        in 30..32 -> MethodOffsets(8, 12, 28, 20, 22, 24)
        else -> MethodOffsets(8, 12, 32, 24, 26, 28)
    }

    // =========================================================================
    // Header ranges
    // =========================================================================

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

    // =========================================================================
    // Read functions with auto-detected strides/offsets
    // =========================================================================

    private fun readImages(
        reader: BinaryReader, ranges: List<MetadataRange>,
        stride: Int, nameOffset: Int, typeStartOffset: Int, typeCountOffset: Int
    ): List<MetadataImage> {
        val imageRange = ranges.firstOrNull { it.name == "images" } ?: return emptyList()
        val count = imageRange.size / stride
        return List(count) { index ->
            val offset = imageRange.offset + index * stride
            MetadataImage(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset + nameOffset)),
                typeStart = reader.int32(offset + typeStartOffset),
                typeCount = reader.int32(offset + typeCountOffset)
            )
        }
    }

    private fun readTypes(
        reader: BinaryReader, ranges: List<MetadataRange>,
        stride: Int, offsets: TypeOffsets, stringRange: MetadataRange?
    ): List<MetadataTypeDefinition> {
        val typeRange = ranges.firstOrNull { it.name == "typeDefinitions" } ?: return emptyList()
        val count = typeRange.size / stride
        return List(count) { index ->
            val offset = typeRange.offset + index * stride
            MetadataTypeDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                namespaceName = readMetadataString(reader, ranges, reader.int32(offset + 4)),
                fieldStart = reader.int32(offset + offsets.fieldStart),
                methodStart = reader.int32(offset + offsets.methodStart),
                propertyStart = reader.int32(offset + offsets.propertyStart),
                methodCount = reader.uint16(offset + offsets.methodCount),
                propertyCount = reader.uint16(offset + offsets.propertyCount),
                fieldCount = reader.uint16(offset + offsets.fieldCount)
            )
        }
    }

    private fun readFields(reader: BinaryReader, ranges: List<MetadataRange>, stride: Int): List<MetadataFieldDefinition> {
        val fieldRange = ranges.firstOrNull { it.name == "fields" } ?: return emptyList()
        val count = fieldRange.size / stride
        return List(count) { index ->
            val offset = fieldRange.offset + index * stride
            MetadataFieldDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                typeIndex = reader.int32(offset + 4)
            )
        }
    }

    private fun readMethods(
        reader: BinaryReader, ranges: List<MetadataRange>,
        stride: Int, offsets: MethodOffsets
    ): List<MetadataMethodDefinition> {
        val methodRange = ranges.firstOrNull { it.name == "methods" } ?: return emptyList()
        val count = methodRange.size / stride
        return List(count) { index ->
            val offset = methodRange.offset + index * stride
            MetadataMethodDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                returnType = reader.int32(offset + offsets.returnType),
                parameterStart = reader.int32(offset + offsets.parameterStart),
                parameterCount = reader.uint16(offset + offsets.parameterCount)
            )
        }
    }

    private fun readParameters(
        reader: BinaryReader, ranges: List<MetadataRange>,
        stride: Int, typeIndexOffset: Int
    ): List<MetadataParameterDefinition> {
        val parameterRange = ranges.firstOrNull { it.name == "parameters" } ?: return emptyList()
        val count = parameterRange.size / stride
        return List(count) { index ->
            val offset = parameterRange.offset + index * stride
            MetadataParameterDefinition(
                index = index,
                name = readMetadataString(reader, ranges, reader.int32(offset)),
                typeIndex = reader.int32(offset + typeIndexOffset)
            )
        }
    }

    // =========================================================================
    // String reading
    // =========================================================================

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

    // =========================================================================
    // String literals
    // =========================================================================

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
