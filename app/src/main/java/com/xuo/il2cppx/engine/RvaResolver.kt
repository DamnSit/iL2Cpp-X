package com.xuo.il2cppx.engine

import java.io.File
import java.nio.ByteOrder

data class MethodRva(
    val methodIndex: Int,
    val rva: Long,
    val size: Long,
    val symbolName: String = ""
) {
    val hexRva: String get() = "0x${rva.toString(16).uppercase().padStart(8, '0')}"
    val hexSize: String get() = "0x${size.toString(16).uppercase()}"
}

data class TypeRva(
    val typeIndex: Int,
    val methods: List<MethodRva>
)

data class RvaResult(
    val methodRvas: Map<Int, MethodRva>,
    val typeRvas: Map<Int, TypeRva>,
    val unresolvedCount: Int,
    val totalMethods: Int
) {
    val resolvedCount: Int get() = methodRvas.size
    val resolutionRate: Float get() = if (totalMethods > 0) resolvedCount.toFloat() / totalMethods else 0f
}

class RvaResolver {

    val debugLog = mutableListOf<String>()

    fun resolve(
        elfInfo: ElfInfo,
        metadata: MetadataParseResult,
        libFile: File,
        onProgress: ProgressCallback? = null
    ): RvaResult {
        val bytes = libFile.readBytes()
        val methodRvas = mutableMapOf<Int, MethodRva>()
        val order = if (elfInfo.isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val pointerSize = if (elfInfo.is64Bit) 8 else 4
        val codeSegments = elfInfo.loadSegments.filter { (it.flags and 0x1) != 0 }
        val codeStart = codeSegments.minOfOrNull { it.vaddr } ?: 0L
        val codeEnd = codeSegments.maxOfOrNull { it.vaddr + it.memsz } ?: 0L
        val methodCount = metadata.methods.size

        debugLog += "pointerSize=$pointerSize codeStart=0x${codeStart.toString(16)} codeEnd=0x${codeEnd.toString(16)} methods=$methodCount"

        // Strategy 1: Symbol-based resolution
        onProgress?.onProgress(DumpProgress("Mencari symbol IL2CPP", 0.45f))
        resolveFromSymbols(elfInfo, metadata, methodRvas)
        debugLog += "After symbols: ${methodRvas.size}"

        // Strategy 2: g_CodeRegistration by symbol
        if (methodRvas.size < methodCount / 4) {
            onProgress?.onProgress(DumpProgress("Scan code registration symbol", 0.5f))
            resolveFromCodeRegistrationSymbol(bytes, elfInfo, metadata, methodRvas, codeStart, codeEnd, order, pointerSize)
        }
        debugLog += "After codeRegSymbol: ${methodRvas.size}"

        // Strategy 3: Symbol-address clustering (more accurate for symbol-rich binaries)
        onProgress?.onProgress(DumpProgress("Symbol address clustering", 0.6f))
        resolveBySymbolClustering(bytes, elfInfo, metadata, methodRvas, codeStart, codeEnd, order)
        debugLog += "After symbolCluster: ${methodRvas.size}"

        // Strategy 3b: Disabled — segScan finds PLT stubs, not actual method bodies
        // if (methodRvas.size < methodCount * 9 / 10) {
        //     scanAllSegmentsForTable(bytes, elfInfo, metadata, methodRvas, codeStart, codeEnd, order)
        // }
        debugLog += "After segScan: ${methodRvas.size} (disabled)"

        // Strategy 4: Reconstruct .data.rel.ro via relocations (only fill unresolved methods)
        // Disabled: the block found at 0xd6cb0 is not the actual method pointer table,
        // producing wrong RVA values. symbolCluster gives correct but partial (25%) coverage.
        // if (methodRvas.size < methodCount * 9 / 10) {
        //     onProgress?.onProgress(DumpProgress("Parsing relocations", 0.7f))
        //     resolveFromRelocations(bytes, elfInfo, metadata, methodRvas, codeStart, codeEnd, order)
        // }
        debugLog += "After reloc: ${methodRvas.size} (disabled)"

        // Build type RVA mapping
        val typeRvas = mutableMapOf<Int, TypeRva>()
        for (type in metadata.types) {
            val methods = (type.methodStart until (type.methodStart + type.methodCount))
                .mapNotNull { methodRvas[it] }
            if (methods.isNotEmpty()) {
                typeRvas[type.index] = TypeRva(type.index, methods)
            }
        }

        val unresolved = methodCount - methodRvas.size
        return RvaResult(methodRvas = methodRvas, typeRvas = typeRvas, unresolvedCount = unresolved, totalMethods = methodCount)
    }

    // =========================================================================
    // Strategy 3: Reconstruct .data.rel.ro, find method pointer table
    // =========================================================================

    private fun resolveFromRelocations(
        bytes: ByteArray, elfInfo: ElfInfo, metadata: MetadataParseResult,
        results: MutableMap<Int, MethodRva>, codeStart: Long, codeEnd: Long, order: ByteOrder
    ) {
        val relaDyn = elfInfo.sections.firstOrNull { it.name == ".rela.dyn" }
        if (relaDyn == null) { debugLog += "  reloc: .rela.dyn not found"; return }
        val dataRelRo = elfInfo.sections.firstOrNull { it.name == ".data.rel.ro" }
        if (dataRelRo == null) { debugLog += "  reloc: .data.rel.ro not found"; return }

        val sectionFileStart = dataRelRo.offset.toInt()
        val sectionSize = dataRelRo.size.toInt()
        val sectionVaddr = dataRelRo.addr
        if (sectionFileStart + sectionSize > bytes.size || sectionSize <= 0) return

        debugLog += "  reloc: .data.rel.ro vaddr=0x${sectionVaddr.toString(16)} size=$sectionSize"

        // Copy section data
        val reconstructed = bytes.copyOfRange(sectionFileStart, sectionFileStart + sectionSize)

        // Apply R_AARCH64_RELATIVE (0x403) relocations
        val relaEntrySize = 24
        val relaCount = (relaDyn.size / relaEntrySize).toInt()
        var relocApplied = 0
        for (i in 0 until relaCount) {
            val off = (relaDyn.offset + i * relaEntrySize).toInt()
            if (off + relaEntrySize > bytes.size) break
            val rOffset = readU64(bytes, off, order)
            val rInfo = readU64(bytes, off + 8, order)
            val rAddend = readU64(bytes, off + 16, order)
            val relType = (rInfo and 0xFFFFFFFFL).toInt()
            if (relType != 0x403) continue
            if (rOffset !in sectionVaddr until (sectionVaddr + sectionSize.toLong())) continue
            val localOff = (rOffset - sectionVaddr).toInt()
            if (localOff + 8 > reconstructed.size) continue
            reconstructed[localOff] = (rAddend and 0xFF).toByte()
            reconstructed[localOff + 1] = ((rAddend shr 8) and 0xFF).toByte()
            reconstructed[localOff + 2] = ((rAddend shr 16) and 0xFF).toByte()
            reconstructed[localOff + 3] = ((rAddend shr 24) and 0xFF).toByte()
            reconstructed[localOff + 4] = ((rAddend shr 32) and 0xFF).toByte()
            reconstructed[localOff + 5] = ((rAddend shr 40) and 0xFF).toByte()
            reconstructed[localOff + 6] = ((rAddend shr 48) and 0xFF).toByte()
            reconstructed[localOff + 7] = ((rAddend shr 56) and 0xFF).toByte()
            relocApplied++
        }
        debugLog += "  reloc: applied $relocApplied relocations"

        val methodCount = metadata.methods.size
        val gapTolerance = 500 // Abstract methods can create large null gaps

        // Scan reconstructed .data.rel.ro for largest block of code pointers.
        // 4-byte entries with gap tolerance
        var bestStart = -1; var bestCount = 0; var curStart = -1; var curCount = 0; var gapCount = 0
        var i = 0
        while (i + 4 <= reconstructed.size) {
            val raw = readU32(reconstructed, i, order).toLong() and 0xFFFFFFFFL
            if (raw in codeStart until codeEnd) {
                if (curCount == 0 && gapCount == 0) curStart = i
                curCount++
                gapCount = 0
            } else {
                if (curCount > 0) gapCount++
                if (gapCount > gapTolerance) {
                    if (curCount > bestCount) { bestCount = curCount; bestStart = curStart }
                    curCount = 0; gapCount = 0
                }
            }
            i += 4
        }
        if (curCount > bestCount) { bestCount = curCount; bestStart = curStart }
        debugLog += "  reloc: 4-byte: start=0x${bestStart.toString(16)} count=$bestCount"

        if (bestCount >= methodCount / 10 && bestStart >= 0) {
            // Read all entries from bestStart, skipping gaps
            var mapped = 0; var idx = 0; var pos = bestStart; var consecutiveNulls = 0
            while (idx < methodCount && pos + 4 <= reconstructed.size && consecutiveNulls <= gapTolerance) {
                val raw = readU32(reconstructed, pos, order).toLong() and 0xFFFFFFFFL
                if (raw in codeStart until codeEnd) {
                    if (idx !in results) {
                        results[idx] = MethodRva(methodIndex = idx, rva = raw, size = 0, symbolName = "reloc")
                        mapped++
                    }
                    consecutiveNulls = 0
                } else {
                    consecutiveNulls++
                }
                idx++
                pos += 4
            }
            debugLog += "  reloc: 4-byte mapped=$mapped"
            if (mapped > methodCount / 4) return
        }

        // 8-byte entries with gap tolerance
        bestStart = -1; bestCount = 0; curCount = 0; gapCount = 0; i = 0
        while (i + 8 <= reconstructed.size) {
            val v = readU64(reconstructed, i, order)
            if (v in codeStart until codeEnd) {
                if (curCount == 0 && gapCount == 0) curStart = i
                curCount++
                gapCount = 0
            } else {
                if (curCount > 0) gapCount++
                if (gapCount > gapTolerance) {
                    if (curCount > bestCount) { bestCount = curCount; bestStart = curStart }
                    curCount = 0; gapCount = 0
                }
            }
            i += 8
        }
        if (curCount > bestCount) { bestCount = curCount; bestStart = curStart }
        debugLog += "  reloc: 8-byte: start=0x${bestStart.toString(16)} count=$bestCount"

        if (bestCount >= methodCount / 10 && bestStart >= 0) {
            var mapped = 0; var idx = 0; var pos = bestStart; var consecutiveNulls = 0
            while (idx < methodCount && pos + 8 <= reconstructed.size && consecutiveNulls <= gapTolerance) {
                val v = readU64(reconstructed, pos, order)
                if (v in codeStart until codeEnd) {
                    if (idx !in results) {
                        results[idx] = MethodRva(methodIndex = idx, rva = v, size = 0, symbolName = "reloc")
                        mapped++
                    }
                    consecutiveNulls = 0
                } else {
                    consecutiveNulls++
                }
                idx++
                pos += 8
            }
            debugLog += "  reloc: 8-byte mapped=$mapped"
        }

        debugLog += "  reloc: done"
    }

    // =========================================================================
    // Strategy 4: Symbol-address clustering
    // =========================================================================

    private fun resolveBySymbolClustering(
        bytes: ByteArray, elfInfo: ElfInfo, metadata: MetadataParseResult,
        results: MutableMap<Int, MethodRva>, codeStart: Long, codeEnd: Long, order: ByteOrder
    ) {
        val knownAddrSet = elfInfo.symbols
            .filter { it.isFunction && it.isDefined && it.size > 0 && it.value in codeStart until codeEnd }
            .map { it.value }.toHashSet()
        if (knownAddrSet.size < 10) return
        val knownAddrs = knownAddrSet.toList()

        val pointerSize = if (elfInfo.is64Bit) 8 else 4
        val methodCount = metadata.methods.size

        // Only scan data segments (not executable code segments)
        val dataSegments = elfInfo.loadSegments.filter { (it.flags and 0x1) == 0 }
        for (seg in dataSegments) {
            val segStart = seg.offset.toInt()
            val segEnd = (seg.offset + seg.filesz).toInt()
            if (segStart < 0 || segEnd > bytes.size || segEnd <= segStart) continue
            if (segEnd - segStart < methodCount * 4) continue

            // Try: 8-byte absolute pointers
            tryAbsoluteTable(bytes, seg, segStart, segEnd, 8, knownAddrs, methodCount, codeStart, codeEnd, order, results)
            if (results.size > methodCount / 2) return

            // Try: 4-byte absolute pointers
            tryAbsoluteTable(bytes, seg, segStart, segEnd, 4, knownAddrs, methodCount, codeStart, codeEnd, order, results)
            if (results.size > methodCount / 2) return

            // Try: 4-byte relative offsets (Unity 2021+ / metadata v27+)
            tryRelativeTable(bytes, seg, segStart, segEnd, knownAddrs, methodCount, codeStart, codeEnd, order, results)
            if (results.size > methodCount / 2) return
        }
    }

    private fun tryAbsoluteTable(
        bytes: ByteArray, seg: ElfSegment, segStart: Int, segEnd: Int, entrySize: Int,
        knownAddrs: List<Long>, methodCount: Int, codeStart: Long, codeEnd: Long,
        order: ByteOrder, results: MutableMap<Int, MethodRva>
    ) {
        // Quick probe: sample every 1024 entries to check if any known addr exists
        var quickHits = 0
        var pos = segStart
        while (pos + entrySize <= segEnd && quickHits == 0) {
            val ptr = if (entrySize == 8) readU64(bytes, pos, order)
                      else readU32(bytes, pos, order).toLong() and 0xFFFFFFFFL
            if (ptr in knownAddrs) quickHits++
            pos += entrySize * 1024
        }
        if (quickHits == 0) {
            debugLog += "  symbolCluster: abs entrySize=$entrySize seg=0x${seg.vaddr.toString(16)} quick=0 skip"
            return
        }

        val addrLocations = mutableListOf<Int>()
        pos = segStart
        while (pos + entrySize <= segEnd) {
            val ptr = if (entrySize == 8) readU64(bytes, pos, order)
                      else readU32(bytes, pos, order).toLong() and 0xFFFFFFFFL
            if (ptr in knownAddrs) addrLocations += pos
            pos += entrySize
        }

        debugLog += "  symbolCluster: abs entrySize=$entrySize seg=0x${seg.vaddr.toString(16)} matches=${addrLocations.size}"
        if (addrLocations.size < 10) return

        // Find best cluster
        var bestStart = -1; var bestCount = 0
        for (startIdx in addrLocations.indices) {
            var count = 0; var endOffset = addrLocations[startIdx]
            for (j in startIdx until addrLocations.size) {
                val loc = addrLocations[j]
                if (loc - endOffset <= entrySize * 5) { count++; endOffset = loc + entrySize } else break
            }
            if (count > bestCount) { bestCount = count; bestStart = addrLocations[startIdx] }
        }

        if (bestCount < 10 || bestStart < 0) return

        var valid = 0
        for (s in 0 until minOf(bestCount, 50)) {
            val off = bestStart + s * entrySize
            if (off + entrySize > bytes.size) break
            val ptr = if (entrySize == 8) readU64(bytes, off, order)
                      else readU32(bytes, off, order).toLong() and 0xFFFFFFFFL
            if (ptr in codeStart until codeEnd) valid++
        }
        if (valid < minOf(bestCount, 50) / 3) return

        val readCount = minOf(methodCount, (segEnd - bestStart) / entrySize)
        val pointers = readPointerArray(bytes, bestStart, readCount, entrySize, order)
        var mapped = 0
        for (idx in pointers.indices) {
            if (idx >= methodCount) break
            val ptr = pointers[idx]
            if (ptr in codeStart until codeEnd && idx !in results) {
                results[idx] = MethodRva(methodIndex = idx, rva = ptr, size = 0, symbolName = "symbolCluster")
                mapped++
            }
        }
        debugLog += "  symbolCluster: abs $entrySize mapped=$mapped"
    }

    private fun tryRelativeTable(
        bytes: ByteArray, seg: ElfSegment, segStart: Int, segEnd: Int,
        knownAddrs: List<Long>, methodCount: Int, codeStart: Long, codeEnd: Long,
        order: ByteOrder, results: MutableMap<Int, MethodRva>
    ) {
        // Try several possible table start positions within the segment
        // For each candidate start, check if knownAddrs are reachable via relative offsets
        val step = 4
        val segVaddr = seg.vaddr

        // Quick coarse scan: check only 10 known addresses at candidate starts
        val probeAddrs = knownAddrs.take(10)
        var bestStart = -1; var bestMatches = 0
        val coarseStep = 4096

        var candidate = segStart
        while (candidate + methodCount * 4 <= segEnd) {
            val tableVA = segVaddr + (candidate - segStart)
            var matches = 0
            for (addr in probeAddrs) {
                val relOffset = addr - tableVA
                if (relOffset in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) {
                    val stored = readU32(bytes, candidate, order).toLong()
                    if (stored == (relOffset and 0xFFFFFFFFL)) matches++
                }
            }
            if (matches > bestMatches) { bestMatches = matches; bestStart = candidate }
            if (matches == probeAddrs.size) break
            candidate += coarseStep
        }

        if (bestStart < 0 || bestMatches < 3) {
            debugLog += "  symbolCluster: rel seg=0x${segVaddr.toString(16)} no match"
            return
        }

        // Fine scan around best position
        val fineStart = maxOf(segStart, bestStart - 4096)
        val fineEnd = minOf(segEnd - methodCount * 4, bestStart + 4096)
        candidate = fineStart
        bestStart = -1; bestMatches = 0
        while (candidate + methodCount * 4 <= fineEnd) {
            val tableVA = segVaddr + (candidate - segStart)
            var matches = 0
            for (addr in knownAddrs.take(200)) {
                val relOffset = addr - tableVA
                if (relOffset in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) {
                    val stored = readU32(bytes, candidate, order).toLong()
                    if (stored == (relOffset and 0xFFFFFFFFL)) matches++
                }
            }
            if (matches > bestMatches) { bestMatches = matches; bestStart = candidate }
            if (matches > knownAddrs.take(200).size / 2) break
            candidate += step
        }

        debugLog += "  symbolCluster: rel seg=0x${segVaddr.toString(16)} bestStart=0x${bestStart.toString(16)} matches=$bestMatches"

        if (bestStart < 0 || bestMatches < 3) return

        // Map all entries using relative offsets
        val tableVA = segVaddr + (bestStart - segStart)
        var mapped = 0
        for (idx in 0 until methodCount) {
            val off = bestStart + idx * 4
            if (off + 4 > bytes.size) break
            val relOffset = readU32(bytes, off, order).toLong()
            val target = tableVA + idx * 4 + relOffset
            if (target in codeStart until codeEnd && idx !in results) {
                results[idx] = MethodRva(methodIndex = idx, rva = target, size = 0, symbolName = "symbolCluster-rel")
                mapped++
            }
        }
        debugLog += "  symbolCluster: rel mapped=$mapped"
    }

    // =========================================================================
    // Strategy 1: Symbol-based resolution
    // =========================================================================

    private fun resolveFromSymbols(
        elfInfo: ElfInfo, metadata: MetadataParseResult, results: MutableMap<Int, MethodRva>
    ) {
        val methodSymbols = elfInfo.symbols.filter { it.isFunction && it.isDefined && it.size > 0 }
        val typeLookup = mutableMapOf<String, MutableList<Int>>()
        for (type in metadata.types) {
            val fqcn = if (type.namespaceName.isNotBlank()) "${type.namespaceName}.${type.name}" else type.name
            typeLookup.getOrPut(fqcn) { mutableListOf() }.add(type.index)
            if (type.namespaceName.isNotBlank()) typeLookup.getOrPut(type.name) { mutableListOf() }.add(type.index)
        }
        val methodNameIndex = mutableMapOf<String, MutableList<Int>>()
        for (method in metadata.methods) methodNameIndex.getOrPut(method.name) { mutableListOf() }.add(method.index)

        for (symbol in methodSymbols) {
            val name = symbol.name
            if (name.length < 3) continue
            if (name.startsWith("il2cpp_") || name.startsWith("_Z") || name.startsWith("__")) continue
            val parsed = parseIl2CppSymbol(name) ?: continue
            val typeIndices = typeLookup[parsed.typeName] ?: typeLookup[parsed.simpleTypeName] ?: continue
            for (typeIdx in typeIndices) {
                val type = metadata.types[typeIdx]
                for (methodIdx in type.methodStart until (type.methodStart + type.methodCount)) {
                    if (methodIdx in results) continue
                    val method = metadata.methods.getOrNull(methodIdx) ?: continue
                    if (method.name == parsed.methodName) {
                        results[methodIdx] = MethodRva(methodIndex = methodIdx, rva = symbol.value, size = symbol.size, symbolName = name)
                        break
                    }
                }
            }
        }

        for (symbol in methodSymbols) {
            val name = symbol.name
            if (name.length < 3 || name.startsWith("il2cpp_") || name.startsWith("_Z") || name.startsWith("__")) continue
            if (name.contains("_") || name.contains("::")) continue
            val methodName = extractMethodName(name)
            if (methodName.isNotBlank()) {
                val candidates = methodNameIndex[methodName] ?: continue
                if (candidates.size == 1 && candidates[0] !in results) {
                    results[candidates[0]] = MethodRva(methodIndex = candidates[0], rva = symbol.value, size = symbol.size, symbolName = name)
                }
            }
        }
    }

    private data class ParsedSymbol(val typeName: String, val simpleTypeName: String, val methodName: String)

    private fun parseIl2CppSymbol(name: String): ParsedSymbol? {
        if ("::" in name) {
            val parts = name.split("::", limit = 2)
            if (parts.size == 2 && parts[0].isNotBlank() && parts[1].isNotBlank()) {
                return ParsedSymbol(parts[0], parts[0].substringAfterLast('.'), parts[1].substringBefore("__"))
            }
        }
        val segments = name.split("_")
        if (segments.size >= 2) {
            val methodName = segments.last().substringBefore("__")
            if (methodName.isNotBlank() && segments.dropLast(1).isNotEmpty()) {
                val ts = segments.dropLast(1)
                return ParsedSymbol(ts.joinToString("."), ts.last(), methodName)
            }
        }
        return null
    }

    private fun extractMethodName(symbolName: String): String {
        val lastSep = maxOf(symbolName.lastIndexOf("::"), symbolName.lastIndexOf('.'))
        val name = if (lastSep >= 0) symbolName.substring(lastSep + 2) else symbolName
        return name.removeSuffix("_m__0").removeSuffix("_m__1").removeSuffix("_m__2")
            .substringBefore("__MetadataUsageId").substringBefore("_Injected")
    }

    // =========================================================================
    // Strategy 2: g_CodeRegistration by symbol name
    // =========================================================================

    private fun resolveFromCodeRegistrationSymbol(
        bytes: ByteArray, elfInfo: ElfInfo, metadata: MetadataParseResult,
        results: MutableMap<Int, MethodRva>, codeStart: Long, codeEnd: Long, order: ByteOrder, pointerSize: Int
    ) {
        val codeReg = elfInfo.findSymbol("g_CodeRegistration") ?: return
        val codeRegFileOffset = elfInfo.vaddrToFileOffset(codeReg.value) ?: return
        if (codeRegFileOffset + pointerSize * 4 > bytes.size) return

        val funcPtrArrayCount = readPointer(bytes, (codeRegFileOffset + pointerSize * 2).toInt(), pointerSize, order)
        val funcPtrArrayAddr = readPointer(bytes, (codeRegFileOffset + pointerSize * 3).toInt(), pointerSize, order)
        if (funcPtrArrayAddr == 0L || funcPtrArrayCount <= 0 || funcPtrArrayCount > metadata.methods.size * 2L) return

        val funcPtrArrayOffset = elfInfo.vaddrToFileOffset(funcPtrArrayAddr) ?: return
        val methodPointers = readPointerArray(bytes, funcPtrArrayOffset.toInt(), funcPtrArrayCount.toInt(), pointerSize, order)
        mapPointerTable(methodPointers, metadata, results, codeStart, codeEnd)
    }

    // =========================================================================
    // Utility functions
    // =========================================================================

    private fun readPointer(bytes: ByteArray, offset: Int, pointerSize: Int, order: ByteOrder): Long {
        return if (pointerSize == 8) readU64(bytes, offset, order)
        else readU32(bytes, offset, order).toLong() and 0xFFFFFFFFL
    }

    private fun readPointerArray(bytes: ByteArray, offset: Int, count: Int, pointerSize: Int, order: ByteOrder): List<Long> {
        return List(count) { i -> readPointer(bytes, offset + i * pointerSize, pointerSize, order) }
    }

    private fun mapPointerTable(
        pointers: List<Long>, metadata: MetadataParseResult, results: MutableMap<Int, MethodRva>,
        codeStart: Long = 0, codeEnd: Long = Long.MAX_VALUE
    ) {
        if (pointers.size == metadata.methods.size) {
            for (idx in pointers.indices) {
                if (idx !in results && pointers[idx] != 0L && pointers[idx] in codeStart until codeEnd) {
                    results[idx] = MethodRva(methodIndex = idx, rva = pointers[idx], size = 0)
                }
            }
            return
        }
        if (kotlin.math.abs(pointers.size - metadata.methods.size) < metadata.methods.size / 10) {
            val limit = minOf(pointers.size, metadata.methods.size)
            for (idx in 0 until limit) {
                if (idx !in results && pointers[idx] != 0L && pointers[idx] in codeStart until codeEnd) {
                    results[idx] = MethodRva(methodIndex = idx, rva = pointers[idx], size = 0)
                }
            }
            return
        }
        var ptrIdx = 0
        for (method in metadata.methods) {
            if (method.index !in results && ptrIdx < pointers.size) {
                val ptr = pointers[ptrIdx]
                if (ptr != 0L && ptr in codeStart until codeEnd) {
                    results[method.index] = MethodRva(methodIndex = method.index, rva = ptr, size = 0)
                }
                ptrIdx++
            }
        }
    }

    /**
     * Count consecutive code pointers at the given offset.
     * Tries both absolute and relative (int32) interpretations.
     * For relative: target = baseAddr + idx * 4 + readI32(entryOffset)
     * where baseAddr = sectionVaddr + offset (the VA of the first entry).
     */
    private fun countCodePointers(
        data: ByteArray, offset: Int, entrySize: Int,
        codeStart: Long, codeEnd: Long, order: ByteOrder,
        sectionVaddr: Long = 0
    ): Int {
        var count = 0
        var pos = offset
        val maxScan = minOf(data.size, offset + 200000 * entrySize)
        val baseAddr = sectionVaddr + offset // VA of entry 0

        while (pos + entrySize <= maxScan) {
            val raw = if (entrySize == 8) readU64(data, pos, order)
                      else readU32(data, pos, order).toLong() and 0xFFFFFFFFL

            // Try absolute
            if (raw in codeStart until codeEnd) {
                count++; pos += entrySize; continue
            }

            // Try relative (4-byte int32): target = baseAddr + (pos - offset) + signedInt32
            if (entrySize == 4 && sectionVaddr > 0) {
                val relOffset = readU32(data, pos, order).toLong() // signed
                val target = baseAddr + (pos - offset) + relOffset
                if (target in codeStart until codeEnd) {
                    count++; pos += entrySize; continue
                }
            }

            break
        }
        return count
    }

    private fun tryReadArray(
        reconstructed: ByteArray, arrayOff: Int, count: Int, entrySize: Int,
        codeStart: Long, codeEnd: Long, order: ByteOrder,
        results: MutableMap<Int, MethodRva>, label: String,
        sectionVaddr: Long = 0
    ): Boolean {
        if (arrayOff + count * entrySize > reconstructed.size) return false
        val baseAddr = sectionVaddr + arrayOff

        // Sample: determine if absolute or relative
        var absValid = 0; var relValid = 0
        val sample = minOf(count, 500)
        for (idx in 0 until sample) {
            val off = arrayOff + idx * entrySize
            val raw = if (entrySize == 8) readU64(reconstructed, off, order)
                      else readU32(reconstructed, off, order).toLong() and 0xFFFFFFFFL
            if (raw in codeStart until codeEnd) absValid++
            if (entrySize == 4 && sectionVaddr > 0) {
                val relOffset = readU32(reconstructed, off, order).toLong()
                val target = baseAddr + idx * 4 + relOffset
                if (target in codeStart until codeEnd) relValid++
            }
        }

        val useRelative = relValid > absValid && relValid >= sample * 9 / 10
        val useAbsolute = absValid >= sample * 9 / 10
        if (!useRelative && !useAbsolute) return false

        var mapped = 0
        for (idx in 0 until count) {
            val off = arrayOff + idx * entrySize
            if (off + entrySize > reconstructed.size) break
            val rva: Long
            if (useRelative) {
                val relOffset = readU32(reconstructed, off, order).toLong()
                rva = baseAddr + idx * 4 + relOffset
            } else {
                rva = if (entrySize == 8) readU64(reconstructed, off, order)
                      else readU32(reconstructed, off, order).toLong() and 0xFFFFFFFFL
            }
            if (rva in codeStart until codeEnd && idx !in results) {
                results[idx] = MethodRva(methodIndex = idx, rva = rva, size = 0, symbolName = "reloc")
                mapped++
            }
        }
        debugLog += "  reloc: $label entrySize=$entrySize rel=$useRelative mapped=$mapped"
        return mapped > count / 2
    }

    // =========================================================================
    // Strategy 3b: Scan ALL segments for 4-byte code pointer blocks
    // =========================================================================

    private fun scanAllSegmentsForTable(
        bytes: ByteArray, elfInfo: ElfInfo, metadata: MetadataParseResult,
        results: MutableMap<Int, MethodRva>, codeStart: Long, codeEnd: Long, order: ByteOrder
    ) {
        val methodCount = metadata.methods.size
        val gapTolerance = 500

        for (seg in elfInfo.loadSegments) {
            val segStart = seg.offset.toInt()
            val segEnd = (seg.offset + seg.filesz).toInt()
            if (segStart < 0 || segEnd > bytes.size || segEnd <= segStart) continue
            if (segEnd - segStart < methodCount * 2) continue // too small

            // Scan for largest block of 4-byte code pointers with gap tolerance
            var bestStart = -1; var bestCount = 0; var curStart = -1; var curCount = 0; var gapCount = 0
            var i = segStart
            while (i + 4 <= segEnd) {
                val raw = readU32(bytes, i, order).toLong() and 0xFFFFFFFFL
                if (raw in codeStart until codeEnd) {
                    if (curCount == 0 && gapCount == 0) curStart = i
                    curCount++
                    gapCount = 0
                } else {
                    if (curCount > 0) gapCount++
                    if (gapCount > gapTolerance) {
                        if (curCount > bestCount) { bestCount = curCount; bestStart = curStart }
                        curCount = 0; gapCount = 0
                    }
                }
                i += 4
            }
            if (curCount > bestCount) { bestCount = curCount; bestStart = curStart }

            if (bestCount >= methodCount / 10 && bestStart >= 0) {
                debugLog += "  segScan: seg=0x${seg.vaddr.toString(16)} start=0x${bestStart.toString(16)} count=$bestCount"
                var mapped = 0; var idx = 0; var pos = bestStart; var consecutiveNulls = 0
                while (idx < methodCount && pos + 4 <= segEnd && consecutiveNulls <= gapTolerance) {
                    val raw = readU32(bytes, pos, order).toLong() and 0xFFFFFFFFL
                    if (raw in codeStart until codeEnd) {
                        if (idx !in results) {
                            results[idx] = MethodRva(methodIndex = idx, rva = raw, size = 0, symbolName = "segScan")
                            mapped++
                        }
                        consecutiveNulls = 0
                    } else {
                        consecutiveNulls++
                    }
                    idx++
                    pos += 4
                }
                debugLog += "  segScan: mapped=$mapped"
            }
        }
    }

    companion object {
        fun readU32(bytes: ByteArray, offset: Int, order: ByteOrder): Int {
            val b0 = bytes[offset].toInt() and 0xFF
            val b1 = bytes[offset + 1].toInt() and 0xFF
            val b2 = bytes[offset + 2].toInt() and 0xFF
            val b3 = bytes[offset + 3].toInt() and 0xFF
            return if (order == ByteOrder.LITTLE_ENDIAN) b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
            else (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
        }

        fun readU64(bytes: ByteArray, offset: Int, order: ByteOrder): Long {
            val lo = readU32(bytes, offset, order).toLong() and 0xFFFFFFFFL
            val hi = readU32(bytes, offset + 4, order).toLong() and 0xFFFFFFFFL
            return if (order == ByteOrder.LITTLE_ENDIAN) lo or (hi shl 32) else (lo shl 32) or hi
        }
    }
}
