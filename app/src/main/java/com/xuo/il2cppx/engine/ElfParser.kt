package com.xuo.il2cppx.engine

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

// ELF constants
private val ELF_MAGIC_BYTES = byteArrayOf(0x7F, 0x45, 0x4C, 0x46) // "\x7FELF"
private const val ELFCLASS32 = 1
private const val ELFCLASS64 = 2
private const val ELFDATA2LSB = 1
private const val PT_LOAD = 1
private const val SHT_SYMTAB = 2
private const val SHT_STRTAB = 3
private const val SHT_DYNAMIC = 6
private const val SHT_DYNSYM = 11
private const val STT_FUNC = 2
private const val SHN_UNDEF = 0

data class ElfSegment(
    val type: Int,
    val offset: Long,
    val vaddr: Long,
    val filesz: Long,
    val memsz: Long,
    val flags: Int
) {
    val isLoad: Boolean get() = type == PT_LOAD
    fun containsFileOffset(fileOffset: Long): Boolean =
        fileOffset in offset until (offset + filesz)

    fun fileOffsetToVaddr(fileOffset: Long): Long =
        vaddr + (fileOffset - offset)

    fun vaddrToFileOffset(targetVaddr: Long): Long =
        offset + (targetVaddr - vaddr)
}

data class ElfSection(
    val nameOffset: Int,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int = 0,
    val name: String = ""
) {
    val isText: Boolean get() = name == ".text"
    val isSymtab: Boolean get() = type == SHT_SYMTAB
    val isDynsym: Boolean get() = type == SHT_DYNSYM
    val isStrtab: Boolean get() = type == SHT_STRTAB
}

data class ElfSymbol(
    val name: String,
    val value: Long,
    val size: Long,
    val info: Int,
    val sectionIndex: Int
) {
    val isFunction: Boolean get() = (info and 0xF) == STT_FUNC
    val isDefined: Boolean get() = sectionIndex != SHN_UNDEF
    val endValue: Long get() = value + size
}

data class ElfInfo(
    val is64Bit: Boolean,
    val isLittleEndian: Boolean,
    val entryPoint: Long,
    val segments: List<ElfSegment>,
    val sections: List<ElfSection>,
    val symbols: List<ElfSymbol>
) {
    val loadSegments: List<ElfSegment> get() = segments.filter { it.isLoad }

    fun vaddrToFileOffset(vaddr: Long): Long? {
        for (seg in loadSegments) {
            if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.memsz) {
                return seg.offset + (vaddr - seg.vaddr)
            }
        }
        return null
    }

    fun fileOffsetToVaddr(fileOffset: Long): Long? {
        for (seg in loadSegments) {
            if (seg.containsFileOffset(fileOffset)) {
                return seg.fileOffsetToVaddr(fileOffset)
            }
        }
        return null
    }

    fun findSymbol(name: String): ElfSymbol? =
        symbols.firstOrNull { it.name == name && it.isDefined }

    fun findSymbols(prefix: String): List<ElfSymbol> =
        symbols.filter { it.name.startsWith(prefix) && it.isDefined }
}

class ElfParser {
    fun parse(file: File): ElfInfo {
        val bytes = file.readBytes()
        val reader = BinaryReader.fromFile(file)

        require(reader.size >= 16) { "File terlalu kecil untuk ELF" }
        val magicBytes = reader.bytes(0, 4)
        require(magicBytes.contentEquals(ELF_MAGIC_BYTES)) {
            "Bukan file ELF valid: magic=0x${magicBytes.joinToString("") { "%02x".format(it) }}"
        }

        // EI_CLASS (byte 4) and EI_DATA (byte 5) are single-byte fields
        val elfClass = bytes[4].toInt() and 0xFF // 1=32-bit, 2=64-bit
        val is64Bit = elfClass == ELFCLASS64
        val dataEncoding = bytes[5].toInt() and 0xFF // 1=LE, 2=BE
        val isLittleEndian = dataEncoding == ELFDATA2LSB
        val byteOrder = if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN

        val entryPoint: Long
        val phoff: Long
        val shoff: Long
        val phentsize: Int
        val phnum: Int
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int

        if (is64Bit) {
            entryPoint = readU64(bytes, 24, byteOrder)
            phoff = readU64(bytes, 32, byteOrder)
            shoff = readU64(bytes, 40, byteOrder)
            phentsize = readU16(bytes, 54, byteOrder)
            phnum = readU16(bytes, 56, byteOrder)
            shentsize = readU16(bytes, 58, byteOrder)
            shnum = readU16(bytes, 60, byteOrder)
            shstrndx = readU16(bytes, 62, byteOrder)
        } else {
            entryPoint = readU32(bytes, 24, byteOrder).toLong()
            phoff = readU32(bytes, 28, byteOrder).toLong()
            shoff = readU32(bytes, 32, byteOrder).toLong()
            phentsize = readU16(bytes, 42, byteOrder)
            phnum = readU16(bytes, 44, byteOrder)
            shentsize = readU16(bytes, 46, byteOrder)
            shnum = readU16(bytes, 48, byteOrder)
            shstrndx = readU16(bytes, 50, byteOrder)
        }

        val segments = parseSegments(bytes, phoff, phnum, phentsize, is64Bit, byteOrder)
        val sections = parseSections(bytes, shoff, shnum, shentsize, is64Bit, byteOrder)

        // Read section name string table
        val sectionNames = if (shstrndx in sections.indices) {
            val strtabSection = sections[shstrndx]
            readStringTable(bytes, strtabSection.offset.toInt(), strtabSection.size.toInt())
        } else emptyMap()

        val namedSections = sections.map { sec ->
            sec.copy(name = sectionNames[sec.nameOffset] ?: "")
        }

        // Parse symbol tables
        val symbols = parseSymbolTables(bytes, namedSections, is64Bit, byteOrder)

        return ElfInfo(
            is64Bit = is64Bit,
            isLittleEndian = isLittleEndian,
            entryPoint = entryPoint,
            segments = segments,
            sections = namedSections,
            symbols = symbols
        )
    }

    private fun parseSegments(
        bytes: ByteArray, phoff: Long, phnum: Int, phentsize: Int,
        is64Bit: Boolean, byteOrder: ByteOrder
    ): List<ElfSegment> {
        val segments = mutableListOf<ElfSegment>()
        for (i in 0 until phnum) {
            val off = (phoff + i * phentsize).toInt()
            if (off + phentsize > bytes.size) break

            if (is64Bit) {
                segments += ElfSegment(
                    type = readU32(bytes, off, byteOrder),
                    flags = readU32(bytes, off + 4, byteOrder),
                    offset = readU64(bytes, off + 8, byteOrder),
                    vaddr = readU64(bytes, off + 16, byteOrder),
                    memsz = readU64(bytes, off + 40, byteOrder),
                    filesz = readU64(bytes, off + 32, byteOrder)
                )
            } else {
                segments += ElfSegment(
                    type = readU32(bytes, off, byteOrder),
                    offset = readU32(bytes, off + 4, byteOrder).toLong(),
                    vaddr = readU32(bytes, off + 8, byteOrder).toLong(),
                    flags = readU32(bytes, off + 24, byteOrder),
                    filesz = readU32(bytes, off + 16, byteOrder).toLong(),
                    memsz = readU32(bytes, off + 20, byteOrder).toLong()
                )
            }
        }
        return segments
    }

    private fun parseSections(
        bytes: ByteArray, shoff: Long, shnum: Int, shentsize: Int,
        is64Bit: Boolean, byteOrder: ByteOrder
    ): List<ElfSection> {
        val sections = mutableListOf<ElfSection>()
        for (i in 0 until shnum) {
            val off = (shoff + i * shentsize).toInt()
            if (off + shentsize > bytes.size) break

            if (is64Bit) {
                sections += ElfSection(
                    nameOffset = readU32(bytes, off, byteOrder),
                    type = readU32(bytes, off + 4, byteOrder),
                    flags = readU64(bytes, off + 8, byteOrder),
                    addr = readU64(bytes, off + 16, byteOrder),
                    offset = readU64(bytes, off + 24, byteOrder),
                    size = readU64(bytes, off + 32, byteOrder),
                    link = readU32(bytes, off + 40, byteOrder)
                )
            } else {
                sections += ElfSection(
                    nameOffset = readU32(bytes, off, byteOrder),
                    type = readU32(bytes, off + 4, byteOrder),
                    flags = readU32(bytes, off + 8, byteOrder).toLong(),
                    addr = readU32(bytes, off + 12, byteOrder).toLong(),
                    offset = readU32(bytes, off + 16, byteOrder).toLong(),
                    size = readU32(bytes, off + 20, byteOrder).toLong(),
                    link = readU32(bytes, off + 24, byteOrder)
                )
            }
        }
        return sections
    }

    private fun parseSymbolTables(
        bytes: ByteArray, sections: List<ElfSection>,
        is64Bit: Boolean, byteOrder: ByteOrder
    ): List<ElfSymbol> {
        val allSymbols = mutableListOf<ElfSymbol>()

        for (section in sections) {
            if (!section.isSymtab && !section.isDynsym) continue

            // Use sh_link to find associated string table
            val strtabSection = if (section.link in sections.indices) {
                sections[section.link]
            } else {
                sections.firstOrNull { it.isStrtab && it.offset != section.offset }
            }

            val stringTable = if (strtabSection != null) {
                readStringTable(bytes, strtabSection.offset.toInt(), strtabSection.size.toInt())
            } else emptyMap()

            val entrySize = if (is64Bit) 24 else 16
            val entryCount = (section.size / entrySize).toInt()
            val sectionOffset = section.offset.toInt()

            for (i in 0 until entryCount) {
                val off = sectionOffset + i * entrySize
                if (off + entrySize > bytes.size) break

                val nameOffset: Int
                val info: Int
                val value: Long
                val size: Long
                val sectionIndex: Int

                if (is64Bit) {
                    nameOffset = readU32(bytes, off, byteOrder)
                    info = bytes[off + 4].toInt() and 0xFF
                    sectionIndex = readU16(bytes, off + 6, byteOrder)
                    value = readU64(bytes, off + 8, byteOrder)
                    size = readU64(bytes, off + 16, byteOrder)
                } else {
                    nameOffset = readU32(bytes, off, byteOrder)
                    value = readU32(bytes, off + 4, byteOrder).toLong()
                    size = readU32(bytes, off + 8, byteOrder).toLong()
                    info = bytes[off + 12].toInt() and 0xFF
                    sectionIndex = readU16(bytes, off + 14, byteOrder)
                }

                val name = stringTable[nameOffset] ?: ""
                if (name.isNotBlank()) {
                    allSymbols += ElfSymbol(
                        name = name,
                        value = value,
                        size = size,
                        info = info,
                        sectionIndex = sectionIndex
                    )
                }
            }
        }
        return allSymbols
    }

    private fun readStringTable(bytes: ByteArray, offset: Int, size: Int): Map<Int, String> {
        val result = mutableMapOf<Int, String>()
        val end = (offset + size).coerceAtMost(bytes.size)
        var start = -1
        for (i in offset until end) {
            if (bytes[i].toInt() == 0) {
                if (start >= 0) {
                    result[start - offset] = String(bytes, start, i - start, Charsets.UTF_8)
                    start = -1
                }
            } else if (start < 0) {
                start = i
            }
        }
        return result
    }

    companion object {
        private fun readU16(bytes: ByteArray, offset: Int, order: ByteOrder): Int {
            val b0 = bytes[offset].toInt() and 0xFF
            val b1 = bytes[offset + 1].toInt() and 0xFF
            return if (order == ByteOrder.LITTLE_ENDIAN) b0 or (b1 shl 8) else (b0 shl 8) or b1
        }

        private fun readU32(bytes: ByteArray, offset: Int, order: ByteOrder): Int {
            val b0 = bytes[offset].toInt() and 0xFF
            val b1 = bytes[offset + 1].toInt() and 0xFF
            val b2 = bytes[offset + 2].toInt() and 0xFF
            val b3 = bytes[offset + 3].toInt() and 0xFF
            return if (order == ByteOrder.LITTLE_ENDIAN) {
                b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
            } else {
                (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
            }
        }

        private fun readU64(bytes: ByteArray, offset: Int, order: ByteOrder): Long {
            val lo = readU32(bytes, offset, order).toLong() and 0xFFFFFFFFL
            val hi = readU32(bytes, offset + 4, order).toLong() and 0xFFFFFFFFL
            return if (order == ByteOrder.LITTLE_ENDIAN) lo or (hi shl 32) else (lo shl 32) or hi
        }
    }
}
