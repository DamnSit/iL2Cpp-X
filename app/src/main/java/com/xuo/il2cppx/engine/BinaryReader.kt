package com.xuo.il2cppx.engine

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset

class BinaryReader private constructor(private val bytes: ByteArray) {
    companion object {
        fun fromFile(file: File): BinaryReader = BinaryReader(file.readBytes())
    }

    val size: Int get() = bytes.size

    fun int16(offset: Int): Short {
        requireRange(offset, 2)
        return ByteBuffer.wrap(bytes, offset, 2).order(ByteOrder.LITTLE_ENDIAN).short
    }

    fun uint16(offset: Int): Int = int16(offset).toInt() and 0xFFFF

    fun int32(offset: Int): Int {
        requireRange(offset, 4)
        return ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int
    }

    fun uint32(offset: Int): Long = int32(offset).toLong() and 0xFFFFFFFFL

    fun bytes(offset: Int, length: Int): ByteArray {
        requireRange(offset, length)
        return bytes.copyOfRange(offset, offset + length)
    }

    fun utf8(offset: Int, length: Int): String {
        if (length <= 0) return ""
        val raw = bytes(offset, length)
        val trimmedLength = raw.indexOf(0).takeIf { it >= 0 } ?: raw.size
        return raw.copyOf(trimmedLength).toString(Charset.forName("UTF-8"))
    }

    fun isValidRange(offset: Int, length: Int): Boolean {
        if (offset < 0 || length < 0) return false
        val end = offset.toLong() + length.toLong()
        return end <= bytes.size
    }

    private fun requireRange(offset: Int, length: Int) {
        require(isValidRange(offset, length)) { "Range out of metadata bounds: offset=$offset length=$length size=${bytes.size}" }
    }
}
