package com.xuo.il2cppx.engine

import java.io.File

object JsonWriters {
    fun writeSummary(result: MetadataParseResult, file: File) {
        file.writeText(
            buildString {
                appendLine("{")
                appendLine("  \"magic\": \"0x${result.magic.toString(16).uppercase()}\",")
                appendLine("  \"version\": ${result.version},")
                appendLine("  \"fileSize\": ${result.fileSize},")
                appendLine("  \"stringLiteralCountExported\": ${result.stringLiterals.size},")
                appendLine("  \"tables\": [")
                result.ranges.forEachIndexed { index, range ->
                    append("    {")
                    append("\"name\": \"${escape(range.name)}\", ")
                    append("\"offset\": ${range.offset}, ")
                    append("\"size\": ${range.size}, ")
                    append("\"countPair\": ${range.countPair}")
                    append("}")
                    if (index != result.ranges.lastIndex) append(',')
                    appendLine()
                }
                appendLine("  ]")
                appendLine("}")
            }
        )
    }

    fun writeStringLiterals(result: MetadataParseResult, file: File, maxCount: Int = 10000) {
        file.writeText(
            buildString {
                appendLine("[")
                result.stringLiterals.forEachIndexed { index, literal ->
                    append("  {")
                    append("\"index\": ${literal.index}, ")
                    append("\"dataIndex\": ${literal.dataIndex}, ")
                    append("\"length\": ${literal.length}, ")
                    append("\"value\": \"${escape(literal.value)}\"")
                    append("}")
                    if (index != result.stringLiterals.lastIndex) append(',')
                    appendLine()
                }
                appendLine("]")
            }
        )
    }

    fun writeRvaReport(rvaResult: RvaResult, metadata: MetadataParseResult, file: File) {
        file.writeText(
            buildString {
                appendLine("{")
                appendLine("  \"totalMethods\": ${rvaResult.totalMethods},")
                appendLine("  \"resolvedMethods\": ${rvaResult.resolvedCount},")
                appendLine("  \"unresolvedMethods\": ${rvaResult.unresolvedCount},")
                appendLine("  \"resolutionRate\": ${(rvaResult.resolutionRate * 100).toInt()},")
                appendLine("  \"typesWithRva\": ${rvaResult.typeRvas.size},")
                appendLine("  \"methods\": [")
                var count = 0
                metadata.methods.forEachIndexed { index, method ->
                    val rva = rvaResult.methodRvas[index]
                    if (rva != null) {
                        if (count > 0) appendLine(",")
                        append("    {")
                        append("\"index\": $index, ")
                        append("\"name\": \"${escape(method.name)}\", ")
                        append("\"rva\": \"${rva.hexRva}\", ")
                        append("\"size\": ${rva.size}, ")
                        append("\"symbol\": \"${escape(rva.symbolName)}\"")
                        append("}")
                        count++
                    }
                }
                appendLine()
                appendLine("  ]")
                appendLine("}")
            }
        )
    }

    fun writeLog(lines: List<String>, file: File) {
        file.writeText(lines.joinToString(separator = "\n", postfix = "\n"))
    }

    private fun escape(value: String): String = buildString {
        value.forEach { char ->
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> {
                    if (char.code < 0x20) {
                        append("\\u")
                        append(char.code.toString(16).padStart(4, '0'))
                    } else {
                        append(char)
                    }
                }
            }
        }
    }
}
