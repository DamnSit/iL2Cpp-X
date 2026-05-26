package com.xuo.il2cppx.engine

import com.xuo.il2cppx.settings.DumpSettings
import com.xuo.il2cppx.settings.OutputFormat
import java.io.File

data class NativeDumpOutput(
    val outputFiles: List<File>,
    val logLines: List<String>,
    val metadata: MetadataParseResult? = null,
    val rvaResult: RvaResult? = null
)

class Il2CppNativeDumper {
    fun dump(
        libFile: File,
        metadataFile: File,
        outputDir: File,
        settings: DumpSettings? = null,
        onProgress: ProgressCallback? = null
    ): NativeDumpOutput {
        outputDir.mkdirs()

        // Try native Rust engine first
        if (NativeDumper.isAvailable()) {
            onProgress?.onProgress(DumpProgress("Parsing dengan Rust native engine", 0.05f))
            val result = NativeDumper.dump(
                libFile.absolutePath,
                metadataFile.absolutePath,
                outputDir.absolutePath,
                settings?.includeRvaInfo ?: true
            )
            if (result.success) {
                val logLines = mutableListOf<String>()
                logLines += "IL2CPP X Rust native dumper"
                logLines += "libil2cpp: ${libFile.absolutePath} (${libFile.length()} bytes)"
                logLines += "metadata: ${metadataFile.absolutePath} (${metadataFile.length()} bytes)"
                logLines += "output: ${outputDir.absolutePath}"
                logLines += "types: ${result.types}"
                logLines += "methods: ${result.methods}"
                logLines += "RVA resolved: ${result.resolvedMethods}/${result.methods} (${result.resolutionRate}%)"
                logLines += "types written: ${result.typesWritten}"
                logLines += "files: ${result.outputFiles.joinToString { it.name }}"
                onProgress?.onProgress(DumpProgress("Selesai (native)", 1.0f, "${result.types} types, ${result.methods} methods"))
                return NativeDumpOutput(
                    outputFiles = result.outputFiles,
                    logLines = logLines
                )
            }
            // Native failed, fall through to Kotlin
        }

        val logLines = mutableListOf<String>()
        logLines += "IL2CPP X native Kotlin dumper"
        logLines += "libil2cpp: ${libFile.absolutePath} (${libFile.length()} bytes)"
        logLines += "metadata: ${metadataFile.absolutePath} (${metadataFile.length()} bytes)"
        logLines += "output: ${outputDir.absolutePath}"

        onProgress?.onProgress(DumpProgress("Validasi input", 0.02f))
        require(libFile.exists() && libFile.length() > 0) { "libil2cpp.so tidak valid atau kosong" }
        require(metadataFile.exists() && metadataFile.length() > 0) { "global-metadata.dat tidak valid atau kosong" }

        val metadata = MetadataParser().parse(metadataFile, onProgress)
        logLines += "metadata magic: 0x${metadata.magic.toString(16).uppercase()}"
        logLines += "metadata version: ${metadata.version}"
        logLines += "metadata file size: ${metadata.fileSize}"
        logLines += "exported string literals: ${metadata.stringLiterals.size}"
        logLines += "images: ${metadata.images.size}"
        logLines += "types: ${metadata.types.size}"
        logLines += "fields: ${metadata.fields.size}"
        logLines += "methods: ${metadata.methods.size}"
        logLines += "parameters: ${metadata.parameters.size}"

        // Parse ELF and resolve RVA
        onProgress?.onProgress(DumpProgress("Parsing ELF", 0.4f))
        val elfParser = ElfParser()
        val elfInfo = elfParser.parse(libFile)
        logLines += "ELF: ${if (elfInfo.is64Bit) "64-bit" else "32-bit"}, ${if (elfInfo.isLittleEndian) "LE" else "BE"}"
        logLines += "ELF segments: ${elfInfo.segments.size}, sections: ${elfInfo.sections.size}"
        logLines += "ELF symbols: ${elfInfo.symbols.size} (${elfInfo.symbols.count { it.isFunction && it.isDefined }} functions)"
        val codeSegs = elfInfo.loadSegments.filter { (it.flags and 0x1) != 0 }
        val codeStart = codeSegs.minOfOrNull { it.vaddr } ?: 0L
        val codeEnd = codeSegs.maxOfOrNull { it.vaddr + it.memsz } ?: 0L
        logLines += "Code range: 0x${codeStart.toString(16)} - 0x${codeEnd.toString(16)}"
        for (seg in elfInfo.loadSegments) {
            logLines += "  Segment: type=${seg.type} flags=0x${seg.flags.toString(16)} vaddr=0x${seg.vaddr.toString(16)} filesz=${seg.filesz} memsz=${seg.memsz}"
        }
        for (sec in elfInfo.sections.take(29)) {
            logLines += "  Section: name='${sec.name}' type=${sec.type} flags=0x${sec.flags.toString(16)} addr=0x${sec.addr.toString(16)} offset=0x${sec.offset.toString(16)} size=${sec.size}"
        }

        val rvaResolver = RvaResolver()
        val rvaResult = rvaResolver.resolve(elfInfo, metadata, libFile, onProgress)
        logLines += "RVA resolved: ${rvaResult.resolvedCount}/${rvaResult.totalMethods} methods (${(rvaResult.resolutionRate * 100).toInt()}%)"
        logLines += "Types with RVA: ${rvaResult.typeRvas.size}"
        for (line in rvaResolver.debugLog) {
            logLines += "  [RVA] $line"
        }

        val outputFiles = mutableListOf<File>()
        val formats = settings?.outputFormats ?: setOf(OutputFormat.DumpCs, OutputFormat.Json)

        if (settings?.generateSummary != false) {
            onProgress?.onProgress(DumpProgress("Menulis summary", 0.92f))
            val summaryFile = File(outputDir, "metadata_summary.json")
            JsonWriters.writeSummary(metadata, summaryFile)
            outputFiles += summaryFile
            logLines += "wrote: ${summaryFile.absolutePath}"
        }

        onProgress?.onProgress(DumpProgress("Menulis RVA report", 0.93f))
        val rvaFile = File(outputDir, "rva_report.json")
        JsonWriters.writeRvaReport(rvaResult, metadata, rvaFile)
        outputFiles += rvaFile
        logLines += "wrote: ${rvaFile.absolutePath}"

        onProgress?.onProgress(DumpProgress("Menulis string literals", 0.94f))
        val stringLiteralFile = File(outputDir, "stringliteral.json")
        JsonWriters.writeStringLiterals(metadata, stringLiteralFile, settings?.maxStringLiterals ?: 10000)
        outputFiles += stringLiteralFile
        logLines += "wrote: ${stringLiteralFile.absolutePath}"

        if (OutputFormat.DumpCs in formats) {
            onProgress?.onProgress(DumpProgress("Menulis dump.cs", 0.96f))
            val dumpCsFile = File(outputDir, "dump.cs")
            val typeWritten = DumpCsWriter(settings).write(metadata, dumpCsFile, rvaResult)
            outputFiles += dumpCsFile
            logLines += "dump.cs types written: $typeWritten"
            logLines += "wrote: ${dumpCsFile.absolutePath}"
        }

        if (OutputFormat.Csv in formats) {
            onProgress?.onProgress(DumpProgress("Menulis CSV", 0.97f))
            val csvFile = File(outputDir, "dump.csv")
            writeCsv(metadata, csvFile)
            outputFiles += csvFile
            logLines += "wrote: ${csvFile.absolutePath}"
        }

        onProgress?.onProgress(DumpProgress("Menulis log", 0.99f))
        val logFile = File(outputDir, "engine_log.txt")
        JsonWriters.writeLog(logLines, logFile)
        outputFiles += logFile

        onProgress?.onProgress(DumpProgress("Selesai", 1.0f, "${metadata.types.size} types, ${metadata.methods.size} methods"))
        return NativeDumpOutput(
            outputFiles = outputFiles,
            logLines = logLines,
            metadata = metadata,
            rvaResult = rvaResult
        )
    }

    private fun writeCsv(metadata: MetadataParseResult, file: File) {
        file.bufferedWriter().use { writer ->
            writer.write("Index,Namespace,Name,Fields,Methods,Properties")
            writer.newLine()
            metadata.types.forEach { type ->
                val ns = type.namespaceName.replace(",", ";")
                val name = type.name.replace(",", ";")
                writer.write("${type.index},$ns,$name,${type.fieldCount},${type.methodCount},${type.propertyCount}")
                writer.newLine()
            }
        }
    }
}
