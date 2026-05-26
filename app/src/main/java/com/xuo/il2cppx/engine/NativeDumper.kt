package com.xuo.il2cppx.engine

import java.io.File
import org.json.JSONObject

data class NativeDumpResult(
    val success: Boolean,
    val types: Int = 0,
    val methods: Int = 0,
    val resolvedMethods: Int = 0,
    val typesWritten: Int = 0,
    val resolutionRate: Int = 0,
    val error: String = "",
    val logLines: List<String> = emptyList(),
    val outputFiles: List<File> = emptyList()
)

object NativeDumper {

    private var libraryLoaded = false

    init {
        try {
            System.loadLibrary("il2cpp_native")
            libraryLoaded = true
        } catch (e: UnsatisfiedLinkError) {
            libraryLoaded = false
        }
    }

    fun isAvailable(): Boolean = libraryLoaded

    /**
     * Dump IL2CPP using native Rust engine.
     * Returns a NativeDumpResult with the dump results.
     */
    fun dump(
        libPath: String,
        metadataPath: String,
        outputDir: String,
        includeRvaInfo: Boolean = true
    ): NativeDumpResult {
        if (!isAvailable()) {
            return NativeDumpResult(
                success = false,
                error = "Native library not loaded"
            )
        }

        return try {
            val outputDirFile = File(outputDir).apply { mkdirs() }
            val jsonStr = nativeDump(libPath, metadataPath, outputDir, includeRvaInfo)
            parseResult(jsonStr, outputDirFile)
        } catch (e: UnsatisfiedLinkError) {
            NativeDumpResult(
                success = false,
                error = "Native library not loaded: ${e.message}"
            )
        } catch (e: Exception) {
            NativeDumpResult(
                success = false,
                error = "Native dump error: ${e.message}"
            )
        }
    }

    private fun parseResult(jsonStr: String, outputDir: File): NativeDumpResult {
        return try {
            val json = JSONObject(jsonStr)
            val success = json.optBoolean("success", false)

            // Collect output files that exist
            val outputFiles = mutableListOf<File>()
            if (success) {
                val possibleFiles = listOf("dump.cs", "metadata_summary.json", "rva_report.json", "stringliteral.json", "engine_log.txt")
                for (name in possibleFiles) {
                    val file = File(outputDir, name)
                    if (file.exists() && file.length() > 0) {
                        outputFiles.add(file)
                    }
                }
            }

            NativeDumpResult(
                success = success,
                types = json.optInt("types", 0),
                methods = json.optInt("methods", 0),
                resolvedMethods = json.optInt("resolvedMethods", 0),
                typesWritten = json.optInt("typesWritten", 0),
                resolutionRate = json.optInt("resolutionRate", 0),
                error = json.optString("error", ""),
                outputFiles = outputFiles
            )
        } catch (e: Exception) {
            NativeDumpResult(
                success = false,
                error = "Failed to parse native result: ${e.message}"
            )
        }
    }

    @JvmStatic
    private external fun nativeDump(
        libPath: String,
        metadataPath: String,
        outputDir: String,
        includeRvaInfo: Boolean
    ): String
}
