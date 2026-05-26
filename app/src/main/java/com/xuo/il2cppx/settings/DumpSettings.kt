package com.xuo.il2cppx.settings

import android.content.Context
import android.content.SharedPreferences
import android.os.Environment
import java.io.File

enum class OutputFormat(val label: String, val extension: String) {
    DumpCs("dump.cs", "cs"),
    Json("JSON", "json"),
    Csv("CSV", "csv")
}

data class DumpSettings(
    val outputDir: String = defaultOutputPath(),
    val outputFormats: Set<OutputFormat> = setOf(OutputFormat.DumpCs, OutputFormat.Json),
    val maxStringLiterals: Int = 10000,
    val includeRvaInfo: Boolean = true,
    val includeInheritance: Boolean = true,
    val generateSummary: Boolean = true
) {
    companion object {
        private const val PREFS_NAME = "il2cppx_settings"
        private const val KEY_OUTPUT_DIR = "output_dir"
        private const val KEY_FORMAT_DUMP_CS = "format_dump_cs"
        private const val KEY_FORMAT_JSON = "format_json"
        private const val KEY_FORMAT_CSV = "format_csv"
        private const val KEY_MAX_STRING_LITERALS = "max_string_literals"
        private const val KEY_INCLUDE_RVA = "include_rva"
        private const val KEY_INCLUDE_INHERITANCE = "include_inheritance"
        private const val KEY_GENERATE_SUMMARY = "generate_summary"

        fun defaultOutputPath(): String =
            File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "Dump").absolutePath

        fun load(context: Context): DumpSettings {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val formats = mutableSetOf<OutputFormat>()
            if (prefs.getBoolean(KEY_FORMAT_DUMP_CS, true)) formats += OutputFormat.DumpCs
            if (prefs.getBoolean(KEY_FORMAT_JSON, true)) formats += OutputFormat.Json
            if (prefs.getBoolean(KEY_FORMAT_CSV, false)) formats += OutputFormat.Csv
            if (formats.isEmpty()) formats += OutputFormat.DumpCs

            return DumpSettings(
                outputDir = prefs.getString(KEY_OUTPUT_DIR, defaultOutputPath()) ?: defaultOutputPath(),
                outputFormats = formats,
                maxStringLiterals = prefs.getInt(KEY_MAX_STRING_LITERALS, 10000),
                includeRvaInfo = prefs.getBoolean(KEY_INCLUDE_RVA, true),
                includeInheritance = prefs.getBoolean(KEY_INCLUDE_INHERITANCE, true),
                generateSummary = prefs.getBoolean(KEY_GENERATE_SUMMARY, true)
            )
        }
    }

    fun save(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().apply {
            putString(KEY_OUTPUT_DIR, outputDir)
            putBoolean(KEY_FORMAT_DUMP_CS, OutputFormat.DumpCs in outputFormats)
            putBoolean(KEY_FORMAT_JSON, OutputFormat.Json in outputFormats)
            putBoolean(KEY_FORMAT_CSV, OutputFormat.Csv in outputFormats)
            putInt(KEY_MAX_STRING_LITERALS, maxStringLiterals)
            putBoolean(KEY_INCLUDE_RVA, includeRvaInfo)
            putBoolean(KEY_INCLUDE_INHERITANCE, includeInheritance)
            putBoolean(KEY_GENERATE_SUMMARY, generateSummary)
            apply()
        }
    }
}
