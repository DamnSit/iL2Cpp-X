package com.xuo.il2cppx

import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.xuo.il2cppx.engine.Il2CppNativeDumper
import com.xuo.il2cppx.engine.ProgressCallback
import com.xuo.il2cppx.settings.DumpSettings
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class OfflineIl2CppDumperEngine(
    private val context: Context,
    private val settings: DumpSettings? = null,
    private val onProgress: ProgressCallback? = null
) : DumpEngine<DumpInput> {
    override suspend fun run(input: DumpInput): DumpResult = withContext(Dispatchers.IO) {
        try {
            val workDir = File(context.filesDir, "il2cpp-input").apply { mkdirs() }
            val privateOutputDir = File(context.filesDir, "il2cpp-output").apply { mkdirs() }
            onProgress?.onProgress(com.xuo.il2cppx.engine.DumpProgress("Menyalin file input", 0.01f))
            val libFile = copyUriToFile(input.libIl2cppUri, File(workDir, "libil2cpp.so"))
            val metadataFile = copyUriToFile(input.metadataUri, File(workDir, "global-metadata.dat"))

            val dumpOutput = Il2CppNativeDumper().dump(libFile, metadataFile, privateOutputDir, settings, onProgress)

            val customOutputDir = settings?.outputDir
            val publishedFiles = if (customOutputDir != null && customOutputDir != DumpSettings.defaultOutputPath()) {
                val targetDir = File(customOutputDir).apply { mkdirs() }
                dumpOutput.outputFiles.map { file ->
                    val target = File(targetDir, file.name)
                    file.copyTo(target, overwrite = true)
                    PublishedFile(file.name, Uri.fromFile(target))
                }
            } else {
                dumpOutput.outputFiles.map { publishToDownloads(it) }
            }

            DumpResult(
                success = true,
                log = buildString {
                    appendLine("Mode: Offline Kotlin Il2CppDumper")
                    appendLine("Dump metadata berhasil dibuat.")
                    appendLine("output: ${settings?.outputDir ?: "/storage/emulated/0/Download/Dump"}")
                    publishedFiles.forEach { published ->
                        appendLine("- ${published.name}")
                    }
                    appendLine()
                    appendLine("Total types: ${dumpOutput.logLines.firstOrNull { it.startsWith("types:") }?.substringAfter(": ") ?: "?"}")
                    appendLine("Total methods: ${dumpOutput.logLines.firstOrNull { it.startsWith("methods:") }?.substringAfter(": ") ?: "?"}")
                },
                metadata = dumpOutput.metadata,
                rvaResult = dumpOutput.rvaResult
            )
        } catch (error: Exception) {
            DumpResult(
                success = false,
                log = "Dump gagal: ${error.message ?: error.javaClass.simpleName}"
            )
        }
    }

    private fun copyUriToFile(uri: Uri, target: File): File {
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Tidak bisa membuka input" }
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    private fun publishToDownloads(source: File): PublishedFile {
        val resolver = context.contentResolver
        val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)

        // Use unique name with timestamp to avoid UNIQUE constraint on all Android versions
        val timestamp = System.currentTimeMillis()
        val baseName = source.nameWithoutExtension
        val ext = source.extension
        val uniqueName = "${baseName}_${timestamp}.${ext}"

        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, uniqueName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeTypeFor(source.name))
            put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/Dump")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
        }

        val uri = requireNotNull(resolver.insert(collection, values)) {
            "Gagal membuat file output $uniqueName di Download/Dump"
        }

        resolver.openOutputStream(uri, "w").use { output ->
            requireNotNull(output) { "Gagal membuka output ${source.name}" }
            source.inputStream().use { input -> input.copyTo(output) }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val doneValues = ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }
            resolver.update(uri, doneValues, null, null)
        }

        return PublishedFile(uniqueName, uri)
    }

    private fun mimeTypeFor(name: String): String = when {
        name.endsWith(".json", ignoreCase = true) -> "application/json"
        name.endsWith(".cs", ignoreCase = true) -> "text/plain"
        name.endsWith(".txt", ignoreCase = true) -> "text/plain"
        else -> "application/octet-stream"
    }

    private data class PublishedFile(
        val name: String,
        val uri: Uri
    )
}
