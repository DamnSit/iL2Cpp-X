package com.xuo.il2cppx

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ZygiskCompanionEngine : DumpEngine<ZygiskInput> {
    override suspend fun run(input: ZygiskInput): DumpResult = withContext(Dispatchers.Default) {
        val normalizedPackage = input.packageName.trim()
        if (normalizedPackage.isBlank()) {
            return@withContext DumpResult(
                success = false,
                log = "Package name target belum diisi."
            )
        }

        DumpResult(
            success = false,
            log = buildString {
                appendLine("Mode: Zygisk Il2CppDumper companion")
                appendLine("Target package: $normalizedPackage")
                appendLine()
                appendLine("Requirement:")
                appendLine("- Device root dengan Magisk v24+.")
                appendLine("- Zygisk aktif.")
                appendLine("- Module Perfare/Zygisk-Il2CppDumper dipasang terpisah.")
                appendLine("- Target dibuka setelah module aktif.")
                appendLine()
                appendLine("Output module biasanya dibuat di sandbox target, misalnya:")
                appendLine("/data/data/$normalizedPackage/files/dump.cs")
                appendLine()
                appendLine("Aplikasi biasa tidak bisa membaca path target tanpa root. Mode ini hanya companion workflow, bukan eksekutor Zygisk di dalam APK.")
            }
        )
    }
}
