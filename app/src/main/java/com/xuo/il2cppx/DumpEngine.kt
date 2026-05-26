package com.xuo.il2cppx

import android.net.Uri
import com.xuo.il2cppx.engine.MetadataParseResult
import com.xuo.il2cppx.engine.RvaResult

enum class DumpMode(
    val label: String,
    val description: String
) {
    Offline(
        label = "Offline",
        description = "Siapkan libil2cpp.so dan global-metadata.dat untuk engine Il2CppDumper lokal."
    ),
    ZygiskCompanion(
        label = "Zygisk",
        description = "Workflow companion untuk device root/Magisk/Zygisk yang memakai module dumper terpisah."
    )
}

data class DumpInput(
    val libIl2cppUri: Uri,
    val metadataUri: Uri
)

data class ZygiskInput(
    val packageName: String
)

data class DumpResult(
    val success: Boolean,
    val log: String,
    val metadata: MetadataParseResult? = null,
    val rvaResult: RvaResult? = null
)

interface DumpEngine<T> {
    suspend fun run(input: T): DumpResult
}
