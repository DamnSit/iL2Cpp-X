package com.xuo.il2cppx

import android.content.Context
import com.xuo.il2cppx.engine.ProgressCallback
import com.xuo.il2cppx.settings.DumpSettings

class Il2cppDumpAdapter(
    context: Context,
    settings: DumpSettings? = null,
    onProgress: ProgressCallback? = null
) {
    private val offlineEngine = OfflineIl2CppDumperEngine(context, settings, onProgress)
    private val zygiskEngine = ZygiskCompanionEngine()

    suspend fun prepareAndDump(input: DumpInput): DumpResult = offlineEngine.run(input)

    suspend fun prepareZygiskWorkflow(input: ZygiskInput): DumpResult = zygiskEngine.run(input)
}
