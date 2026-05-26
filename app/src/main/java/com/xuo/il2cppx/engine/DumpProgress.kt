package com.xuo.il2cppx.engine

data class DumpProgress(
    val phase: String,
    val progress: Float, // 0.0 - 1.0
    val detail: String = ""
) {
    val percent: Int get() = (progress * 100).toInt().coerceIn(0, 100)
}

fun interface ProgressCallback {
    fun onProgress(progress: DumpProgress)
}
