package com.xuo.il2cppx

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallTopAppBar
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.xuo.il2cppx.engine.DumpProgress
import com.xuo.il2cppx.engine.MetadataParseResult
import com.xuo.il2cppx.engine.ProgressCallback
import com.xuo.il2cppx.engine.RvaResult
import com.xuo.il2cppx.settings.DumpSettings
import com.xuo.il2cppx.ui.SearchScreen
import com.xuo.il2cppx.ui.SettingsScreen
import com.xuo.il2cppx.ui.theme.MyComposeApplicationTheme
import com.xuo.il2cppx.ui.theme.NeonGreen
import com.xuo.il2cppx.ui.theme.NeonGreenDim
import com.xuo.il2cppx.ui.theme.DarkCard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MyComposeApplicationTheme {
                Il2cppDumpApp()
            }
        }
    }
}

private enum class Screen { Main, Settings, Search }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Il2cppDumpApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var currentScreen by remember { mutableStateOf(Screen.Main) }
    var settings by remember { mutableStateOf(DumpSettings.load(context)) }
    var metadataCache by remember { mutableStateOf<MetadataParseResult?>(null) }
    var rvaResultCache by remember { mutableStateOf<RvaResult?>(null) }
    var isLoadingMetadata by remember { mutableStateOf(false) }

    when (currentScreen) {
        Screen.Settings -> {
            SettingsScreen(
                initialSettings = settings,
                onSave = { newSettings ->
                    newSettings.save(context)
                    settings = newSettings
                    currentScreen = Screen.Main
                },
                onBack = { currentScreen = Screen.Main }
            )
        }
        Screen.Search -> {
            SearchScreen(
                metadata = metadataCache,
                rvaResult = rvaResultCache,
                isLoading = isLoadingMetadata,
                onBack = { currentScreen = Screen.Main }
            )
        }
        Screen.Main -> {
            MainScreen(
                settings = settings,
                onSettingsClick = { currentScreen = Screen.Settings },
                onSearchClick = { currentScreen = Screen.Search },
                onMetadataParsed = { metadata, rvaResult ->
                    metadataCache = metadata
                    rvaResultCache = rvaResult
                    isLoadingMetadata = false
                },
                onDumpStarted = { isLoadingMetadata = true }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(
    settings: DumpSettings,
    onSettingsClick: () -> Unit,
    onSearchClick: () -> Unit,
    onMetadataParsed: (MetadataParseResult, RvaResult?) -> Unit,
    onDumpStarted: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var libUri by remember { mutableStateOf<Uri?>(null) }
    var metadataUri by remember { mutableStateOf<Uri?>(null) }
    var selectedMode by remember { mutableStateOf(DumpMode.Offline) }
    var packageName by remember { mutableStateOf("") }
    var logText by remember { mutableStateOf("Pilih mode dan input untuk mulai.") }
    var isDumping by remember { mutableStateOf(false) }
    var progressPhase by remember { mutableStateOf("") }
    var progressValue by remember { mutableStateOf(0f) }
    var progressDetail by remember { mutableStateOf("") }

    val libPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        libUri = uri
        logText = validateSelectedInputs(context, libUri, metadataUri)
    }
    val metadataPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        metadataUri = uri
        logText = validateSelectedInputs(context, libUri, metadataUri)
    }

    val canDump = when (selectedMode) {
        DumpMode.Offline -> libUri != null && metadataUri != null && !isDumping
        DumpMode.ZygiskCompanion -> packageName.isNotBlank()
    }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("IL2CPP X", color = NeonGreen) },
                modifier = Modifier.statusBarsPadding(),
                colors = TopAppBarDefaults.smallTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                actions = {
                    TextButton(onClick = onSearchClick) {
                        Text("Cari", color = NeonGreen)
                    }
                    TextButton(onClick = onSettingsClick) {
                        Text("Settings", color = NeonGreen)
                    }
                }
            )
        }
    ) { innerPadding ->
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "IL2CPP Dumper",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    color = NeonGreen
                )
                Text(
                    text = "Workflow lokal untuk memilih file Unity IL2CPP dan menyiapkan proses dump secara aman.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                ModeSelector(
                    selectedMode = selectedMode,
                    onModeSelected = { mode ->
                        selectedMode = mode
                        logText = mode.description
                    }
                )

                if (selectedMode == DumpMode.Offline) {
                    FilePickerCard(
                        title = "Library IL2CPP",
                        fileName = libUri?.let { getDisplayName(context, it) } ?: "Belum dipilih",
                        buttonText = "Pilih libil2cpp.so",
                        onClick = { libPicker.launch(arrayOf("application/octet-stream", "application/x-sharedlib", "*/*")) }
                    )

                    FilePickerCard(
                        title = "Metadata",
                        fileName = metadataUri?.let { getDisplayName(context, it) } ?: "Belum dipilih",
                        buttonText = "Pilih global-metadata.dat",
                        onClick = { metadataPicker.launch(arrayOf("application/octet-stream", "*/*")) }
                    )
                } else {
                    ZygiskCard(
                        packageName = packageName,
                        onPackageNameChange = { packageName = it }
                    )
                }

                // Progress indicator
                AnimatedVisibility(visible = isDumping) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = androidx.compose.material3.CardDefaults.cardColors(
                            containerColor = DarkCard
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(progressPhase, fontWeight = FontWeight.Bold, color = NeonGreen)
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(
                                progress = progressValue,
                                modifier = Modifier.fillMaxWidth(),
                                color = NeonGreen,
                                trackColor = NeonGreen.copy(alpha = 0.15f)
                            )
                            Spacer(Modifier.height(4.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "${(progressValue * 100).toInt()}%",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                if (progressDetail.isNotBlank()) {
                                    Text(
                                        text = progressDetail,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        enabled = canDump,
                        onClick = {
                            isDumping = true
                            progressPhase = "Menyiapkan..."
                            progressValue = 0f
                            onDumpStarted()
                            scope.launch {
                                val adapter = Il2cppDumpAdapter(
                                    context,
                                    settings,
                                    ProgressCallback { progress ->
                                        progressPhase = progress.phase
                                        progressValue = progress.progress
                                        progressDetail = progress.detail
                                    }
                                )
                                val result = when (selectedMode) {
                                    DumpMode.Offline -> {
                                        val selectedLib = libUri
                                        val selectedMetadata = metadataUri
                                        if (selectedLib == null || selectedMetadata == null) {
                                            isDumping = false
                                            return@launch
                                        }
                                        adapter.prepareAndDump(
                                            DumpInput(
                                                libIl2cppUri = selectedLib,
                                                metadataUri = selectedMetadata
                                            )
                                        )
                                    }
                                    DumpMode.ZygiskCompanion -> adapter.prepareZygiskWorkflow(
                                        ZygiskInput(packageName = packageName)
                                    )
                                }
                                logText = result.log
                                isDumping = false

                                // Cache metadata and RVA for search
                                if (result.success && result.metadata != null) {
                                    onMetadataParsed(result.metadata, result.rvaResult)
                                }
                            }
                        }
                    ) {
                        Text(if (selectedMode == DumpMode.Offline) "Dump metadata" else "Siapkan")
                    }
                    OutlinedButton(
                        onClick = {
                            libUri = null
                            metadataUri = null
                            packageName = ""
                            logText = "Pilihan direset. Pilih input baru."
                        }
                    ) {
                        Text("Reset")
                    }
                }

                LogCard(logText)
            }
        }
    }
}

@Composable
private fun ModeSelector(
    selectedMode: DumpMode,
    onModeSelected: (DumpMode) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = DarkCard
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("Mode engine", fontWeight = FontWeight.Bold, color = NeonGreen)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                DumpMode.values().forEach { mode ->
                    val isSelected = selectedMode == mode
                    if (isSelected) {
                        Button(onClick = { onModeSelected(mode) }) {
                            Text(mode.label)
                        }
                    } else {
                        OutlinedButton(onClick = { onModeSelected(mode) }) {
                            Text(mode.label)
                        }
                    }
                }
            }
            Text(selectedMode.description, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ZygiskCard(
    packageName: String,
    onPackageNameChange: (String) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = DarkCard
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("Zygisk companion", fontWeight = FontWeight.Bold, color = NeonGreen)
            OutlinedTextField(
                value = packageName,
                onValueChange = onPackageNameChange,
                label = { Text("Package name target") },
                placeholder = { Text("com.example.game") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Text(
                text = "Mode ini hanya menyiapkan workflow untuk module Zygisk terpisah pada device root/Magisk.",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun FilePickerCard(
    title: String,
    fileName: String,
    buttonText: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = DarkCard
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(title, fontWeight = FontWeight.Bold, color = NeonGreen)
            Text(fileName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(onClick = onClick) {
                Text(buttonText)
            }
        }
    }
}

@Composable
private fun LogCard(text: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = DarkCard
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Log", fontWeight = FontWeight.Bold, color = NeonGreen)
            Spacer(Modifier.height(8.dp))
            Text(
                text = text,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                color = NeonGreenDim
            )
        }
    }
}

private fun validateSelectedInputs(context: Context, libUri: Uri?, metadataUri: Uri?): String {
    val messages = mutableListOf<String>()
    if (libUri == null) {
        messages += "- libil2cpp.so belum dipilih"
    } else {
        messages += validateReadableFile(context, libUri, ".so", "libil2cpp.so")
    }

    if (metadataUri == null) {
        messages += "- global-metadata.dat belum dipilih"
    } else {
        messages += validateReadableFile(context, metadataUri, ".dat", "global-metadata.dat")
    }

    return if (messages.all { it.startsWith("+") }) {
        "Input valid. Siap menjalankan dump.\n" + messages.joinToString("\n")
    } else {
        messages.joinToString("\n")
    }
}

private fun validateReadableFile(context: Context, uri: Uri, extension: String, expectedName: String): String {
    val displayName = getDisplayName(context, uri)
    val hasExpectedName = displayName == expectedName || displayName.endsWith(extension, ignoreCase = true)
    if (!hasExpectedName) {
        return "- $displayName tidak terlihat seperti $expectedName"
    }

    return try {
        context.contentResolver.openInputStream(uri)?.use { input ->
            val header = ByteArray(16)
            val read = input.read(header)
            if (read > 0) "+ $displayName dapat dibaca" else "- $displayName kosong"
        } ?: "- $displayName tidak bisa dibuka"
    } catch (error: Exception) {
        "- $displayName gagal dibaca: ${error.message ?: error.javaClass.simpleName}"
    }
}

private fun getDisplayName(context: Context, uri: Uri): String {
    if (uri.scheme == "file") return uri.lastPathSegment ?: "unknown"
    val cursor: Cursor? = context.contentResolver.query(uri, null, null, null, null)
    cursor.use {
        if (it != null && it.moveToFirst()) {
            val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0) return it.getString(index)
        }
    }
    return uri.lastPathSegment ?: "unknown"
}
