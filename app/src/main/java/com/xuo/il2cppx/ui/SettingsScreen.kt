package com.xuo.il2cppx.ui

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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.xuo.il2cppx.settings.DumpSettings
import com.xuo.il2cppx.settings.OutputFormat
import com.xuo.il2cppx.ui.theme.NeonGreen
import com.xuo.il2cppx.ui.theme.DarkCard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    initialSettings: DumpSettings,
    onSave: (DumpSettings) -> Unit,
    onBack: () -> Unit
) {
    var outputDir by remember { mutableStateOf(initialSettings.outputDir) }
    var selectedFormats by remember { mutableStateOf(initialSettings.outputFormats) }
    var maxStringLiterals by remember { mutableStateOf(initialSettings.maxStringLiterals) }
    var includeRva by remember { mutableStateOf(initialSettings.includeRvaInfo) }
    var includeInheritance by remember { mutableStateOf(initialSettings.includeInheritance) }
    var generateSummary by remember { mutableStateOf(initialSettings.generateSummary) }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("Pengaturan", color = NeonGreen) },
                modifier = Modifier.statusBarsPadding(),
                colors = TopAppBarDefaults.smallTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                navigationIcon = {
                    TextButton(onClick = onBack) {
                        Text("< Kembali", color = NeonGreen)
                    }
                }
            )
        }
    ) { innerPadding ->
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState()),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Output directory
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = androidx.compose.material3.CardDefaults.cardColors(containerColor = DarkCard)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Direktori Output", fontWeight = FontWeight.Bold, color = NeonGreen)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = outputDir,
                            onValueChange = { outputDir = it },
                            label = { Text("Path output") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Text(
                            text = "Default: ${DumpSettings.defaultOutputPath()}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // Output formats
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = androidx.compose.material3.CardDefaults.cardColors(containerColor = DarkCard)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Format Output", fontWeight = FontWeight.Bold, color = NeonGreen)
                        Spacer(Modifier.height(8.dp))
                        OutputFormat.values().forEach { format ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Checkbox(
                                    checked = format in selectedFormats,
                                    onCheckedChange = { checked ->
                                        selectedFormats = if (checked) {
                                            selectedFormats + format
                                        } else {
                                            selectedFormats - format
                                        }.takeIf { it.isNotEmpty() } ?: selectedFormats
                                    }
                                )
                                Text(format.label)
                            }
                        }
                    }
                }

                // String literals limit
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = androidx.compose.material3.CardDefaults.cardColors(containerColor = DarkCard)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Batas String Literal", fontWeight = FontWeight.Bold, color = NeonGreen)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = maxStringLiterals.toString(),
                            onValueChange = { it.toIntOrNull()?.let { v -> maxStringLiterals = v } },
                            label = { Text("Maksimum") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                // Dump options
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = androidx.compose.material3.CardDefaults.cardColors(containerColor = DarkCard)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Opsi Dump", fontWeight = FontWeight.Bold, color = NeonGreen)
                        Spacer(Modifier.height(8.dp))
                        CheckboxRow("Sertakan info RVA", includeRva) { includeRva = it }
                        CheckboxRow("Sertakan inheritance", includeInheritance) { includeInheritance = it }
                        CheckboxRow("Generate summary JSON", generateSummary) { generateSummary = it }
                    }
                }

                // Save button
                Button(
                    onClick = {
                        val settings = DumpSettings(
                            outputDir = outputDir.ifBlank { DumpSettings.defaultOutputPath() },
                            outputFormats = selectedFormats,
                            maxStringLiterals = maxStringLiterals.coerceIn(100, 100000),
                            includeRvaInfo = includeRva,
                            includeInheritance = includeInheritance,
                            generateSummary = generateSummary
                        )
                        onSave(settings)
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Simpan Pengaturan")
                }

                Spacer(Modifier.height(32.dp))
            }
        }
    }
}

@Composable
private fun CheckboxRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Text(label)
    }
}
