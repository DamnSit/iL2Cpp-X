package com.xuo.il2cppx.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallTopAppBar
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.xuo.il2cppx.engine.MetadataParseResult
import com.xuo.il2cppx.engine.RvaResult
import com.xuo.il2cppx.ui.theme.NeonGreen
import com.xuo.il2cppx.ui.theme.NeonGreenDim
import com.xuo.il2cppx.ui.theme.DarkCard
import com.xuo.il2cppx.ui.theme.DarkCardClass
import com.xuo.il2cppx.ui.theme.DarkCardMethod
import com.xuo.il2cppx.ui.theme.DarkCardField
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

enum class SearchFilter(val label: String) {
    All("Semua"),
    Classes("Class"),
    Methods("Method"),
    Fields("Field")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SearchScreen(
    metadata: MetadataParseResult?,
    rvaResult: RvaResult? = null,
    isLoading: Boolean,
    onBack: () -> Unit
) {
    if (metadata == null) {
        EmptySearchState(isLoading, onBack)
        return
    }
    val context = LocalContext.current
    var query by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf(SearchFilter.All) }
    var searchResults by remember { mutableStateOf<List<SearchResultItem>>(emptyList()) }
    var expandedItem by remember { mutableStateOf<SearchResultItem?>(null) }

    LaunchedEffect(query, selectedFilter, metadata, rvaResult) {
        if (query.length < 2) {
            searchResults = emptyList()
            return@LaunchedEffect
        }
        searchResults = withContext(Dispatchers.Default) {
            searchMetadata(metadata, query, selectedFilter, rvaResult)
        }
    }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("Cari Dump") },
                modifier = Modifier.statusBarsPadding(),
                colors = TopAppBarDefaults.smallTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = NeonGreen
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
                .padding(innerPadding),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Cari class, method, atau field...") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(8.dp))

                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    SearchFilter.values().forEach { filter ->
                        FilterChip(
                            selected = selectedFilter == filter,
                            onClick = { selectedFilter = filter },
                            label = { Text(filter.label) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = NeonGreen.copy(alpha = 0.2f),
                                selectedLabelColor = NeonGreen
                            )
                        )
                    }
                }

                Spacer(Modifier.height(8.dp))

                if (query.length >= 2) {
                    Text(
                        text = "${searchResults.size} hasil ditemukan",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                if (isLoading) {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        CircularProgressIndicator(color = NeonGreen)
                        Spacer(Modifier.height(8.dp))
                        Text("Memuat data dump...", color = NeonGreenDim)
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        items(searchResults.take(500)) { item ->
                            SearchResultCard(
                                item = item,
                                isExpanded = expandedItem == item,
                                rvaResult = rvaResult,
                                context = context,
                                onClick = {
                                    expandedItem = if (expandedItem == item) null else item
                                }
                            )
                        }

                        if (searchResults.size > 500) {
                            item {
                                Text(
                                    text = "...dan ${searchResults.size - 500} hasil lainnya",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(8.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SearchResultCard(
    item: SearchResultItem,
    isExpanded: Boolean,
    rvaResult: RvaResult? = null,
    context: Context,
    onClick: () -> Unit
) {
    val cardColor = when (item.type) {
        SearchResultType.Class -> DarkCardClass
        SearchResultType.Method -> DarkCardMethod
        SearchResultType.Field -> DarkCardField
    }
    val tagColor = when (item.type) {
        SearchResultType.Class -> NeonGreen
        SearchResultType.Method -> NeonGreenDim
        SearchResultType.Field -> NeonGreen.copy(alpha = 0.7f)
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = cardColor)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = when (item.type) {
                        SearchResultType.Class -> "[C]"
                        SearchResultType.Method -> "[M]"
                        SearchResultType.Field -> "[F]"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = tagColor
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = item.name,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            if (item.namespace.isNotBlank()) {
                Text(
                    text = item.namespace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            if (isExpanded) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = item.detail,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
                if (item.type == SearchResultType.Method && rvaResult != null && item.methodIndex >= 0) {
                    val methodRva = rvaResult.methodRvas[item.methodIndex]
                    if (methodRva != null) {
                        Spacer(Modifier.height(4.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = buildAnnotatedString {
                                    withStyle(SpanStyle(color = NeonGreen, fontFamily = FontFamily.Monospace)) {
                                        append("RVA: ${methodRva.hexRva}")
                                    }
                                    withStyle(SpanStyle(color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)) {
                                        append("  Size: ${methodRva.hexSize}")
                                    }
                                },
                                style = MaterialTheme.typography.bodySmall
                            )
                            Spacer(Modifier.weight(1f))
                            TextButton(
                                onClick = {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    clipboard.setPrimaryClip(ClipData.newPlainText("RVA", methodRva.hexRva))
                                    Toast.makeText(context, "RVA disalin: ${methodRva.hexRva}", Toast.LENGTH_SHORT).show()
                                }
                            ) {
                                Text("Salin", color = NeonGreen, style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
        }
    }
}

enum class SearchResultType { Class, Method, Field }

data class SearchResultItem(
    val name: String,
    val namespace: String,
    val type: SearchResultType,
    val detail: String,
    val methodIndex: Int = -1
)

private fun searchMetadata(
    metadata: MetadataParseResult,
    query: String,
    filter: SearchFilter,
    rvaResult: RvaResult? = null
): List<SearchResultItem> {
    val results = mutableListOf<SearchResultItem>()
    val lowerQuery = query.lowercase()

    if (filter == SearchFilter.All || filter == SearchFilter.Classes) {
        metadata.types.forEach { type ->
            if (type.name.lowercase().contains(lowerQuery) ||
                type.namespaceName.lowercase().contains(lowerQuery)
            ) {
                results += SearchResultItem(
                    name = type.name,
                    namespace = type.namespaceName,
                    type = SearchResultType.Class,
                    detail = buildString {
                        appendLine("TypeDefIndex: ${type.index}")
                        appendLine("Fields: ${type.fieldCount}, Methods: ${type.methodCount}")
                        appendLine("FieldStart: ${type.fieldStart}, MethodStart: ${type.methodStart}")
                    }
                )
            }
        }
    }

    if (filter == SearchFilter.All || filter == SearchFilter.Methods) {
        metadata.methods.forEach { method ->
            if (method.name.lowercase().contains(lowerQuery)) {
                val parentType = metadata.types.firstOrNull {
                    method.index in it.methodStart until it.methodStart + it.methodCount
                }
                results += SearchResultItem(
                    name = method.name,
                    namespace = parentType?.namespaceName ?: "",
                    type = SearchResultType.Method,
                    detail = buildString {
                        appendLine("MethodIndex: ${method.index}")
                        appendLine("ReturnType: ${method.returnType}")
                        appendLine("Parameters: ${method.parameterCount}")
                        if (parentType != null) appendLine("Class: ${parentType.namespaceName}.${parentType.name}")
                    },
                    methodIndex = method.index
                )
            }
        }
    }

    if (filter == SearchFilter.All || filter == SearchFilter.Fields) {
        metadata.fields.forEach { field ->
            if (field.name.lowercase().contains(lowerQuery)) {
                val parentType = metadata.types.firstOrNull {
                    field.index in it.fieldStart until it.fieldStart + it.fieldCount
                }
                results += SearchResultItem(
                    name = field.name,
                    namespace = parentType?.namespaceName ?: "",
                    type = SearchResultType.Field,
                    detail = buildString {
                        appendLine("FieldIndex: ${field.index}")
                        appendLine("TypeIndex: ${field.typeIndex}")
                        if (parentType != null) appendLine("Class: ${parentType.namespaceName}.${parentType.name}")
                    }
                )
            }
        }
    }

    return results.sortedWith(compareBy<SearchResultItem> { it.type.ordinal }.thenBy { it.name })
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EmptySearchState(isLoading: Boolean, onBack: () -> Unit) {
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("Cari Dump") },
                modifier = Modifier.statusBarsPadding(),
                colors = TopAppBarDefaults.smallTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = NeonGreen
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
                .padding(innerPadding),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                if (isLoading) {
                    CircularProgressIndicator(color = NeonGreen)
                    Spacer(Modifier.height(8.dp))
                    Text("Memuat data dump...", color = NeonGreenDim)
                } else {
                    Text(
                        text = "Belum ada data dump.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "Jalankan dump terlebih dahulu, lalu buka menu Cari.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}
