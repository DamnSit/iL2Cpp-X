package com.xuo.il2cppx.engine

data class MetadataRange(
    val name: String,
    val offset: Int,
    val size: Int
) {
    val countPair: Int get() = size / 8
}

data class MetadataImage(
    val index: Int,
    val name: String,
    val typeStart: Int,
    val typeCount: Int
)

data class MetadataTypeDefinition(
    val index: Int,
    val name: String,
    val namespaceName: String,
    val fieldStart: Int,
    val methodStart: Int,
    val propertyStart: Int,
    val fieldCount: Int,
    val methodCount: Int,
    val propertyCount: Int
)

data class MetadataFieldDefinition(
    val index: Int,
    val name: String,
    val typeIndex: Int
)

data class MetadataMethodDefinition(
    val index: Int,
    val name: String,
    val returnType: Int,
    val parameterStart: Int,
    val parameterCount: Int
)

data class MetadataParameterDefinition(
    val index: Int,
    val name: String,
    val typeIndex: Int
)

data class StringLiteral(
    val index: Int,
    val dataIndex: Int,
    val length: Int,
    val value: String
)

data class MetadataParseResult(
    val magic: Long,
    val version: Int,
    val fileSize: Int,
    val ranges: List<MetadataRange>,
    val stringLiterals: List<StringLiteral>,
    val images: List<MetadataImage>,
    val types: List<MetadataTypeDefinition>,
    val fields: List<MetadataFieldDefinition>,
    val methods: List<MetadataMethodDefinition>,
    val parameters: List<MetadataParameterDefinition>
)
