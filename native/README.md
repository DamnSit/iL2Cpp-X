# IL2CPP X - Rust Native Dumper

A Rust-native IL2CPP metadata + binary dumper for Android games.

## Features

- Parses `global-metadata.dat` (metadata v16-v39, Unity 5.3 - Unity 6)
- Parses `libil2cpp.so` (ELF64, AArch64)
- RVA resolution via CodeGenModule, symbol table, and dense pointer scanning
- Generates `dump.cs` and `script.json` compatible with Frida/Ghidra/IDA
- Supports R_AARCH64_RELATIVE relocations
- Supports v33+ varint length-prefixed string pool

## Build

```bash
# For Android (Termux)
cargo build --release --target aarch64-linux-android

# For desktop (testing)
cargo build --release
```

### Android NDK Setup

Create `.cargo/config.toml` with your NDK path:

```toml
[target.aarch64-linux-android]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang"
```

## Usage

```bash
# Dump
./dump <libil2cpp.so> <global-metadata.dat> [output_dir]

# Diagnose metadata only
./dump --diagnose <global-metadata.dat>
```

## Output

- `dump.cs` - C# type/method/field dump with RVA annotations
- `script.json` - Frida-compatible script format
- `metadata_summary.json` - Metadata table info
- `rva_report.json` - RVA resolution report
- `stringliteral.json` - String literal pool

## Architecture

```
src/
  main.rs            - CLI entrypoint
  lib.rs             - Core dump orchestration
  binary_reader.rs   - Low-level byte reading
  elf_parser.rs      - ELF32/ELF64 parser
  metadata_parser.rs - Global metadata parser
  metadata_models.rs - Data structures
  rva_resolver.rs    - RVA resolution engine
  dump_cs_writer.rs  - dump.cs generator
  json_writers.rs    - JSON output writers
```

## Supported Metadata Versions

| Version | Unity Range           | TypeDef Stride | Status    |
|---------|-----------------------|----------------|-----------|
| 16      | Unity 5.0-5.2         | 64             | Supported |
| 17      | Unity 5.3             | 64             | Supported |
| 19      | Unity 5.4-5.5         | 64             | Supported |
| 20      | Unity 5.6             | 72             | Supported |
| 21      | Unity 2017.1          | 72             | Supported |
| 22      | Unity 2017.2          | 72             | Supported |
| 23      | Unity 2017.3-2018.2   | 80             | Supported |
| 24      | Unity 2018.3-2019.4   | 96             | Supported |
| 27      | Unity 2020.2-2021.1   | 104            | Supported |
| 29      | Unity 2021.3 LTS      | 112            | Supported |
| 31      | Unity 2022.3 LTS      | 120            | Supported |
| 33      | Unity 2024.1+         | 128            | Supported |
| 35      | Unity 2025-2026       | 136            | Supported |

## License

MIT
