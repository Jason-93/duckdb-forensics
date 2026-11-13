# duckdb-forensics

[English](README.md) | **简体中文**

一个只读、离线的 DuckDB 数据库崩溃现场检查器。第一阶段检查 DuckDB v2.0.0 主文件、三个固定 Header 页和基础 Block 几何结构，并以 Text 或 JSON 输出可追溯到文件偏移的 Observation、Finding，以及明确区分的 Inference。

解析器使用 Rust 实现，不依赖 `duckdb-rs`、DuckDB C++ 或 `unsafe` 代码，也不会通过 DuckDB 打开证据文件。

## 支持范围

- 官方 DuckDB **v2.0.0** 原生单文件 `.duckdb` 数据库。
- Storage compatibility **69**，以及 v2.0.0 Main Header 版本标记 **999**。
- 已确认的小端、未加密、默认 8 字节 Header 布局文件。
- Main Header Magic、原始字段和 Checksum。
- 两个 Database Header 的原始字段及独立 Checksum。
- 基于 iteration 的可能有效 Header 选择，以及面向损坏现场的诊断。
- Block allocation size、block count 验证，以及使用 checked arithmetic 的文件长度几何计算。
- 流式计算文件 SHA-256，以及规范化或隐藏的输入路径。

加密文件会通过 Main Header 识别。其加密 Database Header 和 Block 会标记为 `unsupported`，不会按明文计算或报告 Checksum。

## 非目标

本阶段不支持 DuckDB v1.x、加密内容解码、大端文件、非默认 block-header 大小、DuckLake、Parquet、MotherDuck、Catalog 反序列化、free-list/meta-block 内容解码、Row Group、列压缩、业务数据输出、行级恢复、WAL 解析、恢复计划、自动修复、checkpoint、截断或生成替代数据库。

检查通过不代表数据库健康，也不代表 DuckDB 一定能够打开它。有关源码依据、字节布局和未检查区域，请参阅 [FORMAT_NOTES.md](FORMAT_NOTES.md)。

## 构建

需要稳定的 Rust 工具链和 Cargo。

```sh
cargo build --workspace
```

CLI 二进制文件位于 `target/debug/duckdb-forensics`。

## 执行检查

```sh
duckdb-forensics inspect <DB_PATH> [--format text|json] [--output PATH] [--hide-path]
```

示例：

```sh
# 在标准输出中显示人类可读的报告
duckdb-forensics inspect evidence.duckdb

# 在标准输出中显示 JSON，并隐藏规范化输入路径
duckdb-forensics inspect evidence.duckdb --format json --hide-path

# 将 Text 报告写入单独的文件
duckdb-forensics inspect evidence.duckdb --output inspection.txt
```

检查完成时退出码为 0，即使报告包含损坏或不支持特性的 Finding。参数用法、输入 I/O、序列化和输出安全检查失败时退出码为 2。

## 报告模型

JSON 使用 schema version `1`，包含：

- `input`：可选的规范化路径、文件大小和流式 SHA-256（不可用时为 `null`）；
- `observations`：直接观察到的事实，包含 `name`、`structure_path` 和可选的 `file_offset`；
- `findings`：稳定的错误代码、severity、message、location、evidence、remediation hint 和 confidence；
- `inferences`：独立表示、带置信度的推断，例如可能有效的 Header、可能过期的 Header 或可能的撕裂写入；
- `checks_passed`、`checks_failed` 和 `checks_skipped`；
- `coverage`：已检查及明确未检查的区域；
- `unknowns`：在当前证据或支持范围内无法确认的事实。

`--hide-path` 会将 `input.path` 设置为 `null`，但不会隐藏文件大小、哈希、偏移或诊断信息。报告只包含 Header 元数据，不包含表数据行。

稳定 Finding 代码包括 `invalid_magic`、`checksum_mismatch`、`truncated_file`、`unsupported_storage_version`、`unsupported_encryption`、`invalid_block_alloc_size`、`invalid_block_count`、`invalid_metadata_pointer`、`invalid_block_reference`、`geometry_overflow`、`no_valid_database_header` 和 `limit_reached`。

## 只读与输出安全

- `DB_PATH` 始终以只读方式打开。检查器不会调用 DuckDB、创建 WAL 或触发 checkpoint。
- 唯一可选的写入操作是通过 `--output` 指定报告文件。
- 如果输出路径解析后与输入文件相同，操作会被拒绝。符号链接解析以及 Unix device/inode 检查也会防止通过现有别名或硬链接覆盖输入；截断输出前还会再次检查已打开文件的身份。
- Remediation 文本仅为建议，绝不会自动执行。
- 损坏、空、随机、截断、不支持或可能触发溢出的输入会产生结构化诊断，而不会导致解析器 Panic。

请始终保留原始证据，并在副本上执行任何单独的数据库操作。

## 资源限制

检查器最多读取三个固定 4096 字节 Header 页，并通过 1 MiB 缓冲区流式计算 SHA-256。它不会将整个数据库载入内存，也不会根据文件提供的长度分配内存。

默认文件大小预算为 1 TiB。更大的输入会在哈希和 Header 解析前停止，并报告 `limit_reached`；SHA-256 和未检查字段保持 unknown。资源限制不会报告为 corruption。

## 可重复的 Fixture 生成

仓库只提交一个小型官方 v2.0.0 数据库 fixture（536,576 字节），其中包含两行测试数据。损坏变体在测试期间于临时目录生成，不会提交到仓库。

重新生成：

```sh
python3 scripts/generate_fixture.py
```

生成器会下载当前平台对应的官方 v2.0.0 CLI Release 归档，验证其固定 SHA-256 和 `SELECT version()`，然后写入 `normal.duckdb` 以及独立的来源与预期值清单。也可以使用已有的官方二进制文件：

```sh
python3 scripts/generate_fixture.py --duckdb /path/to/duckdb-v2.0.0
```

DuckDB 会生成随机数据库标识符，因此重新生成的数据库结构等价，但不要求逐字节一致。清单记录每次生成的 fixture 哈希和原始 Header 值。运行测试不需要网络或 DuckDB。

## 测试与静态检查

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

测试覆盖官方正常 fixture、空文件、非 DuckDB 文件、随机文件、Main Header 位翻转、任一或两个 Database Header 损坏、截断、非法 block allocation size、巨大 block count、不支持的加密和版本、稳定的 JSON 反序列化、Text 输出、隐藏路径、输出文件，以及直接路径或硬链接覆盖尝试。CLI 测试辅助函数会验证输入 SHA-256 保持不变，并确认没有生成 WAL。

## Workspace 结构

- `crates/duckdb-format`：固定页读取、标量解析、DuckDB Checksum、checked geometry 和格式错误。
- `crates/duckdb-report`：Observation/Finding/Inference 模型、JSON schema 类型和 Text 渲染。
- `crates/duckdb-forensics`：检查流程、CLI、流式 SHA-256 和安全报告输出。
