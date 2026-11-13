# duckdb-forensics

[English](README.md) | **简体中文**

一个只读、离线的 DuckDB 数据库及 WAL 崩溃现场检查器。第一阶段检查 DuckDB v2.0.0 主文件、三个固定 Header 页和基础 Block 几何结构；第二阶段在不执行 Replay 的情况下分析未加密 WAL v2 帧。报告以 Text 或 JSON 输出可追溯到文件偏移的 Observation、Finding、明确区分的 Inference，以及解析覆盖率。

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

`wal` 子命令的支持范围更窄：

- 官方 DuckDB **v2.0.0** 未加密 **WAL version 2** 的小端帧格式。
- 无帧 BinarySerializer 版本对象，以及 `length + checksum + Payload` Entry 帧。
- 流式 Entry Checksum、declared/actual length、结构错误偏移和零/非零尾部证据。
- 源码定义的 WALType 封装、精确的空 WAL_FLUSH 对象，以及可可靠解码的 Checkpoint Marker。
- 已确认 Flush 位置，以及单独定义的连续验证 `last_good_flush`。
- 不输出业务 Payload：普通 Insert/Update/Catalog Payload 保持 `not_decoded`。

WAL v1、加密 WAL v3 和未知 WAL 版本返回 `unsupported_wal_version`，不会强行按 v2 解析。

加密数据库文件会通过 Main Header 识别。其加密 Database Header 和 Block 会标记为 `unsupported`，不会按明文计算或报告 Checksum。

## 非目标

这些阶段不支持 DuckDB v1.x 主文件、WAL v1/v3 帧、加密内容解码、大端文件、非默认 block-header 大小、DuckLake、Parquet、MotherDuck、Catalog 反序列化、free-list/meta-block 内容解码、Row Group、列压缩、业务数据输出、行级恢复、WAL Replay、恢复计划、自动修复、checkpoint、截断或生成替代数据库。

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

## 在不 Replay 的情况下检查 WAL

```sh
duckdb-forensics wal <WAL_PATH> [--format text|json] [--output PATH]
```

示例：

```sh
duckdb-forensics wal evidence.duckdb.wal
duckdb-forensics wal evidence.duckdb.wal --format json --output wal-report.json
```

该命令只读取指定 WAL，不会通过 DuckDB 打开原始数据库、Replay Entry、写入 WAL 或截断 WAL。WAL JSON 契约见 [`schemas/wal-report.schema.json`](schemas/wal-report.schema.json)。

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

WAL JSON 独立使用 schema version `1`，报告版本/加密状态、版本头长度、文件大小和 SHA-256、逐 Entry 偏移和长度、Checksum 状态和类型、汇总数量、首个无法解析和 Checksum 失败位置、扫描覆盖率、unknowns、尾部零证据、已确认 Flush、`last_good_flush`、该边界后的数据，以及可选 Checkpoint Marker。`actual_length` 表示实际存在且不超过 `declared_length` 的 Payload 字节数。

`last_good_flush` 要求从文件开头到精确 WAL_FLUSH 的 Entry 连续完整、Checksum 有效且类型封装可信。它不一定是应用已经收到的最后成功提交，也不是安全恢复点。`confirmed_flushes` 还可能包含早期错误之后物理上有效的 Flush 对象，但它们不能恢复连续性。Checksum mismatch 本身不能证明 torn write，尾部零填充也只能作为证据。

稳定主文件 Finding 代码包括 `invalid_magic`、`checksum_mismatch`、`truncated_file`、`unsupported_storage_version`、`unsupported_encryption`、`invalid_block_alloc_size`、`invalid_block_count`、`invalid_metadata_pointer`、`invalid_block_reference`、`geometry_overflow`、`no_valid_database_header` 和 `limit_reached`。

WAL Finding 代码为 `empty_wal`、`unsupported_wal_version`、`invalid_wal_header`、`invalid_entry_length`、`entry_exceeds_remaining_file`、`checksum_mismatch`、`truncated_entry`、`zero_filled_tail`、`unparsed_trailing_data` 和 `resource_limit_reached`。声明长度超过 EOF 时，可以同时具有越界和截断两种分类。

## 只读与输出安全

- `DB_PATH` 和 `WAL_PATH` 始终以只读方式打开。检查器不会调用 DuckDB、创建 WAL、触发 checkpoint、Replay WAL 或修改任一输入。
- 唯一可选的写入操作是通过 `--output` 指定报告文件。
- 如果输出路径解析后与输入文件相同，操作会被拒绝。符号链接解析以及 Unix device/inode 检查也会防止通过现有别名或硬链接覆盖输入；截断输出前还会再次检查已打开文件的身份。
- Remediation 文本仅为建议，绝不会自动执行。
- 损坏、空、随机、截断、不支持或可能触发溢出的输入会产生结构化诊断，而不会导致解析器 Panic。

请始终保留原始证据，并在副本上执行任何单独的数据库操作。

## 资源限制

检查器最多读取三个固定 4096 字节 Header 页，并通过 1 MiB 缓冲区流式计算 SHA-256。它不会将整个数据库载入内存，也不会根据文件提供的长度分配内存。

默认主文件大小预算为 1 TiB。更大的输入会在哈希和 Header 解析前停止，并报告 `limit_reached`；SHA-256 和未检查字段保持 unknown。资源限制不会报告为 corruption。

WAL 默认预算为每文件 1 TiB、最多 1,000,000 个 Entry 候选、每 Entry 声明 Payload 最大 256 MiB。Payload Checksum 和尾部读取使用固定 1 MiB 分块，绝不会根据未检查的 Entry 声明长度分配内存。达到 WAL 预算时报告 `resource_limit_reached` 并保留停止偏移；初始文件预算阻止处理时，SHA-256 为 `null`。

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

DuckDB 会生成随机数据库标识符，因此重新生成的数据库结构等价，但不要求逐字节一致。清单记录每次生成的 fixture 哈希和原始 Header 值。

单独生成确定性的 WAL fixtures：

```sh
python3 scripts/generate_wal_fixtures.py
```

这个只使用 Python 标准库的生成器不会调用 DuckDB 或 Rust 解析器。它生成 `normal.wal`、独立的逐 Entry 期望清单，以及 Issue #19099 历史语料：一个文件在固定 Entry 内位置截断，另一个从相同位置零填充到原始 EOF。该语料不断言当前 DuckDB 仍存在历史 Bug。

运行测试不需要网络或 DuckDB。

## 测试与静态检查

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

主文件测试覆盖官方正常 fixture、空文件、非 DuckDB 文件、随机文件、Main Header 位翻转、任一或两个 Database Header 损坏、截断、非法 block allocation size、巨大 block count、不支持的加密和版本、稳定的 JSON 反序列化、Text 输出、隐藏路径、输出文件，以及直接路径或硬链接覆盖尝试。CLI 测试辅助函数会验证输入 SHA-256 保持不变，并确认没有生成 WAL。

WAL 测试覆盖正常/空/不支持文件、越界和超大长度、Entry 中间和固定帧头截断、Checksum 位翻转、零/非零尾部、随机字节、未知类型、损坏 Flush、Checkpoint 解码、资源限制、JSON Schema/Text/输出文件，以及历史同位置截断/零填充对照。独立清单复核偏移和长度；测试断言所有异常输入无 Panic、输入 SHA-256 不变，并在不存在连续验证 Flush 时严格要求 `last_good_flush=null`。

## Workspace 结构

- `crates/duckdb-format`：固定页读取、标量解析、DuckDB Checksum、checked geometry、WAL v2 帧/封装解析和格式错误。
- `crates/duckdb-report`：Observation/Finding/Inference 模型、主文件和 WAL JSON 类型及 Text 渲染。
- `crates/duckdb-forensics`：主文件和 WAL 检查流程、CLI、流式 SHA-256/Checksum、资源限制和安全报告输出。
- `schemas/wal-report.schema.json`：WAL JSON Schema version 1。
