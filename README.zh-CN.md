# duckdb-forensics

[English](README.md) | **简体中文**

一个只读、离线的 DuckDB 数据库及 WAL 崩溃现场检查器。它检查 DuckDB v2.0.0 Header、Block 几何结构与 Checksum、Meta Block 链，并在不执行 Replay 的情况下分析未加密 WAL v2 帧。它还能生成仅建议性质的恢复计划，并在临时副本上使用用户显式提供的官方 DuckDB v2.0.0 可执行文件与 Rust 分析进行对照。报告以 Text 或 JSON 输出可追溯到文件偏移的 Observation、Finding、明确区分的 Inference，以及解析覆盖率。

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

`verify` 子命令还支持：

- 以流式方式校验完整明文 Block，并隔离单个 Block 的诊断。
- 截断和越界 Block、recorded count 几何结构，以及非对齐尾部数据。
- 有界的 `meta_block` 和 `free_list` 链遍历，包括指针边界、长度和循环检查。
- 明确的已检查、未检查、不支持及不可用覆盖率；未访问 Block 不会被称为健康，也不会被推断分配状态。

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

这些阶段不支持 DuckDB v1.x 主文件、WAL v1/v3 帧、加密内容解码、大端文件、非默认 block-header 大小、DuckLake、Parquet、MotherDuck、Catalog 反序列化、free-list/meta-block 内容解码、Row Group、列压缩、业务数据输出、行级恢复、WAL Replay、自动修复、checkpoint、截断或生成替代数据库。恢复计划仅为建议，工具不会执行任何候选动作。

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

## 验证主文件

```sh
duckdb-forensics verify <DB_PATH> [--blocks] [--format text|json] [--duckdb PATH]
```

默认验证 Header、所选 Header 的几何结构，以及所选 `meta_block`/`free_list` 链，包括这些链访问的 Block Checksum。`--blocks` 额外流式校验所有完整物理 Block。单个 Block 损坏不会阻止后续独立检查。`block_count` 后的额外 Block 单独报告，因为 DuckDB 可能将其视为隐式 free list；未访问 Block 不会被推断分配状态。重复引用不会自动判为损坏，循环检测按每条链独立进行。

报告区分截断 Block、越界引用、尾部字节、不支持的加密区域和不可用覆盖率。`complete` 状态或 Checksum 有效不代表 DuckDB 一定能打开数据库，也不代表 Catalog/业务内容健康。JSON 契约见 [`schemas/verify-report.schema.json`](schemas/verify-report.schema.json)。

## 生成仅建议性质的恢复计划

```sh
duckdb-forensics recover-plan <EVIDENCE_DIR> [--format text|json] [--duckdb PATH]
```

命令递归清点并哈希所有 regular file，分析唯一且无歧义的顶层 `.duckdb` 及精确同名 `.wal`，随后再次核对原文件集合与哈希。它绝不执行恢复。JSON 始终分为 `observed_facts`、`findings`、`inferences`、`unknowns`、`candidate_actions` 和 `risks`，契约见 [`schemas/recovery-plan.schema.json`](schemas/recovery-plan.schema.json)。

当连续验证的 `last_good_flush` 在 EOF 之前结束时，`candidate_wal_truncation` 建议记录目标偏移、WAL 哈希、Flush 证据，以及可能丢失区间 `[target_offset, wal_file_size)`。该区间可能包含完整但没有后续 Flush 的 Entry，因此事务和行级损失未知。动作必须在副本上执行并全面重新验证。没有边界、边界已在 EOF、分析受资源限制、文件缺失或数据库歧义时均不生成此动作。工具不会截断、删除、改名或覆盖证据，也不会宣称无损恢复。

## 可选官方 DuckDB Oracle

两个新命令均接受 `--duckdb PATH`，仅用于用户显式提供的官方 DuckDB v2.0.0 可执行文件，不会自动发现或下载。工具先在 `:memory:` 中执行 `SELECT version()`，再把数据库及关联 WAL 复制到临时工作目录，通过受控初始化禁用 known-extension 自动安装/加载，之后才对副本执行 `ATTACH ... (READ_ONLY)` 和最小只读查询。原证据路径不会传给 DuckDB。

每次调用记录完整 argv、退出状态、stderr/stdout（每流最多保留 64 KiB 并标记截断）以及默认 30 秒超时。超时进程会被终止并回收。对照结果分为 `agreement`、`disagreement` 或 `not_comparable` 并附原因。Oracle 成功不会推翻 Checksum Finding，也不证明未访问内容健康；无法解释的 Rust/Oracle 差异会报告为 `disagreement`，不会隐藏。

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

Verify JSON 独立使用 schema version `1`，增加所选 Header、数量有界的 Block 异常、Meta 链终止/容量/循环状态、尾部分类和明确的完整性覆盖率。Recovery-plan JSON 同样独立使用 schema version `1`；候选动作只是数据对象，不是可执行指令。

稳定主文件 Finding 代码包括 `invalid_magic`、`checksum_mismatch`、`truncated_file`、`unsupported_storage_version`、`unsupported_encryption`、`invalid_block_alloc_size`、`invalid_block_count`、`invalid_metadata_pointer`、`invalid_block_reference`、`geometry_overflow`、`no_valid_database_header` 和 `limit_reached`。

WAL Finding 代码为 `empty_wal`、`unsupported_wal_version`、`invalid_wal_header`、`invalid_entry_length`、`entry_exceeds_remaining_file`、`checksum_mismatch`、`truncated_entry`、`zero_filled_tail`、`unparsed_trailing_data` 和 `resource_limit_reached`。声明长度超过 EOF 时，可以同时具有越界和截断两种分类。

新增 Verify Finding 包括 `truncated_block`、`block_out_of_bounds`、`trailing_data`、`beyond_header_block_count` 和 `meta_block_cycle`。恢复/Oracle Finding 包括 `evidence_incomplete`、`evidence_changed_during_analysis` 和 `oracle_disagreement`。

## 只读与输出安全

- `DB_PATH`、`WAL_PATH` 和 `EVIDENCE_DIR` 输入始终以只读方式打开。未指定 `--duckdb` 时，工具不会调用 DuckDB、创建 WAL、触发 checkpoint、Replay WAL 或修改任何输入。
- Oracle 的写入仅限于临时副本工作目录；`recover-plan` 分析后会再次哈希原证据。
- 对 `inspect` 和 `wal`，唯一可选写入是通过 `--output` 指定报告文件；`verify` 和 `recover-plan` 只向 stdout 输出报告。
- 如果输出路径解析后与输入文件相同，操作会被拒绝。符号链接解析以及 Unix device/inode 检查也会防止通过现有别名或硬链接覆盖输入；截断输出前还会再次检查已打开文件的身份。
- Remediation 文本仅为建议，绝不会自动执行。
- 损坏、空、随机、截断、不支持或可能触发溢出的输入会产生结构化诊断，而不会导致解析器 Panic。

请始终保留原始证据，并在副本上执行任何单独的数据库操作。

## 资源限制

检查器最多读取三个固定 4096 字节 Header 页，并通过 1 MiB 缓冲区流式计算 SHA-256。它不会将整个数据库载入内存，也不会根据文件提供的长度分配内存。

默认主文件大小预算为 1 TiB。更大的输入会在哈希和 Header 解析前停止，并报告 `limit_reached`；SHA-256 和未检查字段保持 unknown。资源限制不会报告为 corruption。

WAL 默认预算为每文件 1 TiB、最多 1,000,000 个 Entry 候选、每 Entry 声明 Payload 最大 256 MiB。Payload Checksum 和尾部读取使用固定 1 MiB 分块，绝不会根据未检查的 Entry 声明长度分配内存。达到 WAL 预算时报告 `resource_limit_reached` 并保留停止偏移；初始文件预算阻止处理时，SHA-256 为 `null`。

Verify 使用有界的 16–256 KiB Block 缓冲区，每条 Meta 链最多遍历 1,000,000 个节点，最多保留 1,000 条 Block 异常。正常 Block 仅计数，不累计到报告中。Recovery 最多清点 100,000 个 regular file，并以流式方式计算全部哈希。Oracle 默认超时 30 秒，每流最多保留 64 KiB 输出。资源或报告限制会保留省略计数或未知覆盖率，不视为损坏结论。

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

运行测试不需要网络或 DuckDB。只有显式设置 `DUCKDB_V2_0_0=/path/to/duckdb` 时才会额外运行真实 Oracle 测试；模拟 Oracle 测试无需 DuckDB 即可覆盖失败、超时、输出限制和副本隔离。

## 测试与静态检查

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

主文件测试覆盖官方正常 fixture、空文件、非 DuckDB 文件、随机文件、Main Header 位翻转、任一或两个 Database Header 损坏、截断、非法 block allocation size、巨大 block count、不支持的加密和版本、稳定的 JSON 反序列化、Text 输出、隐藏路径、输出文件，以及直接路径或硬链接覆盖尝试。CLI 测试辅助函数会验证输入 SHA-256 保持不变，并确认没有生成 WAL。

WAL 测试覆盖正常/空/不支持文件、越界和超大长度、Entry 中间和固定帧头截断、Checksum 位翻转、零/非零尾部、随机字节、未知类型、损坏 Flush、Checkpoint 解码、资源限制、JSON Schema/Text/输出文件，以及历史同位置截断/零填充对照。独立清单复核偏移和长度；测试断言所有异常输入无 Panic、输入 SHA-256 不变，并在不存在连续验证 Flush 时严格要求 `last_good_flush=null`。

Verify 测试覆盖全量/默认扫描、独立 Block 损坏、截断、额外数据、Meta 循环/边界/Checksum 失败、合法共享 Block、加密和资源限制。Recovery 与 Oracle 测试检查六段报告、候选丢失区间、缺失/歧义证据、版本不符、disagreement、输出截断、超时和只读副本执行。端到端辅助函数比较执行前后所有原证据文件的 SHA-256 和完整文件集合，包括故意修改临时副本的 Oracle。

## Workspace 结构

- `crates/duckdb-format`：固定页读取、标量解析、DuckDB Checksum、checked Block/Meta 几何、WAL v2 帧/封装解析和格式错误。
- `crates/duckdb-report`：Observation/Finding/Inference 模型、主文件、Verify、Recovery、Oracle 和 WAL JSON 类型及 Text 渲染。
- `crates/duckdb-forensics`：只读分析流程、建议性恢复计划、隔离 Oracle 执行、CLI、流式哈希/Checksum 和资源限制。
- `schemas/wal-report.schema.json`、`schemas/verify-report.schema.json` 和 `schemas/recovery-plan.schema.json`：独立的 JSON Schema version 1 契约。
