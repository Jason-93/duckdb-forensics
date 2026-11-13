# duckdb-forensics

[English](README.md) | **简体中文**

`duckdb-forensics` 用于离线检查 DuckDB 数据库和 WAL 文件，适合分析崩溃或写入中断后的现场。它只读取原始文件，不通过 DuckDB 打开它们，也不执行 WAL 重放、自动修复或数据恢复。

目前可检查 DuckDB v2.0.0 的文件头、Block 布局与校验和、Meta Block 链，以及未加密 WAL v2 的帧结构。报告提供文本和 JSON 两种格式，诊断可追溯到具体文件偏移，并区分直接观察、推断和无法确认的部分。

解析器使用 Rust 编写，不依赖 `duckdb-rs`、DuckDB C++ 或 `unsafe` 代码。

## 支持范围与验证状态

| 能力 | 状态 | 验证方式与边界 |
|---|---|---|
| Main Header、Database Header、文件长度与 Block 布局 | 支持 DuckDB v2.0.0 / storage compatibility 69 | 官方 fixture、公开故障样本、proptest、校验和测试 |
| 明文 Block 校验和、`meta_block` / `free_list` 链 | 支持默认 8 字节 Block Header | 全量与按需扫描、短读、循环、越界、稀疏文件和资源限制测试 |
| 未加密 WAL v2 的帧、Flush、Checkpoint 外层结构 | 支持 | 独立 manifest、随机字节和极端长度测试、精确 JSON 往返 |
| `recover-plan` 恢复建议 | **实验性** | 只生成建议数据，不执行，不承诺无损恢复 |
| 官方 DuckDB 对照检查（Oracle） | **实验性** | 模拟进程测试为必选项；真实引擎测试需显式提供 `DUCKDB_V2_0_0` |
| 其他 DuckDB 版本、加密内容、大端或其他 Block Header 布局 | 不支持 | 报告 `unsupported` 或 `unknown`，不按已知布局猜测 |

CI 配置会在 Linux、macOS 和 Windows 上构建并运行测试。某个平台的本机结果不能替代其余平台的 CI 结果。

### 明确不支持的功能

本工具不解析 DuckDB v1.x 主文件、WAL v1/v3、加密内容、Catalog、free-list/meta-block 业务内容、Row Group 或列压缩，也不输出表数据、执行行级恢复、重放 WAL、触发 checkpoint、截断文件或生成替代数据库。DuckLake、Parquet 和 MotherDuck 同样不在支持范围内。

**检查通过只表示已覆盖的项目未发现问题，不代表数据库一定健康，也不代表 DuckDB 一定能打开它。** 格式依据和未覆盖范围见 [FORMAT_NOTES.md](FORMAT_NOTES.md)。

## 构建

需要稳定版 Rust 和 Cargo：

```sh
cargo build --workspace
```

可执行文件位于 `target/debug/duckdb-forensics`。

## 命令用法

### 检查数据库文件头

```sh
duckdb-forensics inspect <DB_PATH> [--format text|json] [--output PATH] [--hide-path]
```

```sh
# 在终端查看文本报告
duckdb-forensics inspect evidence.duckdb

# 输出 JSON，但不记录规范化后的输入路径
duckdb-forensics inspect evidence.duckdb --format json --hide-path

# 将文本报告写入另一个文件
duckdb-forensics inspect evidence.duckdb --output inspection.txt
```

JSON 字段约束见 [`schemas/inspection-report.schema.json`](schemas/inspection-report.schema.json)。

### 检查 WAL，不重放 Entry

```sh
duckdb-forensics wal <WAL_PATH> [--format text|json] [--output PATH]
```

```sh
duckdb-forensics wal evidence.duckdb.wal
duckdb-forensics wal evidence.duckdb.wal --format json --output wal-report.json
```

该命令只读取指定 WAL，不会写入或截断它，也不会打开对应的数据库。支持 WAL v2 的版本对象、`length + checksum + Payload` 帧、WALType 外层结构、精确的 WAL_FLUSH 和 Checkpoint Marker。普通 Insert、Update、Catalog 等业务 Payload 保持 `not_decoded`。

WAL v1、加密 WAL v3 和未知版本返回 `unsupported_wal_version`，不会强行套用 v2 解析规则。JSON 字段约束见 [`schemas/wal-report.schema.json`](schemas/wal-report.schema.json)。

### 校验主文件和 Meta Block 链

```sh
duckdb-forensics verify <DB_PATH> [--blocks] [--format text|json] [--duckdb PATH]
```

默认检查文件头、所选 Database Header 描述的文件布局，以及它引用的 `meta_block` 和 `free_list` 链。链访问到的 Block 也会校验 checksum。加上 `--blocks` 后，还会逐个校验文件中的所有完整物理 Block。

单个 Block 损坏不会中止其他独立检查。`block_count` 之后的完整 Block 单独列出，因为 DuckDB 可能把它们视为隐式 free list；未被访问的 Block 不会被判为健康或空闲。每条链独立检测循环，跨链共享节点不直接视为损坏。

`complete` 只表示本次检查已完成，不是数据库健康证明。JSON 字段约束见 [`schemas/verify-report.schema.json`](schemas/verify-report.schema.json)。

### 生成恢复建议

```sh
duckdb-forensics recover-plan <EVIDENCE_DIR> [--format text|json] [--duckdb PATH]
```

命令先递归清点并哈希目录中的普通文件，再分析顶层唯一的 `.duckdb` 及其同名 `.wal`，最后重新核对文件集合和哈希。缺少数据库、存在多个候选数据库、清单不完整或文件在分析期间发生变化时，都不会给出恢复动作。

如果连续可信前缀中的 `last_good_flush` 位于 EOF 之前，报告可能包含 `candidate_wal_truncation` 建议，记录目标偏移、WAL 哈希、Flush 依据和可能丢失的区间 `[target_offset, wal_file_size)`。该区间可能含有完整但尚未 Flush 的 Entry，因此无法据此确定事务或行级损失。任何人工操作都必须在副本上进行，并重新校验结果。

工具本身不会执行截断、删除、改名或覆盖。JSON 字段约束见 [`schemas/recovery-plan.schema.json`](schemas/recovery-plan.schema.json)。

## 官方 DuckDB 对照检查（实验性）

`verify` 和 `recover-plan` 都接受 `--duckdb PATH`，但只使用用户明确提供的官方 DuckDB v2.0.0 可执行文件，不会自动搜索或下载。

执行流程如下：

1. 在 `:memory:` 中运行 `SELECT version()`，确认版本严格为 v2.0.0。
2. 将数据库及关联 WAL 复制到临时工作目录。
3. 通过初始化配置禁用 known-extension 的自动安装和加载。
4. 仅对副本执行 `ATTACH ... (READ_ONLY)` 和最小只读查询。原始文件路径不会传给 DuckDB。

每次调用记录参数、退出状态、stdout/stderr、超时和截断状态。每个输出流最多保留 64 KiB；非法 UTF-8 会记录有效性标志和原始 hex。默认超时为 30 秒，超时进程会被终止并回收。

对照结果分为 `agreement`、`disagreement` 和 `not_comparable`。DuckDB 能打开副本不代表所有 Block 都健康，也不能推翻已发现的 checksum 问题。临时目录和外部进程输出可能随运行变化，做 JSON 逐字节比较时需要考虑这一点。

## 报告格式与诊断分类

四类报告都使用 schema version `1`。当前版本始终输出新增字段；读取旧报告时，这些新增字段可以缺省，`status` 等核心字段仍然必填。

- `input`：输入路径及其编码、文件大小、SHA-256。无法取得哈希时使用 `null`。
- `observations`：直接观察到的值，包含 `name`、`structure_path` 和可选的 `file_offset`。
- `findings`：问题代码、分类、严重程度、位置、证据、处理建议和置信度。
- `inferences`：与直接观察分开的推断，例如可能有效的 Header、可能过期的 Header 或可能的撕裂写入。
- `checks_passed`、`checks_failed`、`checks_skipped`：各项检查的结果。
- `coverage`：已检查和未检查的范围。
- `unknowns`：受证据、格式支持或资源预算限制而无法确认的内容。

`findings[].category` 的含义如下：

| 分类 | 含义 |
|---|---|
| `corruption` | 发现明确的结构或完整性违例；不代表已经确定物理原因 |
| `unsupported` | 文件使用的版本或功能不在支持范围内 |
| `limit` | 达到资源或报告保留上限；剩余范围未检查，不能据此判断损坏 |
| `unknown` | 当前证据不足，或结果无法与现有检查直接对应 |
| `informational` | 空 WAL、额外 Block、零填充尾部等观察信息 |

I/O、JSON 序列化和输出安全错误属于运行错误，退出码为 2。分析完成时退出码为 0，即使报告中包含 corruption 或 unsupported。

### 文本、路径与数字

- 文件头中的非法 UTF-8 不会被替换后冒充正常文本：文本字段为 `null`，并保留原始 hex 和 UTF-8 有效性标志。
- 非 Unicode 路径使用明确、可逆的编码，不做静默替换。
- JSON 整数覆盖完整 `u64` 范围。读取方必须使用 64 位整数；JavaScript 默认 Number 在 2^53 以上会丢精度。
- 百分比使用精确 JSON 浮点往返测试，避免序列化后再读取时出现最低位差异。
- `--hide-path` 只隐藏 `input.path`，不影响文件大小、哈希、偏移或诊断。

### WAL 特有字段

`actual_length` 是文件中实际存在、且不超过 `declared_length` 的 Payload 字节数。`last_good_flush` 只接受从版本对象开始、连续完整且 checksum 和类型检查均通过的前缀，并要求前缀以精确的 WAL_FLUSH 结束。它不一定是应用已确认的最后提交，也不自动构成安全截断点。

早期 Entry 出错后，仍可能观察到后续物理上有效的 Flush，但这些 Flush 不会恢复前缀连续性。checksum 不匹配不能单独证明撕裂写入，零填充尾部也只是现场证据。

## 只读与输出安全

- 所有输入都以只读方式打开；设备、FIFO、目录等非普通输入会被拒绝。
- 未指定 `--duckdb` 时，不调用 DuckDB，不创建 WAL，不触发 checkpoint，也不修改输入。
- `inspect` 和 `wal` 只能通过 `--output` 写报告；`verify` 和 `recover-plan` 只写 stdout。
- 输出路径指向输入本身、其符号链接或硬链接时会被拒绝。实现同时检查已打开文件的身份，覆盖 Unix 和 Windows；截断输出前还会再检查一次。
- Oracle 的写入限制在临时副本目录。`recover-plan` 最后会重新核对原文件集合和哈希。
- 报告中的修复建议只是文本，工具不会执行。

### 威胁模型与免责声明

文件字节、声明长度、指针、目录深度和文本编码都按不可信输入处理。资源预算用于限制意外资源消耗，但不是 wall-clock 或内存沙箱；预算内的稀疏文件仍需线性 I/O 才能计算哈希。

文件在分析期间被外部进程修改时，工具只能尽力发现，不能抵御恶意本地进程。用户提供的 Oracle 可执行文件必须可信；副本隔离不等于原生代码沙箱。

任何报告都不保证数据库健康、提交持久性、完整损坏检测、可恢复性或无损恢复。请保留原始文件，并始终在副本上进行后续数据库操作。

## 资源限制

| 项目 | 默认限制与行为 |
|---|---|
| 主文件大小 | 1 TiB；超限在哈希和解析前停止，SHA-256 保持 `null` |
| Header 读取 | 最多三个固定 4096 字节页面 |
| 哈希与 WAL 分块读取 | 固定 1 MiB 缓冲区，不按声明长度分配内存 |
| WAL Entry 候选数 | 1,000,000 |
| 单个 WAL Payload | 256 MiB |
| WAL 报告保留量 | Entry 和已确认 Flush 各 10,000；Finding 和 Unknown 各 1,000 |
| Meta Block 链 | 每条链最多 1,000,000 个节点，使用独立 visited 集 |
| Block 缓冲区与异常 | 16–256 KiB 缓冲区；最多保留 1,000 条异常 |
| Recovery 清单 | 最多 100,000 个目录项、64 层目录、1 TiB 总哈希字节，迭代遍历并在超限时停止 |
| Oracle | 默认 30 秒超时，每个输出流最多保留 64 KiB |

WAL 的扫描总数、报告保留数、省略数和 `report_limits` 分开记录。未保留的 Entry 不会被当成不存在或健康。达到资源限制会产生 `limit` 诊断，并保留停止偏移和未覆盖范围，不会被归为 corruption。

## 测试、故障样本与 CI

常规检查命令：

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

测试不需要网络或 DuckDB；公开故障样本的集成测试需要 Python 3。模拟 Oracle 测试覆盖失败、超时、输出限制、非法 UTF-8 和副本隔离。设置 `DUCKDB_V2_0_0=/path/to/duckdb` 后，才会额外运行真实 v2.0.0 引擎测试。

### 属性测试与最小复现

proptest 覆盖任意字节、短输入、极端长度和偏移、Meta Block 损坏、JSON 往返以及输入只读性。测试不仅要求“不 Panic”，还检查实际偏移不越过 EOF、计数一致、百分比有限、Flush 不得伪造等不变量。

单独重跑一个属性：

```sh
cargo test -p duckdb-forensics --test parser_properties extreme_wal_lengths_never_panic -- --exact
```

失败时保留自动缩小的输入和 `*.proptest-regressions` 文件。诊断后应加入确定性回归或公开故障样本，不得删除、忽略或放宽无法解释的断言。

### 公开故障样本

```sh
python3 scripts/generate_fault_corpus.py --output target/fault-corpus

# 可选：额外生成 2 TiB 稀疏资源限制案例
python3 scripts/generate_fault_corpus.py --output target/fault-corpus-sparse --include-sparse
```

`corpus/manifest.json` 记录独立计算的源/输出哈希、字节 patch、预期分类和偏移。默认生成 15 个小型案例；稀疏案例只在显式指定 `--include-sparse` 时生成。输出目录与原始文件分离，不会覆盖证据。

正常 fixture 和 WAL 样本可分别重建：

```sh
python3 scripts/generate_fixture.py
python3 scripts/generate_wal_fixtures.py
```

已有官方 v2.0.0 可执行文件时，可运行 `python3 scripts/generate_fixture.py --duckdb /path/to/duckdb-v2.0.0`。数据库 fixture 包含随机标识符，因此重建后结构等价，但不要求逐字节一致；WAL 生成器只使用 Python 标准库，输出是确定性的。

### 持续集成

CI 在 Linux 上执行格式检查、clippy、全部测试、Corpus 可重复性检查和构建，并在 Linux、macOS、Windows 矩阵上分别构建和测试。真实 DuckDB 下载不是 CI 的必需步骤。

## Workspace 结构

- `crates/duckdb-format`：固定页与标量解析、DuckDB checksum、checked Block/Meta 布局计算、WAL v2 帧和外层结构。
- `crates/duckdb-report`：报告类型、诊断分类、JSON 序列化和文本渲染。
- `crates/duckdb-forensics`：只读分析流程、恢复建议、Oracle 隔离执行、CLI、流式读取和资源限制。
- `schemas/`：`inspect`、WAL、Verify、Recovery 四份 JSON Schema，以及共享定义 `report-common.schema.json`。
- `corpus/`：公开故障样本的独立 patch 与预期结果。
