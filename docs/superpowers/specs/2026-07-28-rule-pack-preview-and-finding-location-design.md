# 规则包条目预览与扫描结果问题定位 — 设计文档

日期：2026-07-28
状态：待评审

## 背景与目标

两个桌面端体验缺口：

1. **规则管理页看不到规则条目**：`RuleManagementView` 只显示包级元数据（ID/版本/哈希/签名状态），用户无法知道内置基线规则包里到底有哪些规则、怎么匹配。
2. **扫描结果无法定位问题**：`ScanResultsView` 选中一条出现位置后只能看“解密值”和“上下文”，没有跳转、打开文件、复制路径等任何能力；且所有检测器把 `TextLocator.Line` 硬编码为 0，行号信息不存在。

目标：

- 规则管理页可预览活动规则包（含内置基线包）的全部规则条目，含检测器匹配参数。
- 扫描结果页可从一条发现方便地定位问题：应用内安全预览（高亮命中位置、显示真实行号）、在资源管理器中定位、外部打开（强制确认）、复制路径/定位信息。

非目标（YAGNI）：

- 不做规则编辑、规则启停切换。
- 不做历史规则包的预览（历史列表当前仅内存回填，为此先做持久化不划算）。
- 不修改检测器填充真实行号（即不做方案 B；行号在预览时按字节偏移现算）。
- 不落地 XLSX 报告导出主链路（`IReportDataReader` 生产实现缺失是既有缺口，不在本范围）。

## 关键现状（已核实）

- 规则条目取数链路现成：`ActiveRulePackRuntimeProvider.GetActiveAsync()`（`src/SecurityReview.Infrastructure/Rules/ActiveRulePackRuntimeProvider.cs`，已带缓存）→ `LoadedRulePack.Policy.Rules`（`RulePackDocument`，含 Categories/Rules/Detectors/Assets/ComplianceRules 五段）。该 provider 已在 `CompositionRoot.cs` 注册为具体类。
- 规则条目（`RuleDefinition`）无名称/描述，需 join `CategoryDefinition`（中文 Name/Description）与 `DetectorDefinition`（匹配模式在 `Parameters` 字典）。
- `RuleManagementViewModel` 由 `CompositionRoot.GetRuleManagementViewModel()` 工厂构造，测试用内存 stub（`tests/SecurityReview.UnitTests/Desktop/RuleManagementViewModelTests.cs`）。
- 定位数据链路完整：`CanonicalLocator`（含 ByteStart/ByteLength）、`VirtualPath`、`RawContext` 经 AES-256-GCM 完整存 SQLite，IPC 不丢数据。行号恒为 0 是唯一数据缺口。
- 已有两套未接线的半成品：
  - `FindingDetailView(Model)`：含 `CopyFullValue`/`CopyLocator`/`LocateInExplorer`/`OpenExternally` 命令，但把相对虚拟路径直接 `Path.GetFullPath`（基于 CWD，必然解析错误），且使用无 scanId 的慢查询重载。
  - `SafePreviewService`：`PreviewText(string fullText, SourceLocator locator)` 静态方法，产出定位点前后 ≤20 行片段 + 高亮范围，行内已带行号；另有表格/二进制/PDF/OCI 预览。有完整单元测试。
- `ExplorerService` 已提供 `LocateInExplorer`（`explorer.exe /select`）、`OpenExternally`（强制经确认委托）、`ResolveOuterPath`（嵌套 `!` 路径回退外层容器）。已在 CompositionRoot 注册，但确认委托被 `path => true` 绕过（安全缺口，需修）。
- 绝对路径还原材料：`FileRecord` 有 `RootIndex + RelativePath`；扫描根绝对路径在 `ScanConfigurationSnapshot.RootPaths`（持久化于 `scan_config_snapshots` 表）。`ScanQueryService` 目前没有暴露此投影。

## 功能 1：规则包条目预览

### 架构与数据流

```
RuleManagementViewModel.RefreshAsync()
  → IRulePackStore.ActivePointer（现有，包级元数据）
  → ActiveRulePackRuntimeProvider.GetActiveAsync()（新增注入，带缓存）
      → LoadedRulePack.Policy.Rules（RulePackDocument）
      → 投影为 RuleEntryItem 列表（join Category/Detector/Asset）
```

- 新增 `RuleEntryItem`（VM 层展示模型）：`RuleId`、`CategoryId`、`CategoryName`、`FindingKind`、`Severity`、`Confidence`、`DetectorId`、`DetectorKind`、`DetectorParameters`（格式化为多行 `key = value` 文本）、`AppliesToAssets`（join 资产名，逗号分隔）、`RequiresSemanticReview`、`Enabled`。
- 无活动规则包时列表为空并显示提示（复用现有提示模式）。

### UI

- `RuleManagementView` 在“规则包历史”下方新增“规则条目”区：
  - 顶部：搜索框（按 RuleId/类别名/DetectorId 过滤）+ 类别下拉筛选 + 条目计数。
  - 列表：DataGrid 或 ListBox，列为 规则 ID、类别、严重级别、检测器、启用。
  - 选中条目：下方详情卡（复用 `FindingDetailView` 的 `HasDetail` 触发式显隐模式），只读显示全部字段，含检测器匹配参数原文。
- 活动规则包卡片加“来源”徽章：`内置` / `导入`。判定方式：比较 active 指针 SHA-256 与随包分发的 `Assets/rules/default-rule-pack.zip` 的 SHA-256，相等为内置；读取失败或不等则显示导入。

### 错误处理

- `GetActiveAsync()` 失败（包损坏/验签失败）：规则列表区显示错误提示，不影响包级元数据显示；与现有 `Warnings` 模式一致。
- 内置包哈希计算失败：来源徽章显示“未知”，不阻断预览。

### 测试

- `RuleManagementViewModelTests` 增补：预览列表加载（join 类别名/检测器参数正确）、搜索/类别筛选、无活动包时的提示、内置/导入徽章判定（哈希相等/不等/读取失败）。
- 复用现有内存 stub 模式。可测性方案定为：VM 不直接依赖具体类 `ActiveRulePackRuntimeProvider`，而是依赖新增的薄接口 `IRulePackPreviewProvider`（方法：`GetActiveRulesAsync()` 返回 `RulePackDocument` 或 null），由 Infrastructure 侧的 provider 适配实现并在 CompositionRoot 注册；单元测试用内存 stub。

## 功能 2：扫描结果问题定位（方案 A）

### 架构与数据流

```
ScanResultsView 选中 occurrence
  → ScanResultsViewModel.SelectOccurrenceAsync（现有：解密值+上下文）
  → 新增：绝对路径解析投影
      ScanQueryService.GetOccurrenceFileLocationAsync(scanId, occurrenceId)
        → occurrence → FileRecord(RootIndex, RelativePath)
        → ScanConfigurationSnapshot.RootPaths[RootIndex] + RelativePath
        → ExplorerService.ResolveOuterPath（嵌套 ! 回退外层容器）
  → 新增：应用内安全预览
      读文件全文（有界：超大文件只读命中点前后窗口）→ SafePreviewService.PreviewText
      → 片段 + 高亮 + 真实行号（由片段行号/字节偏移现算）
```

- **行号策略**：不改检测器。文本类定位在预览生成时按字节偏移计算真实行号/列号并显示（如“第 128 行，第 45 列”）。`TextLocator.Line` 仍为 0 的既有数据兼容：预览以 ByteStart 为准。
- **新增查询投影**：`ScanQueryService` 增加带 scanId 的方法，返回 `(absolutePath, virtualPath, locator, fileExists)`；不沿用无 scanId 的全表扫描重载。

### UI（修复并接线 FindingDetailView）

- 将 `FindingDetailView` 挂接为 `ScanResultsView` 右侧“出现位置”选中后的详情区内容（扩展现有区域：保留“解密值/上下文”只读字段，新增预览与按钮），修复 `FindingDetailViewModel`：
  - 路径解析改用新的 `GetOccurrenceFileLocationAsync` 投影，删除基于 CWD 的 `Path.GetFullPath` 逻辑。
  - 改用带 scanId 的查询重载。
- 详情区内容：
  - 现有：解密值、上下文（只读）。
  - 新增：完整路径（脱敏规则与现有一致：界面显示脱敏路径，复制/跳转用真实路径）、定位信息（canonical display + 文本类显示计算行号）。
  - 新增：应用内预览片段（只读 TextBox，命中行高亮；表格/二进制/PDF/OCI 走 SafePreviewService 对应模式）。
  - 新增按钮：`在资源管理器中定位`、`外部打开`、`复制完整路径`、`复制定位信息`。
- `外部打开`：修复 CompositionRoot 的 `path => true` 绕过，改为真正的 `MessageBox` 确认（文案用 `ExplorerService.GetExternalOpenWarning`），每次打开都需重新确认，绝不自动打开。
- 文件已被移动/删除（`File.Exists` 为 false）：禁用定位/打开按钮并提示“文件已不存在”，预览区提示无法读取。

### 错误处理

- 文件读取失败（权限/占用/编码）：预览区显示失败原因，其余按钮不受影响。
- 超大文件：预览按字节偏移只读命中点前后窗口（上限与 `SafePreviewService` 的 64 KiB 一致），不全文加载。
- 嵌套内容（ZIP 条目等）：预览与定位均回退到外层容器文件，UI 标注“位于容器内：<虚拟路径>”。

### 测试

- 单元：
  - `FindingDetailViewModel`：绝对路径解析（RootIndex 映射、嵌套回退）、外部打开必须经确认委托（拒绝时不打开）、文件不存在时按钮禁用。
  - 行号计算：给定文本 + ByteStart，输出正确行/列；CRLF/LF 两种换行。
- 集成：`ScanQueryService.GetOccurrenceFileLocationAsync` 投影（多根目录、嵌套虚拟路径、scanId 隔离）。
- 回归：既有 `SafePreviewServiceTests`、`ScanResultsViewModel` 相关测试不得变红。

## 安全红线自查

- 不触碰沙箱/worker/解析链路；预览只在主进程读用户自己扫描过的文件，纯文本输出，不用 shell/Office/PDF 控件打开。
- 外部打开强制每次确认（修复现有 `path => true` 绕过）。
- 普通日志不含敏感值：新增日志只记路径与定位，不记命中值。
- 界面展示沿用现有路径脱敏约定；真实路径仅用于复制/跳转的用户显式动作。

## 可追溯性与文档

- 实施后运行 `pwsh build/verify-traceability.ps1` 确认不破坏现有 REQ/AC/SRS-F/VT 链路；本次为既有需求的 UX 完善，预计无需新增编号，若检查发现缺口再补。
- 按仓库惯例在 CHANGELOG.md 的 Unreleased/下一版本节记录两项变更（含测试计数更新）。

## 影响面汇总

| 区域 | 文件 | 变更 |
|---|---|---|
| Desktop VM | `RuleManagementViewModel.cs` | 注入 runtime provider，新增规则列表/筛选/详情/来源徽章 |
| Desktop View | `RuleManagementView.xaml` | 新增规则条目区 |
| Desktop VM | `FindingDetailViewModel.cs` | 修复路径解析与慢查询，接 SafePreview，加按钮命令 |
| Desktop View | `ScanResultsView.xaml`、`FindingDetailView.xaml` | 挂接详情区，加预览与按钮 |
| Application | `ScanQueryService.cs` | 新增 `GetOccurrenceFileLocationAsync` 投影 |
| Desktop | `CompositionRoot.cs` | 注入新依赖；修复外部打开确认委托 |
| 测试 | `RuleManagementViewModelTests`、`FindingDetailViewModelTests`（新）、集成测试 | 见各节 |
