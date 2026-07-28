# AGENTS.md

本文档面向 AI 编码代理，描述本仓库的架构、构建、测试与开发约定。阅读者无需任何项目背景知识。

## 项目概览

**SecurityReviewTool（敏感信息资产内容审查工具）**：一个 Windows 原生桌面工具，在发布前对资产目录做静态扫描，定位敏感信息（网络地址/凭据/私钥/受限实体/占位符/许可/合规/语义共 8 类基线），记录所有覆盖缺口，可选调用用户配置的 OpenAI 兼容 LLM 复核语义候选，并导出固定六 Sheet 的 XLSX 报告。

- 技术栈：**.NET 10 LTS（SDK 10.0.302，`global.json` 固定且禁用 roll-forward）+ C# 14 + WPF**，RID 固定 `win-x64`。
- 运行时目标：Windows 11 x64（或受支持的 Windows 10 Enterprise/IoT LTSC x64），标准用户权限，无需安装 .NET/Docker/Python/Office。
- 交付物：自包含便携 ZIP + Inno Setup 单文件安装器（按当前用户安装，免管理员）。
- 架构（ADR-0001）：**模块化单体 + 沙箱化解析工作进程**。所有不可信格式解析在独立的 `SecurityReview.Worker.exe` 中运行，worker 处于**无网络 capability 的 AppContainer**，受 Job Object 限制，主进程通过 `DuplicateHandle` 授予单文件只读句柄，经带 ACL 的命名管道（IPC）通信。沙箱无法建立时 **fail closed，禁止降级**到普通进程解析。
- 敏感历史存储：SQLite + AES-256-GCM 字段级加密，数据密钥由 DPAPI CurrentUser 保护。普通日志不得包含敏感值。
- 应用内更新（REQ-020）：默认关闭的用户显式开关（持久化于 app-settings.json），开启后主进程访问 GitHub Releases 检查新版本；安装器下载经 SHA-256 校验（sidecar 格式 `<hex>  <filename>`），校验失败不执行；安装版 Inno 静默升级并重启，便携版降级打开发布页。

## 仓库布局

```
src/
  SecurityReview.Domain/            领域模型（零外部依赖，无 Infrastructure/UI 引用）
  SecurityReview.Application/       用例与端口（Abstractions/Scans/Findings/Rules/Llm/Reporting/…）
  SecurityReview.ParserContracts/   主进程与 worker 的 IPC 协议契约
  SecurityReview.Parsers/           格式解析器（Text/Structured/OpenXml/Pdf/Jvm/Binary/Oci/Models/Archives）
  SecurityReview.RulePack/          规则包：Detection/Normalization/Packaging/Policy/Schema/Signing/Validation
  SecurityReview.Infrastructure/    Windows/加密/持久化(SQLite)/LLM/Reporting/Manifest 等适配器
  SecurityReview.Worker/            AppContainer 解析进程（WorkerHost、ParserRegistry、Probe）
  SecurityReview.Desktop/           WPF 桌面（MVVM：Views/ViewModels/Services/CompositionRoot）
tools/
  SecurityReview.RulePackBuilder/   规则包构建/验证 CLI（build、verify 等子命令）
  SecurityReview.CorpusTool/        语料验证 CLI（scan-smoke、verify-parser-corpus、verify-rule-corpus、verify-acceptance）
tests/                              见下文“测试策略”
rules/
  baseline/                         基线规则 JSON（assets/categories/compliance/detectors/entities/licenses/placeholders/rules）
  schemas/                          规则与清单 JSON Schema（*-v1.schema.json）
  templates/                        规则 Excel 模板
build/                              PowerShell 构建/测试/打包/验证脚本 + installer.iss（Inno Setup）
docs/
  prd/ srs/                         PRD、SRS（需求基线，含 REQ-xxx / AC-xxx / SRS-F-xxx / VT-xxx 编号）
  adr/                              架构决策记录（0001 沙箱架构、0002 按用户安装器）
  operations/                       运维文档（发布流程、快速开始、规则导入、XLSX 报告等）
.github/workflows/release-windows.yml   手动触发的 Windows 发布流水线
```

## 构建与测试命令

> 需要 **.NET SDK 10.0.302**（见 `global.json`）与 **PowerShell 7（pwsh）**。完整构建/测试以 Windows 为目标；Windows 安全车道只能在 Windows 上运行。

```powershell
# 还原（锁定模式；所有项目使用 packages.lock.json + 中央包管理）
dotnet restore SecurityReviewTool.sln --locked-mode -r win-x64

# 标准构建（含 dotnet format 校验）
pwsh ./build/build.ps1 -Configuration Release

# 默认测试车道：Unit + Contract + Integration
pwsh ./build/test.ps1
# 指定车道
pwsh ./build/test.ps1 -Lane Unit,Contract,ParserCorpus,Integration
```

其他常用脚本：

- `pwsh build/verify-traceability.ps1` — 需求可追溯性检查（PRD/SRS/验收清单中的 REQ/AC/SRS-F/VT 编号必须齐全且互链），发布门禁之一。
- `pwsh build/package.ps1 -Version <v> -AllowUnsignedPilot` — 生成便携 ZIP（含 release-manifest、SPDX SBOM）。
- `pwsh build/package-installer.ps1 -Version <v> -AllowUnsignedPilot` — 生成安装器（需 Inno Setup 6/7）。
- `pwsh build/verify-package.ps1 -Package <zip>` — 包验证（allowlist、manifest、SBOM、禁止 `.pdb`/状态文件等 10 项检查）。
- `build/windows-lane.sh` — 从 WSL2 侧发布 probe/production worker 并驱动 Windows 安全测试车道。

## 测试策略

测试框架为 **xUnit v3**，测试方法命名约定为 `snake_case`（`.editorconfig` 中对 `tests/**.cs` 关闭了 CA1707）。测试分六个车道（`build/test.ps1` 的 `-Lane` 参数）：

| 车道 | 项目 | 说明 |
|---|---|---|
| Unit | `tests/SecurityReview.UnitTests` | 单元测试，含 `Architecture/ProjectDependencyTests` 架构约束（Domain 不得引用 Infrastructure/Desktop） |
| Contract | `tests/SecurityReview.ContractTests` | 协议/清单/规则包/报告/发布包契约 |
| ParserCorpus | `tests/SecurityReview.ParserCorpusTests` | 基于 `tests/Corpus/` 语料的解析回归（需 `corpus-manifest.json`） |
| Integration | `tests/SecurityReview.IntegrationTests` | 持久化/扫描工作流/LLM/桌面集成 |
| WindowsSecurity | `tests/SecurityReview.WindowsSecurityTests` | 仅 Windows：沙箱、加密、ADS 等；需 `SECURITY_REVIEW_RUN_WINDOWS_SECURITY=1` 及两个 worker 变体 |
| Performance | `tests/SecurityReview.PerformanceTests` | 性能/可靠性，需专用 host（`SECURITY_REVIEW_PERF_HOST=1`） |

发布前验证基线见 `CHANGELOG.md` 每条记录中的计数（如 Unit 802、Contract 300、ParserCorpus 225、Integration 78、WindowsSecurity 119）。修复 bug 时应按现有模式补充回归测试。

## 代码风格约定

- `Directory.Build.props`：`net10.0`、C# 14、`Nullable enable`、`ImplicitUsings enable`、**`TreatWarningsAsErrors=true`**、`AnalysisLevel latest-recommended`、构建期强制执行代码风格、确定性构建、锁定还原。
- `.editorconfig`：UTF-8、LF、4 空格缩进（JSON/YAML/XML/csproj 为 2 空格）；using 排序（System 在前）；文件作用域命名空间；显式可访问性修饰符；Design/Performance/Security 分析器类别为 warning（即构建错误）。
- 提交前 `dotnet format SecurityReviewTool.sln --verify-no-changes` 必须通过（`build.ps1` 已内置）。
- 依赖管理：中央包版本（`Directory.Packages.props`）+ 每个项目的 `packages.lock.json`；新增/升级依赖需锁定还原并运行漏洞扫描。
- 文档语言：PRD/SRS/ADR/CHANGELOG/README 使用中文，`docs/operations/` 多为英文；代码与提交信息遵循仓库现有风格。

## 安全注意事项（核心红线）

- **不得绕过沙箱**：不可信解析只允许在 AppContainer worker 中进行；任何"退回普通进程解析"的降级路径都被明确禁止（ADR-0001）。沙箱建立失败必须 fail closed。
- **worker 零信任**：worker 无网络 capability，不持有 LLM 凭据、规则或数据库访问权，只接收主进程复制的单文件只读句柄。
- **日志脱敏**：敏感值可本地完整展示/导出，但普通日志与诊断数据不得包含敏感值（有专门的 `LlmLogRedaction` 回归测试）。
- **秘密管理**：禁止把签名私钥、凭据提交进仓库或 `.env` 文件；LLM 凭据用 DPAPI 保护。
- **规则包供应链**：规则包需 ECDSA 签名验证；发布包必须通过 allowlist 与 manifest 交叉验证。
- **漏洞门禁**：发布前 `dotnet list package --vulnerable --include-transitive` 中的 Critical/High 必须有书面豁免。
- 完整的发布安全禁令表见 `docs/operations/release-process.md` 的 "Security Prohibitions"。

## 发布流程（摘要）

发布只能走 `.github/workflows/release-windows.yml`（workflow_dispatch），版本号必须与 `VERSION` 文件一致且存在对应的 `.github/release-notes/v<version>.md`。流水线依次执行：测试车道（Unit/Contract/ParserCorpus + 聚焦集成回归）→ 可追溯性验证 → Windows 安全车道 → 打包 → 创建 GitHub Release。**已发布的产物永不覆盖**，有问题就 bump 补丁版本重发。详细步骤（含可复现构建双跑对比、Authenticode 签名、干净 VM 冒烟）见 `docs/operations/release-process.md` 与 `docs/operations/release-checklist.md`。

## 需求可追溯性

本仓库实行严格的编号追溯：PRD 中的 `REQ-xxx`、验收标准 `AC-xxx`、SRS 中的 `SRS-F-xxx`、验证测试 `VT-xxx`，由 `build/verify-traceability.ps1` 强制检查（当前范围为 REQ-001..020、AC-001..064、SRS-F-001..020、VT-001..036），`tests/Acceptance/acceptance-manifest.json` 为验收清单。改动功能时同步维护这些编号与清单。
