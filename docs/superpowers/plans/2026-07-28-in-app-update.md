# 应用内版本更新功能 — 实施计划

日期：2026-07-28
分支建议：`feat/in-app-update`

## 目标

用户无需手动下载安装包：应用内检查新版本 → 下载安装器 → 校验 sha256 → 关闭应用并静默升级安装 → 装完自动重启。

## 已定决策（auto 模式下按仓库约束选定）

| 决策点 | 选择 | 理由 |
|---|---|---|
| 更新执行 | 下载 `setup.exe` + sha256 校验 + `/VERYSILENT /NORESTART` 原地升级 + 重启应用 | Inno 固定 AppId（`installer.iss:15`）+ `CloseApplications=yes` 天然支持；per-user 安装免管理员 |
| 便携版 | 不做 ZIP 原地替换；检测到便携运行时降级为"打开发布页" | 引导器复杂度高、回归面大；安装版是主交付形态 |
| 检查时机 | 状态栏"检查更新"按钮（手动）+ "启动时自动检查"开关（**默认关**） | 零遥测红线：出站网络必须用户显式开启 |
| 产物验证 | 强制 sha256 sidecar 校验（`<hex>  <filename>` 格式）；ECDSA 签名更新清单列为后续跟进 | 当前发布物本就未签名（AllowUnsignedPilot），不引入 CI 密钥管理变更 |
| 版本发现 | GitHub REST `GET /repos/yusiyi0429/Security-review-tool/releases/latest`（流水线恒 `--latest`） | 资产命名稳定：`SecurityReviewTool-<ver>-win-x64-setup.exe` + `.sha256` |

## 架构

```
Desktop (UpdateViewModel / UpdateWindow)
   → Application.Abstractions: IAppUpdateService / IAppSettingsStore
   → Infrastructure.Updates:
       GitHubAppUpdateService  —— 版本发现 + 下载 + sha256 校验（收紧的 HttpClient）
       JsonAppSettingsStore    —— app-settings.json（原子写入，照 JsonLlmConfigurationStore 模式）
   → Desktop.Services: UpdateApplier —— 调起安装器 + 重启辅助 + 应用退出
```

关键既有资产：
- 运行时版本：`Assembly.GetName().Version?.ToString(3)`（先例 `CompositionRoot.cs:700`）
- 临时目录：`AppDataPaths.Temp`（带当前用户独占 ACL，`AppDataPaths.cs:42`）
- 启动挂点：`CompositionRoot.InitializeRuntimeAsync`（`CompositionRoot.cs:665-695`，fire-and-forget + 失败降级模式）
- 状态栏：`MainWindow.xaml:234-235` 已有版本显示，旁边加"检查更新"按钮与"有新版本"徽标
- 诊断：`IDiagnosticSink` + `DiagnosticFieldPolicy`（事件不含敏感值）

## 安全约束（硬）

- 新增出站网络仅两 host：`api.github.com`（版本发现）与 `github.com`/`objects.githubusercontent.com`（资产下载，允许 302 到 CDN）。新建专用 handler：`UseProxy=false`、`UseCookies=false`、`CheckCertificateRevocationList=true`、仅 HTTPS、ConnectTimeout 10s、每请求校验 host 白名单。不复用 `ExactOriginHttpMessageHandler`（它锁定单一内网 LLM origin）。
- 下载上限 500 MB，流式边下边算 sha256；sidecar 解析失败/哈希不匹配 → 删除临时文件并终止，绝不执行。
- 安装器执行前再次 `File.Exists` + 哈希复核；临时文件无论成败用完即删。
- 自动检查默认关；开启状态持久化于 `app-settings.json`（非敏感，不加密）。
- 日志/诊断只含版本号与稳定错误码，不含 URL 参数以外的路径细节之外的敏感值。
- **Desktop 项目无 System.IO 隐式 using**（上次 CI 教训）：所有 Desktop 新文件显式 `using System.IO;`；注意 CA1859/CA1861 等分析器（警告即错误）。

## 任务分解

### Task 1: Application 层抽象 + 版本比较
- Create `src/SecurityReview.Application/Updates/IAppUpdateService.cs`
  - `Task<AppUpdateCheckResult> CheckForUpdateAsync(CancellationToken)`
  - `Task<AppDownloadResult> DownloadInstallerAsync(AppUpdateCheckResult, IProgress<int>?, CancellationToken)`
  - `AppUpdateCheckResult`：`CurrentVersion/LatestVersion/UpdateAvailable/InstallerUrl/Sha256Url/ReleasePageUrl/IsPortableInstall`
  - `AppDownloadResult`：`InstallerPath/VerifiedSha256`
- Create `src/SecurityReview.Application/Updates/IAppSettingsStore.cs`：`Load()`/`Save(AppSettings)`，`AppSettings` 含 `AutoCheckUpdatesOnStartup`（默认 false）
- Create `src/SecurityReview.Application/Updates/UpdateVersionComparer.cs`：纯函数，tag（`v1.2.3`）→ `System.Version` 三段比较；预发布 tag（含 `-`）跳过
- Test: `tests/SecurityReview.UnitTests/Updates/UpdateVersionComparerTests.cs`（相等/较新/较旧/v 前缀/预发布/非法 tag）

### Task 2: JsonAppSettingsStore
- Create `src/SecurityReview.Infrastructure/Updates/JsonAppSettingsStore.cs`：`AppDataPaths.Config` 下 `app-settings.json`，schema version + 原子写入（tmp + `File.Move(overwrite:true)`），损坏文件回退默认值
- Test: `tests/SecurityReview.UnitTests/Updates/JsonAppSettingsStoreTests.cs`（往返/默认/损坏回退）

### Task 3: GitHubAppUpdateService（检查 + 下载 + 校验）
- Create `src/SecurityReview.Infrastructure/Updates/GitHubAppUpdateService.cs`
  - `CheckForUpdateAsync`：GET releases/latest（UA `SecurityReviewTool/<ver>`，Accept `application/vnd.github+json`）；解析 `tag_name` + `assets[].browser_download_url`；选出 `-setup.exe` 与 `-setup.exe.sha256`；`IsPortableInstall` = 当前 exe 不在 `{localappdata}\Programs\SecurityReviewTool` 下
  - `DownloadInstallerAsync`：流式下载到 `AppDataPaths.Temp\update-<ver>-<guid>.exe`，同步算 SHA-256；再 GET sidecar 解析期望哈希；不匹配/异常 → 删文件抛 `UpdateVerificationException`
  - host 白名单校验每请求执行
- Test: `tests/SecurityReview.UnitTests/Updates/GitHubAppUpdateServiceTests.cs` — 用内存 `HttpMessageHandler` fake：latest 响应解析、资产选择、sidecar 两种空白格式、哈希不匹配删除文件、非白名单 host 拒绝、500 MB 上限

### Task 4: Desktop — UpdateViewModel + UpdateWindow
- Create `src/SecurityReview.Desktop/ViewModels/UpdateViewModel.cs`：状态机（空闲/检查中/无更新/有更新/下载中（百分比）/待安装/失败）；命令：检查、下载并安装、取消、打开发布页
- Create `src/SecurityReview.Desktop/Views/UpdateWindow.xaml(.cs)`：模态窗，状态文本 + ProgressBar + 按钮；含"启动时自动检查"CheckBox（绑 IAppSettingsStore）
- 全部走 fake 的单元测试：`tests/SecurityReview.UnitTests/Desktop/UpdateViewModelTests.cs`（状态迁移、便携版降级为打开发布页、校验失败提示、取消）

### Task 5: UpdateApplier + 应用退出/重启
- Create `src/SecurityReview.Desktop/Services/UpdateApplier.cs`
  - `ApplyAndRestart(installerPath)`：写入 `cmd /c` 引导串到 Temp（`"<setup> /VERYSILENT /NORESTART && start "" "<exePath>""`），`Process.Start` 分离进程后 `Application.Current.Shutdown()`
  - 失败（文件丢失/二次校验不过）→ 不退出，回报错误
- Test: 引导串构造纯函数测试（路径含空格引号转义）

### Task 6: 状态栏入口 + 启动自动检查 + CompositionRoot 接线
- Modify `MainWindow.xaml`：版本文本旁加"检查更新"按钮与"有新版本 vX"徽标（`HasUpdateAvailable` 可见性）
- Modify `MainWindowViewModel`：`CheckUpdatesCommand`（打开 UpdateWindow）、`UpdateBadge` 属性
- Modify `CompositionRoot`：注册 `IAppSettingsStore`/`IAppUpdateService`/UpdateViewModel 工厂；`InitializeRuntimeAsync` 尾部：开关开启时后台检查 → 仅置徽标（绝不自动下载）
- Test: `MainWindowViewModel` 徽标逻辑单测；既有 `CompositionRootTests` 回归

### Task 7: 可追溯性与运维文档
- `docs/prd/` 新增 REQ-020（应用内更新），`docs/srs/` 新增 SRS-F-020，验收清单 `tests/Acceptance/acceptance-manifest.json` 新增 AC-061+（默认不联网/开关/sha256 校验/失败不执行），VT-036；按 `build/verify-traceability.ps1` 实际检查范围同步（若脚本内硬编码范围需扩到 REQ-020/AC-061/SRS-F-020/VT-036）
- `docs/operations/release-checklist.md`：修订"Zero startup telemetry"条目为"默认零外联；更新检查为默认关闭的用户显式开关"
- `docs/operations/release-process.md`：补一句应用内更新依赖 sha256 sidecar 格式稳定（`<hex>  <filename>`）
- `CHANGELOG.md` 新增 Unreleased 条目；`AGENTS.md` 项目概览补一句更新能力

### Task 8: CI 验证
- 本机（macOS）无法编译，推送后跑 CI：`gh workflow run release-windows.yml -f version=<next>` 之前先确认 `VERSION`/release-notes 策略——本功能合并后不立即发版，CI 验证走普通 push 触发或手动 build；以 Windows 全绿为准（重点吸取上次教训：Desktop 显式 using、CA 分析器、xUnit 断言重载）

## 测试策略

- 全部新逻辑纯函数/可 fake（checker 用内存 HttpMessageHandler，store 用临时目录，VM 用 fake service）
- 网络真实链路不做自动化测试（避免 CI 外联），手动验收清单写明：断网提示、老版本报有更新、当前版本报已最新
- 测试方法 snake_case，xUnit v3

## 风险与备注

- **信任根是 GitHub TLS + 同源 sha256**：能防传输损坏与部分篡改，不能防账号级攻击；ECDSA 签名更新清单作为后续跟进项记录。
- Inno 静默安装若遇文件占用会安排重启后替换（`CloseApplications=yes` 先尝试关我们——我们已主动退出，正常路径无此问题）。
- 引导串用 cmd（Windows 11 inbox），不依赖 pwsh。
- 历史教训：发布流水线是唯一真实编译环境，前两次失败都是分析器/using 问题——每个任务的代码写完后对照 `.editorconfig` 与相邻文件复查。
