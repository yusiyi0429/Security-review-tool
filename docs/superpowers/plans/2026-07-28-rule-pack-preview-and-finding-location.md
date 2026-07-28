# 规则包条目预览与扫描结果问题定位 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 规则管理页可预览活动规则包的全部规则条目（搜索/类别筛选/只读详情/内置或导入来源徽章）；扫描结果页的出现位置详情支持应用内安全预览（高亮命中行、按 ByteStart 现算真实行号）、在资源管理器中定位、外部打开（每次强制确认）、复制完整路径与复制定位信息。

**Architecture:** 模块化单体 + WPF MVVM（手工 CompositionRoot 组合，无 DI 容器）。规则条目取数走新增薄端口 `IRulePackPreviewProvider`（Application 层定义，Infrastructure 侧 `RulePackPreviewProvider` 适配既有 `ActiveRulePackRuntimeProvider`）。问题定位走 `ScanQueryService` 新增投影 `GetOccurrenceFileLocationAsync`（occurrence → `FileRecord` → `ScanConfigurationSnapshot.RootPaths[RootIndex] + RelativePath` 还原绝对路径），`FindingDetailViewModel` 修复后挂接为 `ScanResultsViewModel.Detail` 子视图模型，预览复用既有 `SafePreviewService`。

**Tech Stack:** .NET 10（SDK 10.0.302，`global.json` 固定）、C# 14、WPF、xUnit v3、SQLite（Microsoft.Data.Sqlite）+ AES-256-GCM 字段级加密。

**Spec:** `docs/superpowers/specs/2026-07-28-rule-pack-preview-and-finding-location-design.md`（唯一需求来源）。

## Global Constraints

- **执行环境**：实现机是 macOS，**无 dotnet SDK**，且 Desktop/UnitTests/IntegrationTests 目标框架为 `net10.0-windows10.0.19041.0`——所有构建与测试**必须在 Windows 上执行**（.NET SDK 10.0.302 + pwsh 7）。本计划中所有 `dotnet test` / `dotnet format` / `pwsh` 命令均为 Windows 侧命令；在 macOS 上只能写代码，不能验证。跑单个测试类优先用 `dotnet test <project> --filter "FullyQualifiedName~<ClassName>"`，全量车道用 `pwsh ./build/test.ps1 -Lane Unit`。
- **代码风格**：xUnit v3，测试方法 `snake_case`；文件作用域命名空间；显式可访问性修饰符；`TreatWarningsAsErrors=true`（警告即错误，含 Design/Performance/Security 分析器）；C# 4 空格缩进，XAML/XML 2 空格；文件顶部 using 排序（System 在前）；UI 文案一律中文。
- **提交前门禁**：`dotnet format SecurityReviewTool.sln --verify-no-changes` 必须通过；`pwsh build/verify-traceability.ps1` 不得破坏（本变更为 UX 完善，预计无需新增 REQ/AC/SRS-F/VT 编号）。
- **安全红线**：
  - 不触碰沙箱/worker/解析/检测器链路；预览只在主进程读用户自己扫描过的文件，纯文本输出，不用 shell/Office/PDF 控件。
  - 外部打开**每次**必须经真实 `MessageBox` 确认（修复 CompositionRoot 的 `path => true` 绕过），绝不自动打开。
  - 新增日志/错误上报只含稳定错误码与路径，**不含敏感命中值**。
  - 界面显示沿用脱敏约定（绝对路径只显示 `…\<文件名>`），真实路径仅用于复制/跳转的用户显式动作。
- **提交风格**：conventional commits，英文小写前缀（`feat:` / `fix:` / `test:`），参考 `git log`（如 `fix: bind scan progress as one way`）。
- **既有事实修正**（实现时以代码为准，不以 spec 描述为准）：
  - `FindingDetailViewModel` 当前并无 `Path.GetFullPath` 调用；缺陷实质是把**相对虚拟路径**直接传给 `ExplorerService.LocateInExplorer/OpenExternally`（两者内部对不存在的路径直接返回 false，定位/打开必然失败）。
  - `FindingOccurrence` 不携带 `FileId`；`finding_occurrences.file_id` 列虽存在但现有读路径不投影。本计划通过 `VirtualPath` 外层段 + `FileSha256` 匹配 `IFileRepository.GetByScanIdAsync` 结果来定位 `FileRecord`，**不改仓储接口**。
  - `ScanQueryServiceTests` 在 `tests/SecurityReview.UnitTests/Scans/`（单元测试，内存 fake）；真实 SQLite 集成测试样板在 `tests/SecurityReview.IntegrationTests/Persistence/RepositoryRoundTripTests.cs`。
  - `CategoryId` / `AssetTypeId` 是封闭集合（`CategoryId.Parse("SENS-001".."SENS-008")`、`AssetTypeId.Parse("ASSET-001".."ASSET-011")`，私有构造），测试中只能用 `Parse`。
  - `DetectorKind` 枚举在 `SecurityReview.Domain.Rules` 命名空间。

---

## Task 1: `IRulePackPreviewProvider` 薄端口 + Infrastructure 适配 + CompositionRoot 注册

**Files:**
- Create: `src/SecurityReview.Application/Rules/IRulePackPreviewProvider.cs`
- Create: `src/SecurityReview.Infrastructure/Rules/RulePackPreviewProvider.cs`
- Create: `tests/SecurityReview.UnitTests/Rules/RulePackPreviewProviderTests.cs`
- Modify: `src/SecurityReview.Desktop/CompositionRoot.cs`（Step 5 规则存储注册段，第 235-241 行附近）

**Interfaces:**
- Produces（供 Task 2/7 消费）：
  ```csharp
  namespace SecurityReview.Application.Rules;

  public interface IRulePackPreviewProvider
  {
      Task<RulePackDocument?> GetActiveRulesAsync(CancellationToken cancellationToken);
      Task<string?> GetBundledBaselineSha256Async(CancellationToken cancellationToken);
  }
  ```
  `RulePackDocument` 位于 `SecurityReview.RulePack.Schema`（Application 项目已引用 RulePack 项目）。
- Produces（Infrastructure 适配类，CompositionRoot 直接构造）：
  ```csharp
  namespace SecurityReview.Infrastructure.Rules;

  public sealed class RulePackPreviewProvider : IRulePackPreviewProvider
  {
      public RulePackPreviewProvider(ActiveRulePackRuntimeProvider runtimeProvider);
      public RulePackPreviewProvider(ActiveRulePackRuntimeProvider runtimeProvider, string bundledPackPath);
  }
  ```
- Consumes（既有）：`SecurityReview.Infrastructure.Rules.ActiveRulePackRuntimeProvider.GetActiveAsync(CancellationToken)` 返回 `ActiveRulePackRuntime?`（`ActiveRulePackRuntime.Package` 是 `LoadedRulePack`，`LoadedRulePack.Policy` 是 `EffectivePolicy`，`EffectivePolicy.Rules` 是 `RulePackDocument`）；`FileRulePackStore(string basePath)`。

- [ ] **Step 1: 写失败测试**

  创建 `tests/SecurityReview.UnitTests/Rules/RulePackPreviewProviderTests.cs`：

  ```csharp
  using System.Security.Cryptography;
  using SecurityReview.Infrastructure.Rules;

  namespace SecurityReview.UnitTests.Rules;

  public sealed class RulePackPreviewProviderTests : IDisposable
  {
      private readonly string _tempDir =
          Directory.CreateTempSubdirectory("srt-preview-").FullName;

      [Fact]
      public async Task GetActiveRules_returns_null_when_no_pack_is_active()
      {
          var store = new FileRulePackStore(Path.Combine(_tempDir, "rules"));
          var provider = new RulePackPreviewProvider(
              new ActiveRulePackRuntimeProvider(store),
              Path.Combine(_tempDir, "missing.zip"));

          Assert.Null(await provider.GetActiveRulesAsync(CancellationToken.None));
      }

      [Fact]
      public async Task Bundled_hash_matches_file_contents_as_lowercase_hex()
      {
          string bundledPath = Path.Combine(_tempDir, "default-rule-pack.zip");
          byte[] bytes = [1, 2, 3, 4, 5];
          await File.WriteAllBytesAsync(bundledPath, bytes);
          string expected = Convert.ToHexStringLower(SHA256.HashData(bytes));
          var store = new FileRulePackStore(Path.Combine(_tempDir, "rules"));
          var provider = new RulePackPreviewProvider(
              new ActiveRulePackRuntimeProvider(store), bundledPath);

          string? actual = await provider
              .GetBundledBaselineSha256Async(CancellationToken.None);

          Assert.Equal(expected, actual);
      }

      [Fact]
      public async Task Bundled_hash_is_null_when_file_is_missing()
      {
          var store = new FileRulePackStore(Path.Combine(_tempDir, "rules"));
          var provider = new RulePackPreviewProvider(
              new ActiveRulePackRuntimeProvider(store),
              Path.Combine(_tempDir, "missing.zip"));

          Assert.Null(await provider
              .GetBundledBaselineSha256Async(CancellationToken.None));
      }

      public void Dispose()
      {
          try { Directory.Delete(_tempDir, recursive: true); }
          catch (IOException) { }
      }
  }
  ```

- [ ] **Step 2: 在 Windows 上跑测试，确认编译失败**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~RulePackPreviewProviderTests"
  ```

  预期：编译错误 `CS0246: The type or namespace name 'RulePackPreviewProvider' could not be found`。

- [ ] **Step 3: 最小实现 — 端口与适配类**

  创建 `src/SecurityReview.Application/Rules/IRulePackPreviewProvider.cs`：

  ```csharp
  using SecurityReview.RulePack.Schema;

  namespace SecurityReview.Application.Rules;

  /// <summary>
  /// Read-only preview port for the active rule pack document. The desktop
  /// rule-management view lists individual rules through this port; it never
  /// mutates the store and never bypasses signature validation (the
  /// underlying runtime provider revalidates every package on load).
  /// </summary>
  public interface IRulePackPreviewProvider
  {
      /// <summary>
      /// Returns the validated active rule pack document, or <c>null</c>
      /// when no rule pack is active. Throws when the active package is
      /// corrupt or no longer passes validation.
      /// </summary>
      Task<RulePackDocument?> GetActiveRulesAsync(CancellationToken cancellationToken);

      /// <summary>
      /// Returns the lowercase SHA-256 hex of the bundled baseline package,
      /// or <c>null</c> when the bundled file is missing or unreadable.
      /// </summary>
      Task<string?> GetBundledBaselineSha256Async(CancellationToken cancellationToken);
  }
  ```

  创建 `src/SecurityReview.Infrastructure/Rules/RulePackPreviewProvider.cs`：

  ```csharp
  using System.Security.Cryptography;
  using SecurityReview.Application.Rules;
  using SecurityReview.RulePack.Schema;

  namespace SecurityReview.Infrastructure.Rules;

  /// <summary>
  /// Adapts <see cref="ActiveRulePackRuntimeProvider"/> to the read-only
  /// preview port used by the desktop rule-management view.
  /// </summary>
  public sealed class RulePackPreviewProvider : IRulePackPreviewProvider
  {
      private readonly ActiveRulePackRuntimeProvider _runtimeProvider;
      private readonly string _bundledPackPath;

      public RulePackPreviewProvider(ActiveRulePackRuntimeProvider runtimeProvider)
          : this(runtimeProvider, GetDefaultBundledPackPath())
      {
      }

      public RulePackPreviewProvider(
          ActiveRulePackRuntimeProvider runtimeProvider,
          string bundledPackPath)
      {
          _runtimeProvider = runtimeProvider
              ?? throw new ArgumentNullException(nameof(runtimeProvider));
          ArgumentException.ThrowIfNullOrWhiteSpace(bundledPackPath);
          _bundledPackPath = bundledPackPath;
      }

      public async Task<RulePackDocument?> GetActiveRulesAsync(
          CancellationToken cancellationToken)
      {
          ActiveRulePackRuntime? runtime = await _runtimeProvider
              .GetActiveAsync(cancellationToken)
              .ConfigureAwait(false);
          return runtime?.Package.Policy.Rules;
      }

      public async Task<string?> GetBundledBaselineSha256Async(
          CancellationToken cancellationToken)
      {
          try
          {
              if (!File.Exists(_bundledPackPath))
                  return null;
              byte[] bytes = await File
                  .ReadAllBytesAsync(_bundledPackPath, cancellationToken)
                  .ConfigureAwait(false);
              return Convert.ToHexStringLower(SHA256.HashData(bytes));
          }
          catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
          {
              return null;
          }
      }

      private static string GetDefaultBundledPackPath() =>
          Path.Combine(AppContext.BaseDirectory, "Assets", "rules", "default-rule-pack.zip");
  }
  ```

- [ ] **Step 4: CompositionRoot 注册**

  在 `src/SecurityReview.Desktop/CompositionRoot.cs` 第 237 行 `Register<IEffectivePolicyProvider>(ruleRuntimeProvider);` 之后插入：

  ```csharp
          Register<IRulePackPreviewProvider>(
              new RulePackPreviewProvider(ruleRuntimeProvider));
  ```

- [ ] **Step 5: 在 Windows 上跑测试，确认通过**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~RulePackPreviewProviderTests"
  ```

  预期：`Passed! - Failed: 0, Passed: 3`。

- [ ] **Step 6: 提交**

  ```
  git add src/SecurityReview.Application/Rules/IRulePackPreviewProvider.cs src/SecurityReview.Infrastructure/Rules/RulePackPreviewProvider.cs src/SecurityReview.Desktop/CompositionRoot.cs tests/SecurityReview.UnitTests/Rules/RulePackPreviewProviderTests.cs
  git commit -m "feat: add rule pack preview provider port"
  ```

---

## Task 2: `RuleManagementViewModel` 规则条目加载/搜索/筛选/详情/来源徽章（TDD）

**Files:**
- Modify: `src/SecurityReview.Desktop/ViewModels/RuleManagementViewModel.cs`（using 区第 1-11 行；构造函数第 38-58 行；`RefreshAsync` 第 209-249 行；文件尾部追加 `RuleEntryItem`）
- Modify: `tests/SecurityReview.UnitTests/Desktop/RuleManagementViewModelTests.cs`（追加测试与 stub）

**Interfaces:**
- Consumes（Task 1 产物）：`SecurityReview.Application.Rules.IRulePackPreviewProvider`。
- Produces（供 Task 3 XAML 与 Task 7 CompositionRoot 消费）：
  ```csharp
  // 构造函数新签名（新增第 5 个可选参数）
  public RuleManagementViewModel(
      Func<RulePackImportService> importFactory,
      IUiErrorSink errorSink,
      Func<IRulePackStore>? storeFactory = null,
      Func<Task>? configurationChanged = null,
      Func<IRulePackPreviewProvider>? previewProviderFactory = null);

  // 新公开成员
  public ObservableCollection<RuleEntryItem> RuleEntries { get; }
  public ObservableCollection<string> CategoryFilters { get; }
  public string RuleSearchText { get; set; }              // setter 触发过滤
  public string? SelectedCategoryFilter { get; set; }     // setter 触发过滤
  public RuleEntryItem? SelectedRuleEntry { get; set; }
  public bool HasSelectedRuleEntry { get; }
  public bool HasRuleEntries { get; }
  public string RuleEntriesStatus { get; }
  public string ActiveSourceBadge { get; }                // "内置" / "导入" / "未知" / ""
  public bool HasActiveSourceBadge { get; }

  public sealed record RuleEntryItem(
      string RuleId, string CategoryId, string CategoryName, string CategoryDescription,
      FindingKind FindingKind, Severity Severity, DetectionConfidence Confidence,
      string DetectorId, string DetectorKind, string DetectorParameters,
      string AppliesToAssets, bool RequiresSemanticReview, bool Enabled)
  {
      public string KindDisplay { get; }           // 敏感内容 / 资产合规
      public string SeverityDisplay { get; }       // 严重 / 高 / 中 / 低 / 信息
      public string ConfidenceDisplay { get; }     // 高 / 中 / 低
      public string EnabledDisplay { get; }        // 启用 / 停用
      public string SemanticReviewDisplay { get; } // 需要 / 不需要
  }
  ```

- [ ] **Step 1: 写失败测试**

  在 `tests/SecurityReview.UnitTests/Desktop/RuleManagementViewModelTests.cs` 顶部 using 区追加：

  ```csharp
  using SecurityReview.Domain.Assets;
  using SecurityReview.Domain.Findings;
  using SecurityReview.Domain.Rules;
  using SecurityReview.RulePack.Schema;
  ```

  在 `RuleManagementViewModelTests` 类内追加以下测试（既有两个测试与 stub 保持不变）：

  ```csharp
      [Fact]
      public async Task Refresh_loads_rule_entries_with_category_and_detector_join()
      {
          var viewModel = CreateViewModel(BuildDocument(), bundledHash: new string('a', 64));

          await viewModel.RefreshAsync();

          Assert.Equal(2, viewModel.RuleEntries.Count);
          RuleEntryItem first = viewModel.RuleEntries[0];
          Assert.Equal("RULE-NET-001", first.RuleId);
          Assert.Equal("网络地址", first.CategoryName);
          Assert.Equal("DET-IPV4", first.DetectorId);
          Assert.Contains("pattern =", first.DetectorParameters);
          Assert.Contains("源代码", first.AppliesToAssets);
          Assert.Equal("启用", first.EnabledDisplay);
          Assert.True(viewModel.HasRuleEntries);
          Assert.Contains("2", viewModel.RuleEntriesStatus);
      }

      [Fact]
      public async Task Search_text_filters_by_rule_id_category_or_detector()
      {
          var viewModel = CreateViewModel(BuildDocument(), bundledHash: null);
          await viewModel.RefreshAsync();

          viewModel.RuleSearchText = "DET-CRED";

          RuleEntryItem only = Assert.Single(viewModel.RuleEntries);
          Assert.Equal("RULE-CRED-002", only.RuleId);

          viewModel.RuleSearchText = "网络地址";
          only = Assert.Single(viewModel.RuleEntries);
          Assert.Equal("RULE-NET-001", only.RuleId);
      }

      [Fact]
      public async Task Category_filter_narrows_entries()
      {
          var viewModel = CreateViewModel(BuildDocument(), bundledHash: null);
          await viewModel.RefreshAsync();

          Assert.Equal(new[] { "全部", "凭据", "网络地址" }, viewModel.CategoryFilters);

          viewModel.SelectedCategoryFilter = "凭据";

          RuleEntryItem only = Assert.Single(viewModel.RuleEntries);
          Assert.Equal("凭据", only.CategoryName);
      }

      [Fact]
      public async Task Badge_is_builtin_when_hashes_match_and_imported_otherwise()
      {
          string activeHash = new string('a', 64);
          var builtin = CreateViewModel(BuildDocument(), bundledHash: activeHash);
          await builtin.RefreshAsync();
          Assert.Equal("内置", builtin.ActiveSourceBadge);

          var imported = CreateViewModel(BuildDocument(), bundledHash: new string('b', 64));
          await imported.RefreshAsync();
          Assert.Equal("导入", imported.ActiveSourceBadge);
      }

      [Fact]
      public async Task Badge_is_unknown_when_bundled_hash_unavailable()
      {
          var viewModel = CreateViewModel(BuildDocument(), bundledHash: null);

          await viewModel.RefreshAsync();

          Assert.Equal("未知", viewModel.ActiveSourceBadge);
      }

      [Fact]
      public async Task No_active_pack_clears_entries_and_badge()
      {
          var viewModel = new RuleManagementViewModel(
              () => throw new InvalidOperationException(),
              new TestErrorSink(),
              () => new TestRulePackStore(null),
              previewProviderFactory: () => new TestRulePackPreviewProvider(BuildDocument(), null));

          await viewModel.RefreshAsync();

          Assert.Empty(viewModel.RuleEntries);
          Assert.False(viewModel.HasRuleEntries);
          Assert.Equal("", viewModel.ActiveSourceBadge);
      }

      [Fact]
      public async Task Preview_failure_shows_error_status_without_losing_pack_metadata()
      {
          var viewModel = new RuleManagementViewModel(
              () => throw new InvalidOperationException(),
              new TestErrorSink(),
              () => new TestRulePackStore(new ActivePointer
              {
                  RulePackId = "baseline",
                  Version = "1.2.3",
                  Sha256 = new string('a', 64),
              }),
              previewProviderFactory: () => new ThrowingRulePackPreviewProvider());

          await viewModel.RefreshAsync();

          Assert.True(viewModel.HasActivePack);
          Assert.Equal("baseline", viewModel.ActiveRulePackId);
          Assert.Empty(viewModel.RuleEntries);
          Assert.Contains("失败", viewModel.RuleEntriesStatus);
      }
  ```

  在测试文件尾部（`TestErrorSink` 类之后）追加 stub 与构造辅助：

  ```csharp
  file static class RulePreviewTestData
  {
      public static RulePackDocument BuildDocument() => new()
      {
          Categories =
          [
              new CategoryDefinition
              {
                  CategoryId = CategoryId.Parse("SENS-001"),
                  Name = "网络地址",
                  Description = "IP 与 URL",
              },
              new CategoryDefinition
              {
                  CategoryId = CategoryId.Parse("SENS-002"),
                  Name = "凭据",
                  Description = "密钥与口令",
              },
          ],
          Assets =
          [
              new AssetPolicy
              {
                  AssetTypeId = AssetTypeId.Parse("ASSET-001"),
                  Name = "源代码",
              },
          ],
          Rules =
          [
              new RuleDefinition
              {
                  Id = new RuleId("RULE-NET-001"),
                  CategoryId = CategoryId.Parse("SENS-001"),
                  FindingKind = FindingKind.SensitiveContent,
                  Severity = Severity.High,
                  Confidence = DetectionConfidence.High,
                  DetectorId = new DetectorId("DET-IPV4"),
                  DetectorConfigId = "cfg-ipv4",
                  AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
                  RequiresSemanticReview = false,
                  Enabled = true,
              },
              new RuleDefinition
              {
                  Id = new RuleId("RULE-CRED-002"),
                  CategoryId = CategoryId.Parse("SENS-002"),
                  FindingKind = FindingKind.SensitiveContent,
                  Severity = Severity.Critical,
                  Confidence = DetectionConfidence.Medium,
                  DetectorId = new DetectorId("DET-CRED"),
                  DetectorConfigId = "cfg-cred",
                  AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
                  RequiresSemanticReview = true,
                  Enabled = true,
              },
          ],
          Detectors =
          [
              new DetectorDefinition
              {
                  Id = new DetectorId("DET-IPV4"),
                  Kind = DetectorKind.NetworkAddress,
                  ConfigId = "cfg-ipv4",
                  Parameters = new Dictionary<string, string>
                  {
                      ["pattern"] = "\\b\\d{1,3}(\\.\\d{1,3}){3}\\b",
                  },
              },
              new DetectorDefinition
              {
                  Id = new DetectorId("DET-CRED"),
                  Kind = DetectorKind.Dictionary,
                  ConfigId = "cfg-cred",
                  Parameters = new Dictionary<string, string>
                  {
                      ["dictionary"] = "credentials",
                  },
              },
          ],
      };

      public static RuleManagementViewModel CreateViewModel(
          RulePackDocument? document,
          string? bundledHash)
      {
          var active = new ActivePointer
          {
              RulePackId = "baseline",
              Version = "1.2.3",
              Sha256 = new string('a', 64),
          };
          return new RuleManagementViewModel(
              () => throw new InvalidOperationException(),
              new TestErrorSink(),
              () => new TestRulePackStore(active),
              previewProviderFactory: () =>
                  new TestRulePackPreviewProvider(document, bundledHash));
      }
  }

  file sealed class TestRulePackPreviewProvider(
      RulePackDocument? document,
      string? bundledHash) : IRulePackPreviewProvider
  {
      public Task<RulePackDocument?> GetActiveRulesAsync(
          CancellationToken cancellationToken) => Task.FromResult(document);

      public Task<string?> GetBundledBaselineSha256Async(
          CancellationToken cancellationToken) => Task.FromResult(bundledHash);
  }

  file sealed class ThrowingRulePackPreviewProvider : IRulePackPreviewProvider
  {
      public Task<RulePackDocument?> GetActiveRulesAsync(
          CancellationToken cancellationToken) =>
          throw new InvalidDataException("corrupt pack");

      public Task<string?> GetBundledBaselineSha256Async(
          CancellationToken cancellationToken) =>
          Task.FromResult<string?>(null);
  }
  ```

  注意：`CreateViewModel`/`BuildDocument` 在测试方法内通过 `RulePreviewTestData.` 前缀调用（上文测试代码中为简洁省略前缀；实现时统一加上，或把两个方法改为类的私有静态成员）。同时把 `TestErrorSink`/`TestRulePackStore` 由 `private` 改为 `internal`（`file` 类型可见性需要），或把 stub 全部移入 `RuleManagementViewModelTests` 类内作为私有嵌套类——任选其一，保持编译通过即可。

- [ ] **Step 2: 在 Windows 上跑测试，确认编译失败**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~RuleManagementViewModelTests"
  ```

  预期：编译错误 `CS1061: 'RuleManagementViewModel' does not contain a definition for 'RuleEntries'`（及 `ActiveSourceBadge` 等）。

- [ ] **Step 3: 最小实现 — ViewModel 扩展**

  在 `src/SecurityReview.Desktop/ViewModels/RuleManagementViewModel.cs`：

  1. using 区追加：

     ```csharp
     using SecurityReview.Domain.Findings;
     using SecurityReview.Domain.Rules;
     using SecurityReview.RulePack.Schema;
     ```

  2. 字段区（`_isImporting` 之后）追加：

     ```csharp
         private readonly Func<IRulePackPreviewProvider>? _previewProviderFactory;

         private IReadOnlyList<RuleEntryItem> _allRuleEntries = Array.Empty<RuleEntryItem>();
         private ObservableCollection<RuleEntryItem> _ruleEntries = new();
         private ObservableCollection<string> _categoryFilters = new();
         private string _ruleSearchText = "";
         private string? _selectedCategoryFilter;
         private RuleEntryItem? _selectedRuleEntry;
         private bool _hasSelectedRuleEntry;
         private bool _hasRuleEntries;
         private string _ruleEntriesStatus = "";
         private string _activeSourceBadge = "";
     ```

  3. 构造函数替换为：

     ```csharp
         public RuleManagementViewModel(
             Func<RulePackImportService> importFactory,
             IUiErrorSink errorSink,
             Func<IRulePackStore>? storeFactory = null,
             Func<Task>? configurationChanged = null,
             Func<IRulePackPreviewProvider>? previewProviderFactory = null)
         {
             _importFactory = importFactory;
             _storeFactory = storeFactory;
             _errorSink = errorSink;
             _configurationChanged = configurationChanged;
             _previewProviderFactory = previewProviderFactory;

             ImportCommand = new AsyncRelayCommand(_ => ImportRulePackAsync(), errorSink,
                 _ => !IsImporting);
             RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync(), errorSink);

             PropertyChanged += (_, e) =>
             {
                 if (e.PropertyName is nameof(IsImporting))
                     CommandManager.InvalidateRequerySuggested();
             };
         }
     ```

  4. 属性区（`IsImporting` 之后）追加：

     ```csharp
         public ObservableCollection<RuleEntryItem> RuleEntries
         {
             get => _ruleEntries;
             private set => SetProperty(ref _ruleEntries, value);
         }

         public ObservableCollection<string> CategoryFilters
         {
             get => _categoryFilters;
             private set => SetProperty(ref _categoryFilters, value);
         }

         public string RuleSearchText
         {
             get => _ruleSearchText;
             set
             {
                 if (SetProperty(ref _ruleSearchText, value))
                     ApplyRuleFilters();
             }
         }

         public string? SelectedCategoryFilter
         {
             get => _selectedCategoryFilter;
             set
             {
                 if (SetProperty(ref _selectedCategoryFilter, value))
                     ApplyRuleFilters();
             }
         }

         public RuleEntryItem? SelectedRuleEntry
         {
             get => _selectedRuleEntry;
             set
             {
                 if (SetProperty(ref _selectedRuleEntry, value))
                     HasSelectedRuleEntry = value is not null;
             }
         }

         public bool HasSelectedRuleEntry
         {
             get => _hasSelectedRuleEntry;
             private set => SetProperty(ref _hasSelectedRuleEntry, value);
         }

         public bool HasRuleEntries
         {
             get => _hasRuleEntries;
             private set => SetProperty(ref _hasRuleEntries, value);
         }

         public string RuleEntriesStatus
         {
             get => _ruleEntriesStatus;
             private set => SetProperty(ref _ruleEntriesStatus, value);
         }

         public string ActiveSourceBadge
         {
             get => _activeSourceBadge;
             private set
             {
                 if (SetProperty(ref _activeSourceBadge, value))
                     OnPropertyChanged(nameof(HasActiveSourceBadge));
             }
         }

         public bool HasActiveSourceBadge => _activeSourceBadge.Length > 0;
     ```

  5. `RefreshAsync` 的 `active is null` 分支（`HasActivePack = false;` 之后）追加清空逻辑：

     ```csharp
                     HasActivePack = false;
                     ClearRuleEntries("尚未激活规则包，规则条目为空。");
                     ActiveSourceBadge = "";
     ```

     在 `active is null` 分支之后、`Warnings = "";` 之后（成功加载指针的分支末尾，`if (_configurationChanged is not null)` 之前）插入：

     ```csharp
                 ActiveSourceBadge = await ResolveSourceBadgeAsync(active.Sha256);
                 await LoadRuleEntriesAsync();
     ```

  6. `RefreshAsync` 之后追加私有方法：

     ```csharp
         private void ClearRuleEntries(string status)
         {
             _allRuleEntries = Array.Empty<RuleEntryItem>();
             RuleEntries = new ObservableCollection<RuleEntryItem>();
             CategoryFilters = new ObservableCollection<string>();
             SelectedRuleEntry = null;
             HasRuleEntries = false;
             RuleEntriesStatus = status;
         }

         private async Task<string> ResolveSourceBadgeAsync(string activeSha256)
         {
             if (_previewProviderFactory is null)
                 return "未知";
             string? bundledHash = await _previewProviderFactory()
                 .GetBundledBaselineSha256Async(CancellationToken.None);
             if (bundledHash is null)
                 return "未知";
             return string.Equals(activeSha256, bundledHash, StringComparison.OrdinalIgnoreCase)
                 ? "内置"
                 : "导入";
         }

         private async Task LoadRuleEntriesAsync()
         {
             ClearRuleEntries("");

             if (_previewProviderFactory is null)
             {
                 RuleEntriesStatus = "规则条目预览不可用。";
                 return;
             }

             try
             {
                 RulePackDocument? document = await _previewProviderFactory()
                     .GetActiveRulesAsync(CancellationToken.None);
                 if (document is null)
                 {
                     RuleEntriesStatus = "当前没有活动规则包，规则条目为空。";
                     return;
                 }

                 _allRuleEntries = ProjectRuleEntries(document);
                 var filters = new ObservableCollection<string> { "全部" };
                 foreach (string name in _allRuleEntries
                     .Select(e => e.CategoryName)
                     .Distinct(StringComparer.Ordinal)
                     .OrderBy(n => n, StringComparer.Ordinal))
                 {
                     filters.Add(name);
                 }
                 CategoryFilters = filters;
                 _selectedCategoryFilter = "全部";
                 OnPropertyChanged(nameof(SelectedCategoryFilter));
                 ApplyRuleFilters();
             }
             catch (Exception)
             {
                 ClearRuleEntries("规则条目加载失败 — 活动规则包可能已损坏，请重新导入。");
                 _errorSink.Report("rule_entries_load_failed", "加载规则条目失败。");
             }
         }

         private void ApplyRuleFilters()
         {
             IEnumerable<RuleEntryItem> filtered = _allRuleEntries;
             if (!string.IsNullOrWhiteSpace(_ruleSearchText))
             {
                 string term = _ruleSearchText.Trim();
                 filtered = filtered.Where(e =>
                     e.RuleId.Contains(term, StringComparison.OrdinalIgnoreCase)
                     || e.CategoryName.Contains(term, StringComparison.OrdinalIgnoreCase)
                     || e.DetectorId.Contains(term, StringComparison.OrdinalIgnoreCase));
             }
             if (!string.IsNullOrEmpty(_selectedCategoryFilter)
                 && _selectedCategoryFilter != "全部")
             {
                 filtered = filtered.Where(e =>
                     e.CategoryName == _selectedCategoryFilter);
             }

             var items = filtered.ToList();
             RuleEntries = new ObservableCollection<RuleEntryItem>(items);
             HasRuleEntries = items.Count > 0;
             RuleEntriesStatus = items.Count > 0
                 ? $"共 {items.Count} 条规则"
                 : "没有匹配的规则条目。";
         }

         private static IReadOnlyList<RuleEntryItem> ProjectRuleEntries(
             RulePackDocument document)
         {
             var categories = document.Categories.ToDictionary(c => c.CategoryId, c => c);
             var detectorsByConfig = document.Detectors
                 .GroupBy(d => (d.Id, d.ConfigId))
                 .ToDictionary(g => g.Key, g => g.First());
             var assetNames = document.Assets.ToDictionary(a => a.AssetTypeId, a => a.Name);

             var items = new List<RuleEntryItem>(document.Rules.Count);
             foreach (RuleDefinition rule in document.Rules)
             {
                 categories.TryGetValue(rule.CategoryId, out CategoryDefinition? category);
                 if (!detectorsByConfig.TryGetValue(
                         (rule.DetectorId, rule.DetectorConfigId),
                         out DetectorDefinition? detector))
                 {
                     detector = document.Detectors
                         .FirstOrDefault(d => d.Id == rule.DetectorId);
                 }

                 string parameters = detector is null
                     ? ""
                     : string.Join('\n',
                         detector.Parameters.Select(p => $"{p.Key} = {p.Value}"));
                 string appliesTo = rule.AppliesToAssets.Count == 0
                     ? ""
                     : string.Join(", ", rule.AppliesToAssets
                         .OrderBy(id => id.Value, StringComparer.Ordinal)
                         .Select(id => assetNames.TryGetValue(id, out string? name)
                             ? name
                             : id.Value));

                 items.Add(new RuleEntryItem(
                     rule.Id.Value,
                     rule.CategoryId.Value,
                     category?.Name ?? rule.CategoryId.Value,
                     category?.Description ?? "",
                     rule.FindingKind,
                     rule.Severity,
                     rule.Confidence,
                     rule.DetectorId.Value,
                     detector?.Kind.ToString() ?? "",
                     parameters,
                     appliesTo,
                     rule.RequiresSemanticReview,
                     rule.Enabled));
             }
             return items;
         }
     ```

  7. 文件尾部（`RulePackHistoryItem` record 之后）追加：

     ```csharp
     /// <summary>
     /// Display item for a single rule entry of the active rule pack.
     /// Rules carry no name/description, so the category and detector are
     /// joined in for display.
     /// </summary>
     public sealed record RuleEntryItem(
         string RuleId,
         string CategoryId,
         string CategoryName,
         string CategoryDescription,
         FindingKind FindingKind,
         Severity Severity,
         DetectionConfidence Confidence,
         string DetectorId,
         string DetectorKind,
         string DetectorParameters,
         string AppliesToAssets,
         bool RequiresSemanticReview,
         bool Enabled)
     {
         public string KindDisplay => FindingKind switch
         {
             FindingKind.SensitiveContent => "敏感内容",
             FindingKind.AssetCompliance => "资产合规",
             _ => FindingKind.ToString(),
         };

         public string SeverityDisplay => Severity switch
         {
             Severity.Critical => "严重",
             Severity.High => "高",
             Severity.Medium => "中",
             Severity.Low => "低",
             Severity.Info => "信息",
             _ => Severity.ToString(),
         };

         public string ConfidenceDisplay => Confidence switch
         {
             DetectionConfidence.High => "高",
             DetectionConfidence.Medium => "中",
             DetectionConfidence.Low => "低",
             _ => Confidence.ToString(),
         };

         public string EnabledDisplay => Enabled ? "启用" : "停用";
         public string SemanticReviewDisplay => RequiresSemanticReview ? "需要" : "不需要";
     }
     ```

- [ ] **Step 4: 在 Windows 上跑测试，确认通过**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~RuleManagementViewModelTests"
  ```

  预期：`Passed! - Failed: 0, Passed: 9`（既有 2 个 + 新增 7 个）。

- [ ] **Step 5: 提交**

  ```
  git add src/SecurityReview.Desktop/ViewModels/RuleManagementViewModel.cs tests/SecurityReview.UnitTests/Desktop/RuleManagementViewModelTests.cs
  git commit -m "feat: preview active rule pack entries in rule management view model"
  ```

---

## Task 3: `RuleManagementView.xaml` 规则条目区 UI

**Files:**
- Modify: `src/SecurityReview.Desktop/Views/RuleManagementView.xaml`（整文件替换；原 114 行）

**Interfaces:**
- Consumes（Task 2 产物）：`RuleEntries`、`CategoryFilters`、`RuleSearchText`、`SelectedCategoryFilter`、`SelectedRuleEntry`、`HasSelectedRuleEntry`、`HasRuleEntries`、`RuleEntriesStatus`、`ActiveSourceBadge`、`HasActiveSourceBadge`，以及 `RuleEntryItem` 的各 `*Display` 属性。
- 备注：XAML 无法在 Windows 之外编译验证；本任务无独立单元测试，验证靠 Task 8 的全量构建 + `dotnet format`。

- [ ] **Step 1: 整文件替换 RuleManagementView.xaml**

  布局变化：根 Grid 由 3 行改为 4 行（页头 / 卡片行 / 规则条目 `*` / 规则包历史 `Auto` 且内部固定高 220）；活动包卡片在 ACTIVE 徽章旁加“来源”徽章；新增规则条目区（搜索框 + 类别下拉 + 计数 + ListBox + 详情卡）。XAML 缩进 2 空格。

  ```xml
  <UserControl x:Class="SecurityReview.Desktop.Views.RuleManagementView"
               xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
               xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
               xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
               xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
               xmlns:vm="clr-namespace:SecurityReview.Desktop.ViewModels"
               mc:Ignorable="d" d:DataContext="{d:DesignInstance Type=vm:RuleManagementViewModel}"
               Loaded="UserControl_Loaded">
    <UserControl.Resources>
      <BooleanToVisibilityConverter x:Key="BooleanToVisibility" />
    </UserControl.Resources>
    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto" />
        <RowDefinition Height="Auto" />
        <RowDefinition Height="*" />
        <RowDefinition Height="Auto" />
      </Grid.RowDefinitions>

      <Grid Margin="0,0,0,20">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*" />
          <ColumnDefinition Width="Auto" />
        </Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="DETECTION POLICY" Style="{StaticResource PageEyebrowStyle}" />
          <TextBlock Text="规则管理" Style="{StaticResource PageTitleStyle}" Margin="0,3,0,0" />
          <TextBlock Text="管理已验证的检测规则包，并追踪版本、哈希与激活状态。"
                     Style="{StaticResource PageSubtitleStyle}" Margin="0,5,0,0" />
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Bottom">
          <Button Content="刷新" Command="{Binding RefreshCommand}" Margin="0,0,8,0" />
          <Button Content="导入规则包" Command="{Binding ImportCommand}"
                  Style="{StaticResource PrimaryButtonStyle}" MinHeight="34" Padding="14,7" />
        </StackPanel>
      </Grid>

      <Grid Grid.Row="1" Margin="0,0,0,14">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="1.35*" />
          <ColumnDefinition Width="14" />
          <ColumnDefinition Width="1*" />
        </Grid.ColumnDefinitions>
        <Border Style="{StaticResource AccentSignalStyle}">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" />
              <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <StackPanel>
              <TextBlock Text="当前活动规则包" Style="{StaticResource FieldLabelStyle}" />
              <TextBlock Text="{Binding ActiveRulePackId}" FontFamily="Bahnschrift SemiBold"
                         FontSize="20" Foreground="{StaticResource BrushTextPrimary}" />
              <TextBlock Margin="0,7,0,0">
                <Run Text="版本  " Foreground="{StaticResource BrushTextSecondary}" />
                <Run Text="{Binding ActiveVersion, Mode=OneWay}" FontWeight="SemiBold" />
              </TextBlock>
            </StackPanel>
            <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Top">
              <Border Background="{StaticResource BrushSurface1}" CornerRadius="6"
                      Padding="11,8" Margin="0,0,6,0"
                      Visibility="{Binding HasActiveSourceBadge, Converter={StaticResource BooleanToVisibility}}">
                <TextBlock Text="{Binding ActiveSourceBadge, Mode=OneWay}"
                           FontFamily="Bahnschrift SemiBold" FontSize="10"
                           Foreground="{StaticResource BrushAccentHover}" />
              </Border>
              <Border Background="{StaticResource BrushSurface1}" CornerRadius="6"
                      Padding="11,8">
                <TextBlock Text="ACTIVE" FontFamily="Bahnschrift SemiBold" FontSize="10"
                           Foreground="{StaticResource BrushOk}" />
              </Border>
            </StackPanel>
          </Grid>
        </Border>
        <Border Grid.Column="2" Style="{StaticResource CardStyle}">
          <StackPanel>
            <TextBlock Text="完整性哈希" Style="{StaticResource FieldLabelStyle}" />
            <TextBlock Text="{Binding ActiveHash}" Style="{StaticResource MonoTextStyle}"
                       TextWrapping="Wrap" TextTrimming="CharacterEllipsis" />
            <TextBlock Text="{Binding Warnings}" Foreground="{StaticResource BrushError}"
                       TextWrapping="Wrap" FontSize="12" Margin="0,8,0,0" />
          </StackPanel>
        </Border>
      </Grid>

      <Border Grid.Row="2" Style="{StaticResource CardStyle}" Padding="0" Margin="0,0,0,14">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
            <RowDefinition Height="Auto" />
          </Grid.RowDefinitions>
          <Grid Background="{StaticResource BrushSurface0}" MinHeight="52">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto" />
              <ColumnDefinition Width="*" />
              <ColumnDefinition Width="180" />
              <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <TextBlock Text="规则条目" Style="{StaticResource SectionTitleStyle}"
                       VerticalAlignment="Center" Margin="18,0" />
            <TextBox Grid.Column="1" Text="{Binding RuleSearchText, UpdateSourceTrigger=PropertyChanged}"
                     VerticalAlignment="Center" Margin="10,8" MinHeight="28"
                     ToolTip="按规则 ID、类别名或检测器 ID 搜索" />
            <ComboBox Grid.Column="2" ItemsSource="{Binding CategoryFilters}"
                      SelectedItem="{Binding SelectedCategoryFilter}"
                      VerticalAlignment="Center" Margin="0,8,10,8" MinHeight="28" />
            <TextBlock Grid.Column="3" Text="{Binding RuleEntriesStatus, Mode=OneWay}"
                       Style="{StaticResource PageSubtitleStyle}"
                       VerticalAlignment="Center" Margin="18,0" />
          </Grid>
          <ListBox Grid.Row="1" ItemsSource="{Binding RuleEntries}"
                   SelectedItem="{Binding SelectedRuleEntry}"
                   BorderThickness="0" Background="Transparent" Margin="12,9">
            <ListBox.ItemTemplate>
              <DataTemplate>
                <Border BorderBrush="{StaticResource BrushSurface2}" BorderThickness="0,0,0,1" Padding="8,10">
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="*" />
                      <ColumnDefinition Width="120" />
                      <ColumnDefinition Width="60" />
                      <ColumnDefinition Width="140" />
                      <ColumnDefinition Width="50" />
                    </Grid.ColumnDefinitions>
                    <TextBlock Text="{Binding RuleId}" Style="{StaticResource MonoTextStyle}" FontSize="12" />
                    <TextBlock Grid.Column="1" Text="{Binding CategoryName}"
                               Foreground="{StaticResource BrushTextSecondary}" />
                    <TextBlock Grid.Column="2" Text="{Binding SeverityDisplay}" FontWeight="SemiBold"
                               Foreground="{StaticResource BrushError}" />
                    <TextBlock Grid.Column="3" Text="{Binding DetectorId}"
                               Style="{StaticResource MonoTextStyle}" FontSize="11"
                               Foreground="{StaticResource BrushTextSecondary}" />
                    <TextBlock Grid.Column="4" Text="{Binding EnabledDisplay}"
                               Foreground="{StaticResource BrushAccentHover}" />
                  </Grid>
                </Border>
              </DataTemplate>
            </ListBox.ItemTemplate>
          </ListBox>
          <Border Grid.Row="2" Background="{StaticResource BrushSurface0}"
                  BorderBrush="{StaticResource BrushSurface2}" BorderThickness="0,1,0,0"
                  Padding="18,12"
                  Visibility="{Binding HasSelectedRuleEntry, Converter={StaticResource BooleanToVisibility}}">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="14" />
                <ColumnDefinition Width="*" />
              </Grid.ColumnDefinitions>
              <StackPanel DataContext="{Binding SelectedRuleEntry}">
                <TextBlock Text="规则详情" Style="{StaticResource FieldLabelStyle}" />
                <TextBlock FontSize="12" Margin="0,4,0,0">
                  <Run Text="类别  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding CategoryName, Mode=OneWay}" FontWeight="SemiBold" />
                  <Run Text="  (" /><Run Text="{Binding CategoryId, Mode=OneWay}" /><Run Text=")" />
                </TextBlock>
                <TextBlock Text="{Binding CategoryDescription, Mode=OneWay}" FontSize="12"
                           Foreground="{StaticResource BrushTextSecondary}" TextWrapping="Wrap" />
                <TextBlock FontSize="12" Margin="0,4,0,0">
                  <Run Text="类型  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding KindDisplay, Mode=OneWay}" />
                  <Run Text="  严重级别  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding SeverityDisplay, Mode=OneWay}" />
                  <Run Text="  置信度  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding ConfidenceDisplay, Mode=OneWay}" />
                </TextBlock>
                <TextBlock FontSize="12" Margin="0,4,0,0">
                  <Run Text="适用资产  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding AppliesToAssets, Mode=OneWay}" />
                </TextBlock>
                <TextBlock FontSize="12" Margin="0,4,0,0">
                  <Run Text="语义复核  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding SemanticReviewDisplay, Mode=OneWay}" />
                  <Run Text="  状态  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding EnabledDisplay, Mode=OneWay}" />
                </TextBlock>
              </StackPanel>
              <StackPanel Grid.Column="2" DataContext="{Binding SelectedRuleEntry}">
                <TextBlock FontSize="12">
                  <Run Text="检测器  " Foreground="{StaticResource BrushTextSecondary}" />
                  <Run Text="{Binding DetectorId, Mode=OneWay}" FontWeight="SemiBold" />
                  <Run Text="  (" /><Run Text="{Binding DetectorKind, Mode=OneWay}" /><Run Text=")" />
                </TextBlock>
                <TextBlock Text="匹配参数" Style="{StaticResource FieldLabelStyle}" Margin="0,6,0,0" />
                <TextBox Text="{Binding DetectorParameters, Mode=OneWay}"
                         IsReadOnly="True" TextWrapping="Wrap"
                         Style="{StaticResource MonoTextStyle}" FontSize="11"
                         MinHeight="48" MaxHeight="140"
                         Background="{StaticResource BrushSurface1}"
                         VerticalScrollBarVisibility="Auto" Margin="0,2,0,0" />
              </StackPanel>
            </Grid>
          </Border>
        </Grid>
      </Border>

      <Border Grid.Row="3" Style="{StaticResource CardStyle}" Padding="0">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
          </Grid.RowDefinitions>
          <Grid Background="{StaticResource BrushSurface0}" Height="52">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" />
              <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <TextBlock Text="规则包历史" Style="{StaticResource SectionTitleStyle}"
                       VerticalAlignment="Center" Margin="18,0" />
            <TextBlock Grid.Column="1" Text="{Binding LastImportStatus}"
                       Style="{StaticResource PageSubtitleStyle}" VerticalAlignment="Center" Margin="18,0" />
          </Grid>
          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" MaxHeight="220">
            <ItemsControl ItemsSource="{Binding History}" Margin="12,9">
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Border BorderBrush="{StaticResource BrushSurface2}" BorderThickness="0,0,0,1" Padding="8,12">
                    <Grid>
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*" />
                        <ColumnDefinition Width="130" />
                        <ColumnDefinition Width="120" />
                      </Grid.ColumnDefinitions>
                      <TextBlock Text="{Binding RulePackId}" FontWeight="SemiBold" />
                      <TextBlock Grid.Column="1" Text="{Binding Version, StringFormat='v{0}'}"
                                 Foreground="{StaticResource BrushTextSecondary}" />
                      <TextBlock Grid.Column="2" Text="{Binding StatusDisplay}" FontWeight="SemiBold"
                                 Foreground="{StaticResource BrushAccentHover}" />
                    </Grid>
                  </Border>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </ScrollViewer>
        </Grid>
      </Border>
    </Grid>
  </UserControl>
  ```

- [ ] **Step 2: 在 Windows 上构建 Desktop 项目，确认 XAML 编译通过**

  ```
  dotnet build src/SecurityReview.Desktop -c Release --no-restore
  ```

  预期：`Build succeeded. 0 Warning(s) 0 Error(s)`。若提示 `MonoTextStyle` 不能用于 `TextBox`（样式 TargetType 不匹配），把详情卡中 `TextBox` 的 `Style="{StaticResource MonoTextStyle}"` 改为 `FontFamily="Cascadia Mono"`。

- [ ] **Step 3: 提交**

  ```
  git add src/SecurityReview.Desktop/Views/RuleManagementView.xaml
  git commit -m "feat: show rule entries section in rule management view"
  ```

---

## Task 4: `ScanQueryService.GetOccurrenceFileLocationAsync` 投影（测试先行）

**Files:**
- Modify: `src/SecurityReview.Application/Scans/ScanQueryService.cs`（using 区第 1-5 行；构造函数第 32-44 行；`GetOccurrenceDetailsAsync` 两 overload 之后第 290 行附近插入新方法；文件尾部 projections 区追加 DTO）
- Modify: `src/SecurityReview.Desktop/CompositionRoot.cs`（第 383 行 `new ScanQueryService(...)` 调用点）
- Create: `tests/SecurityReview.UnitTests/Scans/ScanQueryTestDoubles.cs`（共享 fake：从 `ScanQueryServiceTests.cs` 移出 + 新增）
- Modify: `tests/SecurityReview.UnitTests/Scans/ScanQueryServiceTests.cs`（删除私有嵌套 fake，改用共享 fake；`CreateQuery` 增加 snapshot 参数；追加 3 个新测试）
- Create: `tests/SecurityReview.IntegrationTests/Persistence/OccurrenceFileLocationTests.cs`

**Interfaces:**
- Consumes（既有）：
  - `SecurityReview.Application.Abstractions.IScanSnapshotRepository.GetByScanIdAsync(ScanId, CancellationToken)` → `ScanSnapshotRecord?`
  - `SecurityReview.Application.Scans.ScanConfigurationSnapshotCodec(IPayloadProtector)`：`.Unprotect(ScanSnapshotRecord)` → `ScanConfigurationSnapshot`（`.RootPaths` 是 `string[]`）
  - `SecurityReview.Domain.Scans.FileRecord`：`RootIndex`（int）、`RelativePath`（string）、`ContentSha256`（string?）
  - `SecurityReview.Domain.Findings.FindingOccurrence`：`VirtualPath`、`FileSha256`、`CanonicalLocator`
- Produces（供 Task 5 消费）：
  ```csharp
  // ScanQueryService 构造函数新签名（末尾追加两个参数）
  public ScanQueryService(
      IScanRepository scanRepository,
      IFindingRepository findingRepository,
      ICoverageRepository coverageRepository,
      IFileRepository fileRepository,
      IReviewService reviewService,
      IScanSnapshotRepository snapshotRepository,
      IPayloadProtector payloadProtector);

  public async Task<OccurrenceFileLocation?> GetOccurrenceFileLocationAsync(
      ScanId scanId,
      FindingOccurrenceId occurrenceId,
      CancellationToken cancellationToken = default);

  public sealed record OccurrenceFileLocation(
      string? AbsolutePath,
      string VirtualPath,
      string OuterVirtualPath,
      SourceLocator CanonicalLocator,
      bool IsNested,
      bool FileExists);
  ```
- Produces（测试共享，供 Task 5 消费，均在 `SecurityReview.UnitTests.Scans` 命名空间，`internal`）：`FakeScanRepository`、`FakeFindingRepository`、`FakeCoverageRepository`、`FakeFileRepository`、`FakeReviewService`、`FakePayloadProtector`、`FakeScanSnapshotRepository`、`ScanTestData.BuildSnapshot(params string[])` / `ScanTestData.BuildRecord(ScanId, IPayloadProtector, params string[])`。

- [ ] **Step 1: 抽共享 fake 并扩展 `ScanQueryServiceTests`（先跑红）**

  创建 `tests/SecurityReview.UnitTests/Scans/ScanQueryTestDoubles.cs`（前 5 个 fake 类从 `ScanQueryServiceTests.cs` 原样搬出、改为 `internal` 顶层类；后 3 个为新增）：

  ```csharp
  using SecurityReview.Application.Abstractions;
  using SecurityReview.Application.Reviews;
  using SecurityReview.Application.Scans;
  using SecurityReview.Application.Scans.Preflight;
  using SecurityReview.Domain;
  using SecurityReview.Domain.Findings;
  using SecurityReview.Domain.Reviews;
  using SecurityReview.Domain.Scans;

  namespace SecurityReview.UnitTests.Scans;

  internal sealed class FakeScanRepository(ScanRun scan) : IScanRepository
  {
      public Task InsertAsync(ScanRun value, CancellationToken ct = default)
          => Task.CompletedTask;

      public Task<ScanRun?> GetByIdAsync(
          ScanId scanId,
          CancellationToken ct = default)
          => Task.FromResult<ScanRun?>(scan.ScanId == scanId ? scan : null);

      public Task<IReadOnlyList<ScanRun>> ListAsync(
          CancellationToken ct = default)
          => Task.FromResult<IReadOnlyList<ScanRun>>([scan]);

      public Task<bool> TryTransitionAsync(
          ScanId scanId,
          ScanStatus expectedStatus,
          long expectedVersion,
          ScanStatus nextStatus,
          CancellationToken ct = default)
          => Task.FromResult(false);

      public Task UpdateAsync(ScanRun value, CancellationToken ct = default)
          => Task.CompletedTask;

      public Task<IReadOnlyList<ScanRun>> ListByStatusAsync(
          IReadOnlyList<ScanStatus> statuses,
          CancellationToken ct = default)
          => Task.FromResult<IReadOnlyList<ScanRun>>(
              statuses.Contains(scan.Status) ? [scan] : []);

      public Task<ScanRun?> FindLatestPreviousAsync(
          string activeRulePackHash,
          string endpointFingerprint,
          CancellationToken ct = default)
          => Task.FromResult<ScanRun?>(scan);
  }

  internal sealed class FakeFindingRepository(
      ScanId scanId,
      IReadOnlyList<FindingGroup> groups) : IFindingRepository
  {
      public Task InsertGroupAsync(
          ScanId id,
          FindingGroup group,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task InsertOccurrenceAsync(
          FileId fileId,
          FindingOccurrence occurrence,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task InsertOccurrenceBatchAsync(
          FileId fileId,
          IReadOnlyList<FindingOccurrence> occurrences,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task<FindingGroup?> GetGroupByIdAsync(
          FindingGroupId id,
          CancellationToken ct = default)
          => Task.FromResult(groups.FirstOrDefault(group => group.Id == id));

      public Task<IReadOnlyList<FindingGroup>> GetGroupsByScanIdAsync(
          ScanId id,
          CancellationToken ct = default)
          => Task.FromResult<IReadOnlyList<FindingGroup>>(
              id == scanId ? groups : []);

      public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesByGroupIdAsync(
          FindingGroupId groupId,
          CancellationToken ct = default)
          => Task.FromResult<IReadOnlyList<FindingOccurrence>>(
              groups.FirstOrDefault(group => group.Id == groupId)?.Occurrences
              ?? []);
  }

  internal sealed class FakeCoverageRepository : ICoverageRepository
  {
      public Task InsertAsync(CoverageGap gap, CancellationToken ct = default)
          => Task.CompletedTask;

      public Task InsertBatchAsync(
          IReadOnlyList<CoverageGap> gaps,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task<IReadOnlyList<CoverageGap>> GetByScanIdAsync(
          ScanId scanId,
          CancellationToken ct = default)
          => Task.FromResult<IReadOnlyList<CoverageGap>>([]);
  }

  internal sealed class FakeFileRepository(
      ScanId scanId,
      IReadOnlyList<FileRecord> files) : IFileRepository
  {
      public Task InsertAsync(
          ScanId id,
          FileRecord file,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task InsertBatchAsync(
          ScanId id,
          IReadOnlyList<FileRecord> values,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task UpdateAsync(
          ScanId id,
          FileRecord file,
          CancellationToken ct = default)
          => Task.CompletedTask;

      public Task<FileRecord?> GetByIdAsync(
          FileId fileId,
          CancellationToken ct = default)
          => Task.FromResult(files.FirstOrDefault(file => file.FileId == fileId));

      public Task<IReadOnlyList<FileRecord>> GetByScanIdAsync(
          ScanId id,
          CancellationToken ct = default)
          => Task.FromResult<IReadOnlyList<FileRecord>>(
              id == scanId ? files : []);

      public Task<int> CountByScanIdAsync(
          ScanId id,
          CancellationToken ct = default)
          => Task.FromResult(id == scanId ? files.Count : 0);
  }

  internal sealed class FakeReviewService : IReviewService
  {
      public Task<ReviewDecision> RecordReviewAsync(
          RecordReviewCommand command,
          CancellationToken ct = default)
          => throw new NotSupportedException();

      public Task<ExceptionGrant> GrantExceptionAsync(
          GrantExceptionCommand command,
          CancellationToken ct = default)
          => throw new NotSupportedException();

      public Task<EffectiveReviewResult> GetEffectiveStatusAsync(
          FindingOccurrenceId occurrenceId,
          string assetBindingHmac,
          string occurrenceBindingHmac,
          CancellationToken ct = default)
          => Task.FromResult(new EffectiveReviewResult(
              ReviewStatus.Pending,
              "pending",
              null));
  }

  /// <summary>
  /// Reversible no-op "protector" for query-side tests: the payload is
  /// just base64 of the plaintext so the snapshot codec round-trips.
  /// </summary>
  internal sealed class FakePayloadProtector : IPayloadProtector
  {
      public EncryptedPayload Protect(
          string table, string recordId, string fieldName, byte[] plaintext) =>
          new(1, "test-key", "", Convert.ToBase64String(plaintext), "");

      public byte[] Unprotect(
          string table, string recordId, string fieldName, EncryptedPayload payload) =>
          Convert.FromBase64String(payload.CiphertextBase64);
  }

  internal sealed class FakeScanSnapshotRepository(
      ScanSnapshotRecord? record) : IScanSnapshotRepository
  {
      public Task InsertAsync(
          ScanId scanId,
          ScanSnapshotRecord value,
          CancellationToken cancellationToken = default)
          => Task.CompletedTask;

      public Task<ScanSnapshotRecord?> GetByScanIdAsync(
          ScanId scanId,
          CancellationToken cancellationToken = default)
          => Task.FromResult(
              record is not null && record.ScanId == scanId ? record : null);

      public Task<string?> GetConfigHashAsync(
          ScanId scanId,
          CancellationToken cancellationToken = default)
          => Task.FromResult(
              record is not null && record.ScanId == scanId ? record.ConfigHash : null);
  }

  /// <summary>
  /// Builds minimal but hash-valid scan configuration snapshots for tests.
  /// </summary>
  internal static class ScanTestData
  {
      public static ScanConfigurationSnapshot BuildSnapshot(params string[] rootPaths) =>
          new(
              RootPaths: rootPaths,
              Manifest: new ManifestSnapshot(
                  Manifest: null,
                  OriginalSha256: "manifest-hash",
                  Valid: true,
                  Errors: Array.Empty<ManifestValidationError>()),
              UiOverrideComponentIds: Array.Empty<string>(),
              ExclusionPatterns: Array.Empty<string>(),
              ActiveRulePackHash: "rule-pack-hash",
              PolicySha256: "policy-sha",
              LlmEndpointFingerprint: "endpoint-fp",
              LlmModelFingerprint: "model-fp",
              ClientVersion: "client-v1",
              ParserAdapterVersion: "parser-v1",
              DetectorAdapterVersion: "detector-v1",
              PromptVersion: "prompt-v1",
              Sandbox: new SandboxSelfTestResult(
                  true, "ok", "worker-sha", "os-build", "profile-sid",
                  DateTimeOffset.UnixEpoch),
              EffectiveDetectorVersions: ["detector-v1"],
              CapturedAtUtc: DateTimeOffset.UnixEpoch);

      public static ScanSnapshotRecord BuildRecord(
          ScanId scanId,
          IPayloadProtector protector,
          params string[] rootPaths)
      {
          ScanConfigurationSnapshot snapshot = BuildSnapshot(rootPaths);
          var codec = new ScanConfigurationSnapshotCodec(protector);
          return new ScanSnapshotRecord(
              scanId,
              snapshot.CapturedAtUtc,
              snapshot.ComputeHash(),
              snapshot.ActiveRulePackHash,
              snapshot.PolicySha256,
              snapshot.LlmEndpointFingerprint,
              snapshot.LlmModelFingerprint,
              snapshot.ClientVersion,
              snapshot.ParserAdapterVersion,
              snapshot.DetectorAdapterVersion,
              snapshot.PromptVersion,
              snapshot.Sandbox.WorkerSha256,
              codec.Protect(scanId, snapshot));
      }
  }
  ```

  在 `tests/SecurityReview.UnitTests/Scans/ScanQueryServiceTests.cs` 中：
  - 删除文件底部 5 个 `private sealed class Fake*` 嵌套类（现由共享文件提供；注意 `FakeReviewService` 原引用 `SecurityReview.Domain.Reviews.ReviewStatus` 全限定名，共享版已带 using）。
  - `CreateQuery` 改为：

    ```csharp
        private static ScanQueryService CreateQuery(
            ScanId scanId,
            IReadOnlyList<FindingGroup> groups,
            IReadOnlyList<FileRecord> files,
            ScanSnapshotRecord? snapshotRecord = null)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var scan = new ScanRun(
                scanId,
                ScanStatus.Completed,
                now,
                now,
                "rules",
                "client",
                "pipeline",
                files.Count,
                1);
            return new ScanQueryService(
                new FakeScanRepository(scan),
                new FakeFindingRepository(scanId, groups),
                new FakeCoverageRepository(),
                new FakeFileRepository(scanId, files),
                new FakeReviewService(),
                new FakeScanSnapshotRepository(snapshotRecord),
                new FakePayloadProtector());
        }
    ```

  - 类内追加 3 个新测试：

    ```csharp
        [Fact]
        public async Task File_location_resolves_absolute_path_from_root_index()
        {
            ScanId scanId = new(Guid.NewGuid());
            FindingGroupId groupId = new(Guid.NewGuid());
            FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
            string fileHash = new string('a', 64);
            var occurrence = new FindingOccurrence(
                occurrenceId,
                groupId,
                "raw-secret",
                "raw-context",
                new SourceLocator.TextLocator(0, 0, 10, 4),
                "conf/app.json",
                fileHash,
                []);
            var group = new FindingGroup(
                groupId,
                FindingKind.SensitiveContent,
                Severity.High,
                new ValueFingerprint(new string('b', 64)),
                [occurrence]);
            var file = new FileRecord(
                new FileId(Guid.NewGuid()),
                1,
                "conf/app.json",
                null,
                null,
                128,
                DateTimeOffset.UnixEpoch,
                FileAttributes.Normal,
                new FileStreamIdentity("volume", 1, null),
                [],
                InventoryStatus.Complete,
                "json",
                fileHash,
                CoverageStatus.Covered);
            var protector = new FakePayloadProtector();
            ScanQueryService query = CreateQuery(
                scanId,
                [group],
                [file],
                ScanTestData.BuildRecord(
                    scanId, protector, "C:\\root-a", "D:\\root-b"));

            OccurrenceFileLocation? location =
                await query.GetOccurrenceFileLocationAsync(scanId, occurrenceId);

            Assert.NotNull(location);
            Assert.Equal(
                Path.GetFullPath(Path.Combine("D:\\root-b", "conf/app.json")),
                location.AbsolutePath);
            Assert.Equal("conf/app.json", location.VirtualPath);
            Assert.False(location.IsNested);
            Assert.False(location.FileExists); // 测试机上该路径不存在
        }

        [Fact]
        public async Task File_location_marks_nested_content_and_resolves_outer_container()
        {
            ScanId scanId = new(Guid.NewGuid());
            FindingGroupId groupId = new(Guid.NewGuid());
            FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
            string fileHash = new string('c', 64);
            var occurrence = new FindingOccurrence(
                occurrenceId,
                groupId,
                "raw-secret",
                "raw-context",
                new SourceLocator.NestedLocator(
                    "bundle.zip",
                    new SourceLocator.TextLocator(0, 0, 3, 6)),
                "bundle.zip!inner/secret.txt",
                fileHash,
                []);
            var group = new FindingGroup(
                groupId,
                FindingKind.SensitiveContent,
                Severity.High,
                new ValueFingerprint(new string('d', 64)),
                [occurrence]);
            var file = new FileRecord(
                new FileId(Guid.NewGuid()),
                0,
                "bundle.zip",
                null,
                null,
                4096,
                DateTimeOffset.UnixEpoch,
                FileAttributes.Normal,
                new FileStreamIdentity("volume", 1, null),
                [],
                InventoryStatus.Complete,
                "zip",
                fileHash,
                CoverageStatus.Covered);
            var protector = new FakePayloadProtector();
            ScanQueryService query = CreateQuery(
                scanId,
                [group],
                [file],
                ScanTestData.BuildRecord(scanId, protector, "E:\\scans"));

            OccurrenceFileLocation? location =
                await query.GetOccurrenceFileLocationAsync(scanId, occurrenceId);

            Assert.NotNull(location);
            Assert.True(location.IsNested);
            Assert.Equal("bundle.zip", location.OuterVirtualPath);
            Assert.Equal(
                Path.GetFullPath(Path.Combine("E:\\scans", "bundle.zip")),
                location.AbsolutePath);
        }

        [Fact]
        public async Task File_location_is_scoped_to_the_requested_scan()
        {
            ScanId scanId = new(Guid.NewGuid());
            FindingGroupId groupId = new(Guid.NewGuid());
            FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
            var occurrence = new FindingOccurrence(
                occurrenceId,
                groupId,
                "raw-secret",
                "raw-context",
                new SourceLocator.TextLocator(0, 0, 0, 4),
                "conf/app.json",
                new string('a', 64),
                []);
            var group = new FindingGroup(
                groupId,
                FindingKind.SensitiveContent,
                Severity.High,
                new ValueFingerprint(new string('b', 64)),
                [occurrence]);
            ScanQueryService query = CreateQuery(scanId, [group], []);

            Assert.Null(await query.GetOccurrenceFileLocationAsync(
                new ScanId(Guid.NewGuid()), occurrenceId));
        }
    ```

  - `tests/SecurityReview.UnitTests/Scans/ScanQueryServiceTests.cs` 的 using 区补 `using SecurityReview.Application.Abstractions;`（`ScanSnapshotRecord` 需要；其余 using 已存在）。

- [ ] **Step 2: 写集成测试（真实 SQLite）**

  创建 `tests/SecurityReview.IntegrationTests/Persistence/OccurrenceFileLocationTests.cs`（样板复制自 `RepositoryRoundTripTests`；迁移需 `Migration001Initial` + `Migration003ScanSnapshots`）：

  ```csharp
  using System.Security.Cryptography;
  using Microsoft.Data.Sqlite;
  using SecurityReview.Application.Abstractions;
  using SecurityReview.Application.Scans;
  using SecurityReview.Domain;
  using SecurityReview.Domain.Assets;
  using SecurityReview.Domain.Findings;
  using SecurityReview.Domain.Reviews;
  using SecurityReview.Domain.Scans;
  using SecurityReview.Infrastructure.Cryptography;
  using SecurityReview.Infrastructure.Persistence;
  using SecurityReview.Infrastructure.Persistence.Migrations;
  using SecurityReview.Infrastructure.Persistence.Repositories;

  namespace SecurityReview.IntegrationTests.Persistence;

  public sealed class OccurrenceFileLocationTests : IAsyncDisposable
  {
      private readonly string _tempDir;
      private readonly string _databasePath;
      private readonly SqliteConnectionFactory _factory;
      private readonly AesGcmPayloadProtector _protector;
      private readonly PersistentValueFingerprintService _fingerprint;
      private readonly HkdfSha256 _hkdf;

      public OccurrenceFileLocationTests()
      {
          _tempDir = Directory.CreateTempSubdirectory("srt-fileloc-").FullName;
          _databasePath = Path.Combine(_tempDir, "test.db");
          _factory = new SqliteConnectionFactory(_databasePath);

          byte[] masterKey = new byte[32];
          RandomNumberGenerator.Fill(masterKey);
          _hkdf = new HkdfSha256(masterKey);
          _protector = new AesGcmPayloadProtector(
              _hkdf.DeriveEncryptionKey(), "test-key");
          _fingerprint = new PersistentValueFingerprintService(
              _hkdf.DeriveFingerprintKey());

          using var init = new SqliteConnection(
              $"Data Source={_databasePath};Mode=ReadWriteCreate");
          init.Open();
          new Migration001Initial()
              .ApplyAsync(init, "test-integration", CancellationToken.None)
              .GetAwaiter().GetResult();
          new Migration003ScanSnapshots()
              .ApplyAsync(init, "test-integration", CancellationToken.None)
              .GetAwaiter().GetResult();
          init.Close();
      }

      [Fact]
      public async Task Resolves_absolute_path_for_second_root_and_nested_entry()
      {
          // Arrange: two real roots; the hit file exists under root B.
          string rootA = Path.Combine(_tempDir, "rootA");
          string rootB = Path.Combine(_tempDir, "rootB");
          Directory.CreateDirectory(rootA);
          Directory.CreateDirectory(Path.Combine(rootB, "conf"));
          string realFile = Path.Combine(rootB, "conf", "app.json");
          await File.WriteAllTextAsync(realFile, "{}");
          string fileHash = new string('a', 64);

          var scans = new SqliteScanRepository(_factory, _protector);
          var files = new SqliteFileRepository(_factory, _protector, _fingerprint);
          var findings = new SqliteFindingRepository(_factory, _protector, _fingerprint);
          var coverage = new SqliteCoverageRepository(_factory, _protector);
          var snapshots = new SqliteScanSnapshotRepository(_factory);

          var now = DateTimeOffset.UtcNow;
          var scan = new ScanRun(
              new ScanId(Guid.NewGuid()), ScanStatus.Completed, now, now,
              "rule-fp", "client-v1", "pipeline-hash",
              PlannedCount: 1, Version: 1);
          await scans.InsertAsync(scan);

          var codec = new ScanConfigurationSnapshotCodec(_protector);
          ScanConfigurationSnapshot snapshot = ScanSnapshotBuilder.Build(
              rootA, rootB);
          var record = new ScanSnapshotRecord(
              scan.ScanId,
              snapshot.CapturedAtUtc,
              snapshot.ComputeHash(),
              snapshot.ActiveRulePackHash,
              snapshot.PolicySha256,
              snapshot.LlmEndpointFingerprint,
              snapshot.LlmModelFingerprint,
              snapshot.ClientVersion,
              snapshot.ParserAdapterVersion,
              snapshot.DetectorAdapterVersion,
              snapshot.PromptVersion,
              snapshot.Sandbox.WorkerSha256,
              codec.Protect(scan.ScanId, snapshot));
          await snapshots.InsertAsync(scan.ScanId, record);

          var fileId = new FileStreamIdentity("VOL001", new UInt128(0x1234, 0x5678), null)
              .DeriveFileId(scan.ScanId);
          var file = new FileRecord(
              fileId, 1, "conf/app.json", null, null, 2,
              now, FileAttributes.Normal,
              new FileStreamIdentity("VOL001", new UInt128(0x1234, 0x5678), null),
              [AssetTypeId.Parse("ASSET-001")],
              InventoryStatus.Complete, "json", fileHash, CoverageStatus.Covered);
          await files.InsertAsync(scan.ScanId, file);

          var groupId = new FindingGroupId(Guid.NewGuid());
          var occurrenceId = new FindingOccurrenceId(Guid.NewGuid());
          var occurrence = new FindingOccurrence(
              occurrenceId,
              groupId,
              "secret-value",
              "context",
              new SourceLocator.TextLocator(0, 0, 0, 12),
              "conf/app.json",
              fileHash,
              [new FindingProvenance(
                  new DetectorId("DET-TEST"),
                  new RuleId("RULE-TEST"),
                  DetectionConfidence.High,
                  false)]);
          var group = new FindingGroup(
              groupId, FindingKind.SensitiveContent, Severity.High,
              _fingerprint.Compute("secret-value"), [occurrence]);
          await findings.InsertGroupAsync(scan.ScanId, group);
          await findings.InsertOccurrenceAsync(file.FileId, occurrence);

          var query = new ScanQueryService(
              scans, findings, coverage, files,
              new StubReviewService(), snapshots, _protector);

          // Act
          OccurrenceFileLocation? location =
              await query.GetOccurrenceFileLocationAsync(
                  scan.ScanId, occurrenceId);

          // Assert
          Assert.NotNull(location);
          Assert.Equal(Path.GetFullPath(realFile), location.AbsolutePath);
          Assert.True(location.FileExists);
          Assert.False(location.IsNested);

          // scanId isolation: another scan sees nothing.
          Assert.Null(await query.GetOccurrenceFileLocationAsync(
              new ScanId(Guid.NewGuid()), occurrenceId));
      }

      [Fact]
      public async Task Nested_occurrence_resolves_outer_container_path()
      {
          string root = Path.Combine(_tempDir, "rootC");
          Directory.CreateDirectory(root);
          string container = Path.Combine(root, "bundle.zip");
          await File.WriteAllBytesAsync(container, [1, 2, 3]);
          string fileHash = new string('c', 64);

          var scans = new SqliteScanRepository(_factory, _protector);
          var files = new SqliteFileRepository(_factory, _protector, _fingerprint);
          var findings = new SqliteFindingRepository(_factory, _protector, _fingerprint);
          var coverage = new SqliteCoverageRepository(_factory, _protector);
          var snapshots = new SqliteScanSnapshotRepository(_factory);

          var now = DateTimeOffset.UtcNow;
          var scan = new ScanRun(
              new ScanId(Guid.NewGuid()), ScanStatus.Completed, now, now,
              "rule-fp", "client-v1", "pipeline-hash",
              PlannedCount: 1, Version: 1);
          await scans.InsertAsync(scan);

          var codec = new ScanConfigurationSnapshotCodec(_protector);
          ScanConfigurationSnapshot snapshot = ScanSnapshotBuilder.Build(root);
          var record = new ScanSnapshotRecord(
              scan.ScanId,
              snapshot.CapturedAtUtc,
              snapshot.ComputeHash(),
              snapshot.ActiveRulePackHash,
              snapshot.PolicySha256,
              snapshot.LlmEndpointFingerprint,
              snapshot.LlmModelFingerprint,
              snapshot.ClientVersion,
              snapshot.ParserAdapterVersion,
              snapshot.DetectorAdapterVersion,
              snapshot.PromptVersion,
              snapshot.Sandbox.WorkerSha256,
              codec.Protect(scan.ScanId, snapshot));
          await snapshots.InsertAsync(scan.ScanId, record);

          var fileId = new FileStreamIdentity("VOL002", new UInt128(1, 2), null)
              .DeriveFileId(scan.ScanId);
          var file = new FileRecord(
              fileId, 0, "bundle.zip", null, null, 3,
              now, FileAttributes.Normal,
              new FileStreamIdentity("VOL002", new UInt128(1, 2), null),
              [AssetTypeId.Parse("ASSET-001")],
              InventoryStatus.Complete, "zip", fileHash, CoverageStatus.Covered);
          await files.InsertAsync(scan.ScanId, file);

          var groupId = new FindingGroupId(Guid.NewGuid());
          var occurrenceId = new FindingOccurrenceId(Guid.NewGuid());
          var occurrence = new FindingOccurrence(
              occurrenceId,
              groupId,
              "secret-value",
              "context",
              new SourceLocator.NestedLocator(
                  "bundle.zip",
                  new SourceLocator.TextLocator(0, 0, 0, 12)),
              "bundle.zip!inner/secret.txt",
              fileHash,
              [new FindingProvenance(
                  new DetectorId("DET-TEST"),
                  new RuleId("RULE-TEST"),
                  DetectionConfidence.High,
                  false)]);
          var group = new FindingGroup(
              groupId, FindingKind.SensitiveContent, Severity.High,
              _fingerprint.Compute("secret-value"), [occurrence]);
          await findings.InsertGroupAsync(scan.ScanId, group);
          await findings.InsertOccurrenceAsync(file.FileId, occurrence);

          var query = new ScanQueryService(
              scans, findings, coverage, files,
              new StubReviewService(), snapshots, _protector);

          OccurrenceFileLocation? location =
              await query.GetOccurrenceFileLocationAsync(
                  scan.ScanId, occurrenceId);

          Assert.NotNull(location);
          Assert.True(location.IsNested);
          Assert.Equal("bundle.zip", location.OuterVirtualPath);
          Assert.Equal(Path.GetFullPath(container), location.AbsolutePath);
          Assert.True(location.FileExists);
      }

      private static class ScanSnapshotBuilder
      {
          public static ScanConfigurationSnapshot Build(params string[] rootPaths) =>
              new(
                  RootPaths: rootPaths,
                  Manifest: new SecurityReview.Application.Scans.Preflight.ManifestSnapshot(
                      Manifest: null,
                      OriginalSha256: "manifest-hash",
                      Valid: true,
                      Errors: Array.Empty<SecurityReview.Application.Scans.Preflight.ManifestValidationError>()),
                  UiOverrideComponentIds: Array.Empty<string>(),
                  ExclusionPatterns: Array.Empty<string>(),
                  ActiveRulePackHash: "rule-pack-hash",
                  PolicySha256: "policy-sha",
                  LlmEndpointFingerprint: "endpoint-fp",
                  LlmModelFingerprint: "model-fp",
                  ClientVersion: "client-v1",
                  ParserAdapterVersion: "parser-v1",
                  DetectorAdapterVersion: "detector-v1",
                  PromptVersion: "prompt-v1",
                  Sandbox: new SecurityReview.Application.Scans.Preflight.SandboxSelfTestResult(
                      true, "ok", "worker-sha", "os-build", "profile-sid",
                      DateTimeOffset.UnixEpoch),
                  EffectiveDetectorVersions: ["detector-v1"],
                  CapturedAtUtc: DateTimeOffset.UnixEpoch);
      }

      private sealed class StubReviewService : SecurityReview.Application.Reviews.IReviewService
      {
          public Task<ReviewDecision> RecordReviewAsync(
              SecurityReview.Application.Reviews.RecordReviewCommand command,
              CancellationToken ct = default)
              => throw new NotSupportedException();

          public Task<ExceptionGrant> GrantExceptionAsync(
              SecurityReview.Application.Reviews.GrantExceptionCommand command,
              CancellationToken ct = default)
              => throw new NotSupportedException();

          public Task<EffectiveReviewResult> GetEffectiveStatusAsync(
              FindingOccurrenceId occurrenceId,
              string assetBindingHmac,
              string occurrenceBindingHmac,
              CancellationToken ct = default)
              => Task.FromResult(new EffectiveReviewResult(
                  ReviewStatus.Pending, "pending", null));
      }

      public async ValueTask DisposeAsync()
      {
          _hkdf.Dispose();
          _protector.Dispose();
          _fingerprint.Dispose();

          try
          {
              if (Directory.Exists(_tempDir))
                  Directory.Delete(_tempDir, recursive: true);
          }
          catch
          {
              // Best-effort cleanup.
          }

          await Task.CompletedTask;
      }
  }
  ```

  注意：`ReviewDecision`/`ExceptionGrant`/`EffectiveReviewResult` 的命名空间以 `IReviewService` 定义处为准（`SecurityReview.Application.Reviews` 或 `SecurityReview.Domain.Reviews`），实现时按编译错误修正 using。

- [ ] **Step 3: 在 Windows 上跑测试，确认编译失败**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~ScanQueryServiceTests"
  ```

  预期：编译错误 `CS7036: There is no argument given that corresponds to the required parameter` 及 `CS1061: 'ScanQueryService' does not contain a definition for 'GetOccurrenceFileLocationAsync'`。

- [ ] **Step 4: 最小实现 — ScanQueryService 投影**

  在 `src/SecurityReview.Application/Scans/ScanQueryService.cs`：

  1. using 区追加：

     ```csharp
     using System.IO;
     ```

     （`Path`/`File` 已由 ImplicitUsings 提供则不必加；若 `dotnet format` 报 IDE0005 多余 using 则移除。）

  2. 字段区追加并替换构造函数：

     ```csharp
         private readonly IScanSnapshotRepository _snapshotRepository;
         private readonly ScanConfigurationSnapshotCodec _snapshotCodec;

         public ScanQueryService(
             IScanRepository scanRepository,
             IFindingRepository findingRepository,
             ICoverageRepository coverageRepository,
             IFileRepository fileRepository,
             IReviewService reviewService,
             IScanSnapshotRepository snapshotRepository,
             IPayloadProtector payloadProtector)
         {
             _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
             _findingRepository = findingRepository ?? throw new ArgumentNullException(nameof(findingRepository));
             _coverageRepository = coverageRepository ?? throw new ArgumentNullException(nameof(coverageRepository));
             _fileRepository = fileRepository ?? throw new ArgumentNullException(nameof(fileRepository));
             _reviewService = reviewService ?? throw new ArgumentNullException(nameof(reviewService));
             _snapshotRepository = snapshotRepository ?? throw new ArgumentNullException(nameof(snapshotRepository));
             ArgumentNullException.ThrowIfNull(payloadProtector);
             _snapshotCodec = new ScanConfigurationSnapshotCodec(payloadProtector);
         }
     ```

  3. 在无 scanId 的 `GetOccurrenceDetailsAsync(FindingOccurrenceId, ...)` overload 之后插入：

     ```csharp
         /// <summary>
         /// Resolves the on-disk file location for one occurrence: maps the
         /// occurrence's file record through the scan configuration snapshot's
         /// root paths. Nested content (ZIP entries, OCI layers) resolves to
         /// the outer container file. Never returns raw sensitive values.
         /// </summary>
         public async Task<OccurrenceFileLocation?> GetOccurrenceFileLocationAsync(
             ScanId scanId,
             FindingOccurrenceId occurrenceId,
             CancellationToken cancellationToken = default)
         {
             IReadOnlyList<FindingGroup> groups = await _findingRepository
                 .GetGroupsByScanIdAsync(scanId, cancellationToken)
                 .ConfigureAwait(false);
             FindingOccurrence? occurrence = groups
                 .SelectMany(g => g.Occurrences)
                 .FirstOrDefault(o => o.Id == occurrenceId);
             if (occurrence is null)
                 return null;

             string outerVirtualPath = occurrence.VirtualPath;
             bool isNested = false;
             int bangIndex = occurrence.VirtualPath.IndexOf('!', StringComparison.Ordinal);
             if (bangIndex > 0)
             {
                 isNested = true;
                 outerVirtualPath = occurrence.VirtualPath[..bangIndex];
             }

             IReadOnlyList<FileRecord> files = await _fileRepository
                 .GetByScanIdAsync(scanId, cancellationToken)
                 .ConfigureAwait(false);
             string normalizedOuter = outerVirtualPath.Replace('\\', '/');
             FileRecord? file = files.FirstOrDefault(f =>
                     string.Equals(
                         f.RelativePath.Replace('\\', '/'),
                         normalizedOuter,
                         StringComparison.Ordinal)
                     && string.Equals(
                         f.ContentSha256,
                         occurrence.FileSha256,
                         StringComparison.OrdinalIgnoreCase))
                 ?? files.FirstOrDefault(f =>
                     string.Equals(
                         f.RelativePath.Replace('\\', '/'),
                         normalizedOuter,
                         StringComparison.Ordinal));
             if (file is null)
             {
                 return new OccurrenceFileLocation(
                     AbsolutePath: null,
                     occurrence.VirtualPath,
                     outerVirtualPath,
                     occurrence.CanonicalLocator,
                     isNested,
                     FileExists: false);
             }

             ScanSnapshotRecord? record = await _snapshotRepository
                 .GetByScanIdAsync(scanId, cancellationToken)
                 .ConfigureAwait(false);
             if (record is null)
             {
                 return new OccurrenceFileLocation(
                     AbsolutePath: null,
                     occurrence.VirtualPath,
                     outerVirtualPath,
                     occurrence.CanonicalLocator,
                     isNested,
                     FileExists: false);
             }

             ScanConfigurationSnapshot snapshot = _snapshotCodec.Unprotect(record);
             if (file.RootIndex < 0 || file.RootIndex >= snapshot.RootPaths.Length)
             {
                 return new OccurrenceFileLocation(
                     AbsolutePath: null,
                     occurrence.VirtualPath,
                     outerVirtualPath,
                     occurrence.CanonicalLocator,
                     isNested,
                     FileExists: false);
             }

             string absolutePath = Path.GetFullPath(
                 Path.Combine(snapshot.RootPaths[file.RootIndex], file.RelativePath));
             return new OccurrenceFileLocation(
                 absolutePath,
                 occurrence.VirtualPath,
                 outerVirtualPath,
                 occurrence.CanonicalLocator,
                 isNested,
                 File.Exists(absolutePath));
         }
     ```

  4. projections 区（`DisposableOccurrenceDetail` 之后）追加 DTO：

     ```csharp
     /// <summary>
     /// On-disk file location of one occurrence. <see cref="AbsolutePath"/>
     /// is <c>null</c> when the file record or the scan snapshot cannot be
     /// resolved. For nested content the path points at the outer container.
     /// </summary>
     public sealed record OccurrenceFileLocation(
         string? AbsolutePath,
         string VirtualPath,
         string OuterVirtualPath,
         SourceLocator CanonicalLocator,
         bool IsNested,
         bool FileExists);
     ```

  5. `src/SecurityReview.Desktop/CompositionRoot.cs` 第 383 行改为：

     ```csharp
                         var scanQuery = new ScanQueryService(
                             sr, fr, cr, flr, reviewSvc, ssr, protector);
     ```

     （`ssr` 在第 329 行已声明、`protector` 在 Step 3-4 段已声明，均在该作用域内。）

- [ ] **Step 5: 在 Windows 上跑单元 + 集成测试，确认通过**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~ScanQueryServiceTests"
  dotnet test tests/SecurityReview.IntegrationTests --filter "FullyQualifiedName~OccurrenceFileLocationTests"
  ```

  预期：单元 `Passed: 5`（既有 2 + 新增 3）；集成 `Passed: 2`。

- [ ] **Step 6: 提交**

  ```
  git add src/SecurityReview.Application/Scans/ScanQueryService.cs src/SecurityReview.Desktop/CompositionRoot.cs tests/SecurityReview.UnitTests/Scans/ScanQueryTestDoubles.cs tests/SecurityReview.UnitTests/Scans/ScanQueryServiceTests.cs tests/SecurityReview.IntegrationTests/Persistence/OccurrenceFileLocationTests.cs
  git commit -m "feat: project occurrence file locations from scan snapshots"
  ```

---

## Task 5: `FindingDetailViewModel` 修复与 SafePreview 集成（TDD）

**Files:**
- Modify: `src/SecurityReview.Desktop/ViewModels/FindingDetailViewModel.cs`（整文件替换；原 281 行）
- Create: `tests/SecurityReview.UnitTests/Desktop/FindingDetailViewModelTests.cs`

**Interfaces:**
- Consumes（Task 4 产物）：`ScanQueryService.GetOccurrenceFileLocationAsync` / `OccurrenceFileLocation`；测试复用 `SecurityReview.UnitTests.Scans` 的 `FakeScanRepository`、`FakeFindingRepository`、`FakeCoverageRepository`、`FakeFileRepository`、`FakeReviewService`、`FakePayloadProtector`、`FakeScanSnapshotRepository`、`ScanTestData`。
- Consumes（既有）：`SafePreviewService.PreviewText(string, SourceLocator)` → `SafePreviewFragment`（`Lines: IReadOnlyList<SafePreviewLine>`，`SafePreviewLine(int LineNumber, string Text)`，`HighlightLineIndex`，`TruncatedBefore/After`）；`ExplorerService.LocateInExplorer(string)` 静态、`OpenExternally(string)` 实例（经确认委托）。
- Produces（供 Task 6 XAML 与 Task 7 CompositionRoot 消费）：
  ```csharp
  // 构造函数不变：(Func<ScanQueryService>, Func<ExplorerService>, IUiErrorSink)

  // 新的加载入口（旧的无 scanId overload 删除）
  public Task LoadDetailAsync(ScanId scanId, FindingOccurrenceId occurrenceId, CancellationToken ct = default);

  // 新公开成员
  public string FullPathDisplay { get; }        // 脱敏：…\<文件名>
  public string LineColumnDisplay { get; }      // "第 N 行，第 M 列" 或 ""
  public string PreviewText { get; }            // 预览片段或失败原因
  public bool FileExists { get; }
  public bool IsNestedContainer { get; }
  public ICommand CopyFullPathCommand { get; }

  // 静态纯函数（单元测试直测）
  public static (long Line, long Column) ComputeLineColumn(string text, long byteStart);
  ```
  既有成员（`VirtualPath`、`LocatorDisplay`、`FileHash`、`DecryptedValue`、`DecryptedContext`、`HasDetail`、`IsLoading`、`CopyFullValueCommand`、`CopyLocatorCommand`、`LocateInExplorerCommand`、`OpenExternallyCommand`、`ClearDetailCommand`、`ClearDetail()`、`Dispose()`）签名不变。`LocateInExplorerCommand`/`OpenExternallyCommand` 的 CanExecute 变为 `HasDetail && FileExists`。

- [ ] **Step 1: 写失败测试**

  创建 `tests/SecurityReview.UnitTests/Desktop/FindingDetailViewModelTests.cs`：

  ```csharp
  using SecurityReview.Application.Scans;
  using SecurityReview.Desktop.Services;
  using SecurityReview.Desktop.ViewModels;
  using SecurityReview.Domain;
  using SecurityReview.Domain.Assets;
  using SecurityReview.Domain.Findings;
  using SecurityReview.Domain.Scans;
  using SecurityReview.UnitTests.Scans;

  namespace SecurityReview.UnitTests.Desktop;

  public sealed class FindingDetailViewModelTests : IDisposable
  {
      private readonly string _tempDir =
          Directory.CreateTempSubdirectory("srt-fdetail-").FullName;

      // ---------------------------------------------------------- line/column

      [Fact]
      public void Compute_line_column_handles_lf()
      {
          (long line, long column) =
              FindingDetailViewModel.ComputeLineColumn("abc\ndef\nghi", 4);
          Assert.Equal(2, line);
          Assert.Equal(1, column);

          (line, column) = FindingDetailViewModel.ComputeLineColumn("abc\ndef\nghi", 5);
          Assert.Equal(2, line);
          Assert.Equal(2, column);

          (line, column) = FindingDetailViewModel.ComputeLineColumn("abc\ndef\nghi", 8);
          Assert.Equal(3, line);
          Assert.Equal(1, column);
      }

      [Fact]
      public void Compute_line_column_handles_crlf()
      {
          (long line, long column) =
              FindingDetailViewModel.ComputeLineColumn("abc\r\ndef", 5);
          Assert.Equal(2, line);
          Assert.Equal(1, column);
      }

      [Fact]
      public void Compute_line_column_counts_multibyte_characters()
      {
          // “你”= 3 UTF-8 字节；byteStart 4 指向第二行“好”。
          (long line, long column) =
              FindingDetailViewModel.ComputeLineColumn("你\n好", 4);
          Assert.Equal(2, line);
          Assert.Equal(1, column);
      }

      // ---------------------------------------------------------- detail loading

      [Fact]
      public async Task Load_detail_disables_open_buttons_when_file_is_missing()
      {
          (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
              BuildQuery(writeFile: false, nested: false);
          var viewModel = new FindingDetailViewModel(
              () => query,
              () => new ExplorerService(_ => false),
              new TestErrorSink());

          await viewModel.LoadDetailAsync(scanId, occurrenceId);

          Assert.True(viewModel.HasDetail);
          Assert.False(viewModel.FileExists);
          Assert.False(viewModel.LocateInExplorerCommand.CanExecute(null));
          Assert.False(viewModel.OpenExternallyCommand.CanExecute(null));
          Assert.Contains("不存在", viewModel.PreviewText);
      }

      [Fact]
      public async Task Load_detail_marks_nested_content_with_container_note()
      {
          (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
              BuildQuery(writeFile: true, nested: true);
          var viewModel = new FindingDetailViewModel(
              () => query,
              () => new ExplorerService(_ => false),
              new TestErrorSink());

          await viewModel.LoadDetailAsync(scanId, occurrenceId);

          Assert.True(viewModel.HasDetail);
          Assert.True(viewModel.IsNestedContainer);
          Assert.True(viewModel.FileExists);
          Assert.Contains("位于容器内", viewModel.PreviewText);
          Assert.True(viewModel.LocateInExplorerCommand.CanExecute(null));
      }

      [Fact]
      public async Task Load_detail_shows_preview_and_computed_line_column()
      {
          (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
              BuildQuery(writeFile: true, nested: false);
          var viewModel = new FindingDetailViewModel(
              () => query,
              () => new ExplorerService(_ => false),
              new TestErrorSink());

          await viewModel.LoadDetailAsync(scanId, occurrenceId);

          Assert.True(viewModel.HasDetail);
          Assert.Contains("secret-token", viewModel.PreviewText);
          Assert.Equal("第 2 行，第 1 列", viewModel.LineColumnDisplay);
          Assert.StartsWith("…", viewModel.FullPathDisplay);
          Assert.DoesNotContain(_tempDir, viewModel.FullPathDisplay);
      }

      [Fact]
      public void External_open_returns_false_when_confirmation_is_declined()
      {
          string file = Path.Combine(_tempDir, "exists.txt");
          File.WriteAllText(file, "data");
          var explorer = new ExplorerService(_ => false);

          Assert.False(explorer.OpenExternally(file));
      }

      [Fact]
      public void External_open_returns_false_for_missing_file_without_asking()
      {
          bool asked = false;
          var explorer = new ExplorerService(_ =>
          {
              asked = true;
              return true;
          });

          Assert.False(explorer.OpenExternally(
              Path.Combine(_tempDir, "missing.txt")));
          Assert.False(asked);
      }

      // ---------------------------------------------------------- helpers

      private (ScanQueryService, ScanId, FindingOccurrenceId) BuildQuery(
          bool writeFile,
          bool nested)
      {
          ScanId scanId = new(Guid.NewGuid());
          FindingGroupId groupId = new(Guid.NewGuid());
          FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
          string fileHash = new string('a', 64);

          string relativePath = nested ? "bundle.zip" : "hit.txt";
          string virtualPath = nested ? "bundle.zip!inner/secret.txt" : "hit.txt";
          SourceLocator locator = nested
              ? new SourceLocator.NestedLocator(
                  "bundle.zip", new SourceLocator.TextLocator(0, 0, 0, 12))
              : new SourceLocator.TextLocator(0, 0, 6, 12);

          if (writeFile)
          {
              string content = nested ? "PK-zip-bytes" : "alpha\nsecret-token\nomega\n";
              File.WriteAllText(Path.Combine(_tempDir, relativePath), content);
          }

          var occurrence = new FindingOccurrence(
              occurrenceId,
              groupId,
              "raw-secret",
              "raw-context",
              locator,
              virtualPath,
              fileHash,
              []);
          var group = new FindingGroup(
              groupId,
              FindingKind.SensitiveContent,
              Severity.High,
              new ValueFingerprint(new string('b', 64)),
              [occurrence]);
          var file = new FileRecord(
              new FileId(Guid.NewGuid()),
              0,
              relativePath,
              null,
              null,
              64,
              DateTimeOffset.UnixEpoch,
              FileAttributes.Normal,
              new FileStreamIdentity("volume", 1, null),
              [],
              InventoryStatus.Complete,
              "text",
              fileHash,
              CoverageStatus.Covered);

          var protector = new FakePayloadProtector();
          var now = DateTimeOffset.UtcNow;
          var scan = new ScanRun(
              scanId, ScanStatus.Completed, now, now,
              "rules", "client", "pipeline", 1, 1);
          var query = new ScanQueryService(
              new FakeScanRepository(scan),
              new FakeFindingRepository(scanId, [group]),
              new FakeCoverageRepository(),
              new FakeFileRepository(scanId, [file]),
              new FakeReviewService(),
              new FakeScanSnapshotRepository(
                  ScanTestData.BuildRecord(scanId, protector, _tempDir)),
              protector);
          return (query, scanId, occurrenceId);
      }

      public void Dispose()
      {
          try { Directory.Delete(_tempDir, recursive: true); }
          catch (IOException) { }
      }

      private sealed class TestErrorSink : IUiErrorSink
      {
          public void Report(string code, string message)
          {
          }
      }
  }
  ```

  注意：`SecurityReview.UnitTests.Desktop` 命名空间下若已有其它 `TestErrorSink`（如 `RuleManagementViewModelTests` 的私有嵌套类）不会冲突——私有嵌套类互不可见；保持本文件自包含。

- [ ] **Step 2: 在 Windows 上跑测试，确认编译失败**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~FindingDetailViewModelTests"
  ```

  预期：编译错误 `CS0117: 'FindingDetailViewModel' does not contain a definition for 'ComputeLineColumn'` 及 `CS1501: No overload for method 'LoadDetailAsync' takes 2 arguments`。

- [ ] **Step 3: 最小实现 — 整文件替换 FindingDetailViewModel.cs**

  ```csharp
  using System.ComponentModel;
  using System.Globalization;
  using System.Text;
  using System.Windows;
  using System.Windows.Input;
  using SecurityReview.Application.Scans;
  using SecurityReview.Desktop.Services;
  using SecurityReview.Domain;
  using SecurityReview.Domain.Findings;

  namespace SecurityReview.Desktop.ViewModels;

  /// <summary>
  /// View model for the sensitive finding detail display.
  /// Selects a specific occurrence within one scan and decrypts only that
  /// detail. Resolves the on-disk location through the scan configuration
  /// snapshot (never by treating the virtual path as a file-system path),
  /// renders a bounded safe preview, and locates/opens the file only via
  /// ExplorerService (external open always re-confirms).
  /// Navigating away or closing clears all string references.
  /// Copy Full Value requires explicit button + confirmation;
  /// clipboard auto-clears after 60 seconds.
  /// </summary>
  public sealed class FindingDetailViewModel : ObservableObject, IDisposable
  {
      private const long MaxFullReadBytes = 4 * 1024 * 1024; // 4 MiB
      private const int PreviewWindowBytes = 65_536;         // 与 SafePreviewService 上限一致
      private const int ClipboardAutoClearSeconds = 60;

      private readonly Func<ScanQueryService> _queryFactory;
      private readonly Func<ExplorerService> _explorerFactory;
      private readonly IUiErrorSink _errorSink;

      private DisposableOccurrenceDetail? _currentDetail;
      private string? _absolutePath;
      private string _virtualPath = "";
      private string _fullPathDisplay = "";
      private string _locatorDisplay = "";
      private string _lineColumnDisplay = "";
      private string _fileHash = "";
      private string _decryptedValue = "";
      private string _decryptedContext = "";
      private string _previewText = "";
      private bool _hasDetail;
      private bool _isLoading;
      private bool _fileExists;
      private bool _isNestedContainer;

      private DateTimeOffset _clipboardSetAt;
      private string? _clipboardFingerprint;
      private System.Timers.Timer? _clipboardTimer;

      public FindingDetailViewModel(
          Func<ScanQueryService> queryFactory,
          Func<ExplorerService> explorerFactory,
          IUiErrorSink errorSink)
      {
          _queryFactory = queryFactory;
          _explorerFactory = explorerFactory;
          _errorSink = errorSink;

          CopyFullValueCommand = new RelayCommand(_ => CopyFullValue(), _ => HasDetail);
          CopyFullPathCommand = new RelayCommand(
              _ => CopyFullPath(), _ => HasDetail && _absolutePath is not null);
          CopyLocatorCommand = new RelayCommand(_ => CopyLocator(), _ => HasDetail);
          LocateInExplorerCommand = new RelayCommand(
              _ => LocateInExplorer(), _ => HasDetail && FileExists);
          OpenExternallyCommand = new RelayCommand(
              _ => OpenExternally(), _ => HasDetail && FileExists);
          ClearDetailCommand = new RelayCommand(_ => ClearDetail());
      }

      // ------------------------------------------------------------------ Commands

      public ICommand CopyFullValueCommand { get; }
      public ICommand CopyFullPathCommand { get; }
      public ICommand CopyLocatorCommand { get; }
      public ICommand LocateInExplorerCommand { get; }
      public ICommand OpenExternallyCommand { get; }
      public ICommand ClearDetailCommand { get; }

      // ------------------------------------------------------------------ Properties

      public string VirtualPath
      {
          get => _virtualPath;
          private set => SetProperty(ref _virtualPath, value);
      }

      public string FullPathDisplay
      {
          get => _fullPathDisplay;
          private set => SetProperty(ref _fullPathDisplay, value);
      }

      public string LocatorDisplay
      {
          get => _locatorDisplay;
          private set => SetProperty(ref _locatorDisplay, value);
      }

      public string LineColumnDisplay
      {
          get => _lineColumnDisplay;
          private set => SetProperty(ref _lineColumnDisplay, value);
      }

      public string FileHash
      {
          get => _fileHash;
          private set => SetProperty(ref _fileHash, value);
      }

      public string DecryptedValue
      {
          get => _decryptedValue;
          private set => SetProperty(ref _decryptedValue, value);
      }

      public string DecryptedContext
      {
          get => _decryptedContext;
          private set => SetProperty(ref _decryptedContext, value);
      }

      public string PreviewText
      {
          get => _previewText;
          private set => SetProperty(ref _previewText, value);
      }

      public bool HasDetail
      {
          get => _hasDetail;
          set => SetProperty(ref _hasDetail, value);
      }

      public bool IsLoading
      {
          get => _isLoading;
          set => SetProperty(ref _isLoading, value);
      }

      public bool FileExists
      {
          get => _fileExists;
          private set => SetProperty(ref _fileExists, value);
      }

      public bool IsNestedContainer
      {
          get => _isNestedContainer;
          private set => SetProperty(ref _isNestedContainer, value);
      }

      // ------------------------------------------------------------------ Detail loading

      /// <summary>
      /// Loads and decrypts the detail for a specific occurrence within the
      /// given scan, then resolves its on-disk location and safe preview.
      /// Previous detail is cleared before the new one is loaded.
      /// </summary>
      public async Task LoadDetailAsync(
          ScanId scanId,
          FindingOccurrenceId occurrenceId,
          CancellationToken ct = default)
      {
          ClearDetailInternal();

          IsLoading = true;
          try
          {
              var query = _queryFactory();
              var detail = await query
                  .GetOccurrenceDetailsAsync(scanId, occurrenceId, ct)
                  .ConfigureAwait(true);
              if (detail is null)
              {
                  _errorSink.Report("detail_not_found", "未找到发现出现的详情。");
                  return;
              }

              _currentDetail = detail;
              VirtualPath = detail.VirtualPath;
              LocatorDisplay = detail.CanonicalLocator.ToCanonicalDisplay();
              FileHash = detail.FileSha256.Length >= 16
                  ? detail.FileSha256[..16]
                  : detail.FileSha256;

              // Decrypt and display the sensitive value and context ONCE
              DecryptedValue = detail.SensitiveValue.Value;
              DecryptedContext = detail.SensitiveContext.Value;

              OccurrenceFileLocation? location = await query
                  .GetOccurrenceFileLocationAsync(scanId, occurrenceId, ct)
                  .ConfigureAwait(true);
              if (location is not null)
              {
                  _absolutePath = location.AbsolutePath;
                  FileExists = location.FileExists;
                  IsNestedContainer = location.IsNested;
                  FullPathDisplay = location.AbsolutePath is null
                      ? "（无法还原绝对路径）"
                      : RedactAbsolutePath(location.AbsolutePath);

                  if (location.AbsolutePath is not null && location.FileExists)
                  {
                      await BuildPreviewAsync(location.AbsolutePath, location)
                          .ConfigureAwait(true);
                  }
                  else if (location.AbsolutePath is not null)
                  {
                      PreviewText = "（文件已不存在，无法预览。）";
                  }
                  else
                  {
                      PreviewText = "（无法还原文件位置，预览不可用。）";
                  }
              }
              else
              {
                  FullPathDisplay = "（无法还原绝对路径）";
                  PreviewText = "（无法还原文件位置，预览不可用。）";
              }

              HasDetail = true;
          }
          catch (Exception)
          {
              _errorSink.Report("detail_load_failed", "加载发现详情失败。");
          }
          finally
          {
              IsLoading = false;
              CommandManager.InvalidateRequerySuggested();
          }
      }

      // ------------------------------------------------------------------ Preview

      /// <summary>
      /// Computes the 1-based line and character column for a UTF-8 byte
      /// offset inside decoded text. Handles LF and CRLF line endings.
      /// </summary>
      public static (long Line, long Column) ComputeLineColumn(
          string text, long byteStart)
      {
          ArgumentNullException.ThrowIfNull(text);
          if (byteStart < 0)
              byteStart = 0;

          long consumed = 0;
          long line = 1;
          long column = 1;
          for (int i = 0; i < text.Length; i++)
          {
              if (consumed >= byteStart)
                  break;

              char c = text[i];
              int charLength = char.IsHighSurrogate(c)
                  && i + 1 < text.Length
                  && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
              consumed += Encoding.UTF8.GetByteCount(text.AsSpan(i, charLength));
              if (c == '\n')
              {
                  line++;
                  column = 1;
              }
              else
              {
                  column++;
              }
              i += charLength - 1;
          }
          return (line, column);
      }

      private async Task BuildPreviewAsync(
          string absolutePath, OccurrenceFileLocation location)
      {
          if (location.IsNested)
          {
              PreviewText = $"位于容器内：{location.VirtualPath}\n" +
                  "嵌套内容不支持应用内预览，请用“在资源管理器中定位”查看外层容器。";
              return;
          }

          try
          {
              var info = new FileInfo(absolutePath);
              if (info.Length > MaxFullReadBytes)
              {
                  await BuildWindowedPreviewAsync(absolutePath, location)
                      .ConfigureAwait(true);
                  return;
              }

              string fullText = await File.ReadAllTextAsync(absolutePath)
                  .ConfigureAwait(true);

              SourceLocator previewLocator = location.CanonicalLocator;
              if (location.CanonicalLocator is SourceLocator.TextLocator textLocator)
              {
                  (long line, long column) =
                      ComputeLineColumn(fullText, textLocator.ByteStart);
                  LineColumnDisplay = string.Create(
                      CultureInfo.InvariantCulture, $"第 {line} 行，第 {column} 列");
                  // 存储的 TextLocator.Line 恒为 0；用现算行号定位预览片段。
                  previewLocator = new SourceLocator.TextLocator(
                      line - 1, column - 1,
                      textLocator.ByteStart, textLocator.ByteLength);
              }
              else if (location.CanonicalLocator is SourceLocator.JsonLocator jsonLocator)
              {
                  (long line, long column) =
                      ComputeLineColumn(fullText, jsonLocator.ByteStart);
                  LineColumnDisplay = string.Create(
                      CultureInfo.InvariantCulture, $"第 {line} 行，第 {column} 列");
              }

              SafePreviewFragment fragment =
                  SafePreviewService.PreviewText(fullText, previewLocator);
              PreviewText = FormatFragment(fragment);
          }
          catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
          {
              PreviewText = "（无法读取文件进行预览：权限不足或文件被占用。）";
          }
      }

      private async Task BuildWindowedPreviewAsync(
          string absolutePath, OccurrenceFileLocation location)
      {
          (long byteStart, long byteLength) = location.CanonicalLocator switch
          {
              SourceLocator.TextLocator tl => (tl.ByteStart, tl.ByteLength),
              SourceLocator.JsonLocator jl => (jl.ByteStart, jl.ByteLength),
              _ => (0L, 0L),
          };

          long windowStart = Math.Max(0, byteStart - PreviewWindowBytes / 2);
          (long line, long column, long windowLine) =
              await ComputeLineColumnStreamingAsync(absolutePath, byteStart, windowStart)
                  .ConfigureAwait(true);
          LineColumnDisplay = string.Create(
              CultureInfo.InvariantCulture, $"第 {line} 行，第 {column} 列");

          string windowText = await ReadWindowAsync(
                  absolutePath, windowStart, PreviewWindowBytes)
              .ConfigureAwait(true);
          var windowLocator = new SourceLocator.TextLocator(
              0, 0, byteStart - windowStart, byteLength);
          SafePreviewFragment fragment =
              SafePreviewService.PreviewText(windowText, windowLocator);
          PreviewText = "（大文件仅显示命中点附近片段，行号为文件真实行号。）\n"
              + FormatFragment(fragment, windowLine - 1);
      }

      private static async Task<(long Line, long Column, long WindowLine)>
          ComputeLineColumnStreamingAsync(
              string path, long byteStart, long windowStart)
      {
          await using var stream = new FileStream(
              path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
          var buffer = new byte[81_920];
          long consumed = 0;
          long line = 1;
          long lineStartByte = 0;
          long windowLine = 1;
          while (consumed < byteStart)
          {
              int read = await stream.ReadAsync(buffer, CancellationToken.None)
                  .ConfigureAwait(true);
              if (read == 0)
                  break;
              for (int i = 0; i < read && consumed < byteStart; i++, consumed++)
              {
                  if (buffer[i] == (byte)'\n')
                  {
                      line++;
                      lineStartByte = consumed + 1;
                  }
                  if (consumed == windowStart)
                      windowLine = line;
              }
          }
          return (line, byteStart - lineStartByte + 1, windowLine);
      }

      private static async Task<string> ReadWindowAsync(
          string path, long windowStart, int windowBytes)
      {
          await using var stream = new FileStream(
              path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
          stream.Seek(windowStart, SeekOrigin.Begin);
          var buffer = new byte[windowBytes];
          int read = await stream.ReadAsync(buffer, CancellationToken.None)
              .ConfigureAwait(true);
          return Encoding.UTF8.GetString(buffer, 0, read);
      }

      private static string FormatFragment(
          SafePreviewFragment fragment, long lineNumberOffset = 0)
      {
          var sb = new StringBuilder();
          if (fragment.TruncatedBefore > 0)
          {
              sb.Append("… 前面省略 ")
                  .Append(fragment.TruncatedBefore.ToString(CultureInfo.InvariantCulture))
                  .AppendLine(" 行 …");
          }
          for (int i = 0; i < fragment.Lines.Count; i++)
          {
              SafePreviewLine previewLine = fragment.Lines[i];
              string marker = i == fragment.HighlightLineIndex ? "▶" : " ";
              sb.Append(marker).Append(' ')
                  .Append((previewLine.LineNumber + 1 + lineNumberOffset)
                      .ToString(CultureInfo.InvariantCulture))
                  .Append(" │ ").AppendLine(previewLine.Text);
          }
          if (fragment.TruncatedAfter > 0)
          {
              sb.Append("… 后面省略 ")
                  .Append(fragment.TruncatedAfter.ToString(CultureInfo.InvariantCulture))
                  .Append(" 行 …");
          }
          return sb.ToString();
      }

      private static string RedactAbsolutePath(string absolutePath)
      {
          string leaf = Path.GetFileName(absolutePath);
          return leaf.Length == 0 ? "…" : $"…\\{leaf}";
      }

      // ------------------------------------------------------------------ Actions

      /// <summary>
      /// Copy Full Value requires explicit button press and confirmation.
      /// Sets a 60s clipboard auto-clear timer.
      /// </summary>
      private void CopyFullValue()
      {
          if (!HasDetail || string.IsNullOrEmpty(_decryptedValue)) return;

          var result = MessageBox.Show(
              "完整敏感值将被复制到剪贴板。\n\n剪贴板将在60秒后自动清除。\n确定要继续吗？",
              "复制完整值",
              MessageBoxButton.YesNo,
              MessageBoxImage.Warning);

          if (result != MessageBoxResult.Yes) return;

          Clipboard.SetText(_decryptedValue);
          _clipboardSetAt = DateTimeOffset.UtcNow;
          _clipboardFingerprint = _decryptedValue;

          // Start 60s auto-clear timer
          _clipboardTimer?.Stop();
          _clipboardTimer = new System.Timers.Timer(ClipboardAutoClearSeconds * 1000);
          _clipboardTimer.Elapsed += (_, _) =>
          {
              System.Windows.Application.Current?.Dispatcher.Invoke(() =>
              {
                  if (Clipboard.ContainsText())
                  {
                      string? current = null;
                      try { current = Clipboard.GetText(); } catch { }
                      if (current == _clipboardFingerprint)
                      {
                          Clipboard.Clear();
                      }
                  }
                  _clipboardTimer?.Stop();
              });
          };
          _clipboardTimer.AutoReset = false;
          _clipboardTimer.Start();
      }

      private void CopyFullPath()
      {
          if (!HasDetail || _absolutePath is null) return;
          Clipboard.SetText(_absolutePath);
      }

      private void CopyLocator()
      {
          if (!HasDetail) return;
          Clipboard.SetText(_locatorDisplay);
      }

      private void LocateInExplorer()
      {
          if (!HasDetail || !FileExists || _absolutePath is null) return;
          if (!ExplorerService.LocateInExplorer(_absolutePath))
          {
              _errorSink.Report("explorer_failed", "无法在资源管理器中定位该文件。");
          }
      }

      private void OpenExternally()
      {
          if (!HasDetail || !FileExists || _absolutePath is null) return;
          var explorer = _explorerFactory();
          explorer.OpenExternally(_absolutePath);
      }

      // ------------------------------------------------------------------ Cleanup

      /// <summary>
      /// Clears the current detail. Zeroes all sensitive string references.
      /// Called on navigation, close, or explicit clear.
      /// </summary>
      public void ClearDetail()
      {
          ClearDetailInternal();
          HasDetail = false;
      }

      private void ClearDetailInternal()
      {
          // Dispose the sensitive strings (zeroes the buffers)
          _currentDetail?.SensitiveValue.Dispose();
          _currentDetail?.SensitiveContext.Dispose();
          _currentDetail = null;

          // Clear all string properties
          DecryptedValue = "";
          DecryptedContext = "";
          VirtualPath = "";
          FullPathDisplay = "";
          LocatorDisplay = "";
          LineColumnDisplay = "";
          FileHash = "";
          PreviewText = "";
          _absolutePath = null;
          FileExists = false;
          IsNestedContainer = false;

          // Stop clipboard timer
          _clipboardTimer?.Stop();
          _clipboardTimer = null;
          _clipboardFingerprint = null;
      }

      public void Dispose()
      {
          ClearDetailInternal();
          _clipboardTimer?.Dispose();
      }
  }

  // ---------------------------------------------------------------------------
  // Simple synchronous relay command for non-async operations
  // ---------------------------------------------------------------------------

  file sealed class RelayCommand : ICommand
  {
      private readonly Action<object?> _execute;
      private readonly Func<object?, bool>? _canExecute;

      public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
      {
          _execute = execute;
          _canExecute = canExecute;
      }

      public event EventHandler? CanExecuteChanged
      {
          add => CommandManager.RequerySuggested += value;
          remove => CommandManager.RequerySuggested -= value;
      }

      public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
      public void Execute(object? parameter) => _execute(parameter);
  }
  ```

- [ ] **Step 4: 在 Windows 上跑测试，确认通过**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~FindingDetailViewModelTests"
  ```

  预期：`Passed! - Failed: 0, Passed: 8`。

- [ ] **Step 5: 回归 — 既有预览与结果页测试不变红**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~SafePreviewServiceTests|FullyQualifiedName~ScanResultsViewModelTests"
  ```

  预期：全部通过（本任务未改动这两个类，属于确认性回归）。

- [ ] **Step 6: 提交**

  ```
  git add src/SecurityReview.Desktop/ViewModels/FindingDetailViewModel.cs tests/SecurityReview.UnitTests/Desktop/FindingDetailViewModelTests.cs
  git commit -m "feat: resolve occurrence locations and safe preview in finding detail"
  ```

---

## Task 6: XAML 接线 — `ScanResultsViewModel.Detail` + `ScanResultsView` + `FindingDetailView`

**Files:**
- Modify: `src/SecurityReview.Desktop/ViewModels/ScanResultsViewModel.cs`（构造函数第 58-80 行；`SelectOccurrenceAsync` 第 313-351 行）
- Modify: `src/SecurityReview.Desktop/Views/ScanResultsView.xaml`（根元素 xmlns；右下卡片第 167-184 行）
- Modify: `src/SecurityReview.Desktop/Views/FindingDetailView.xaml`（整文件替换；原 159 行）

**Interfaces:**
- Consumes（Task 5 产物）：`FindingDetailViewModel.LoadDetailAsync(ScanId, FindingOccurrenceId, CancellationToken)` 及全部新绑定属性。
- Produces（供 Task 7 消费）：
  ```csharp
  // ScanResultsViewModel 构造函数新签名（第 3 个可选参数）
  public ScanResultsViewModel(
      IUiErrorSink errorSink,
      Func<ScanQueryService> queryServiceFactory,
      FindingDetailViewModel? detail = null);

  public FindingDetailViewModel? Detail { get; }
  ```
- 备注：`ScanResultsViewModel` 既有属性 `DecryptedValue`/`DecryptedContext` 与其加载逻辑**保留不动**（`ScanResultsViewModelTests` 依赖），仅 XAML 不再直接展示；`SelectOccurrenceAsync` 末尾追加对 `Detail` 的转发。

- [ ] **Step 1: ScanResultsViewModel 挂接子视图模型**

  在 `src/SecurityReview.Desktop/ViewModels/ScanResultsViewModel.cs`：

  1. 构造函数替换为：

     ```csharp
         public ScanResultsViewModel(
             IUiErrorSink errorSink,
             Func<ScanQueryService> queryServiceFactory,
             FindingDetailViewModel? detail = null)
         {
             _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
             _queryServiceFactory = queryServiceFactory
                 ?? throw new ArgumentNullException(nameof(queryServiceFactory));
             Detail = detail;

             LoadGroupsCommand = new AsyncRelayCommand(
                 LoadGroupsAsync, errorSink);
             ExpandGroupCommand = new AsyncRelayCommand(
                 ExpandGroupAsync, errorSink);
             SelectOccurrenceCommand = new AsyncRelayCommand(
                 SelectOccurrenceAsync, errorSink);
             PreviousPageCommand = new AsyncRelayCommand(
                 PreviousPageAsync, errorSink);
             NextPageCommand = new AsyncRelayCommand(
                 NextPageAsync, errorSink);
             ApplyFilterCommand = new AsyncRelayCommand(
                 ApplyFilterAsync, errorSink);
             ClearFiltersCommand = new AsyncRelayCommand(
                 _ => ClearFiltersAsync(), errorSink);
         }

         /// <summary>
         /// Detail panel for the selected occurrence. <c>null</c> when the
         /// composition root could not build the query/explorer services.
         /// </summary>
         public FindingDetailViewModel? Detail { get; }
     ```

  2. `SelectOccurrenceAsync` 的 `try` 块末尾（`else` 分支之后、`finally` 之前）追加：

     ```csharp
                 if (Detail is not null)
                 {
                     await Detail.LoadDetailAsync(
                             _scanId, occurrence.OccurrenceId, cancellationToken)
                         .ConfigureAwait(true);
                 }
     ```

- [ ] **Step 2: 回归 — ScanResultsViewModel 既有测试（Windows）**

  ```
  dotnet test tests/SecurityReview.UnitTests --filter "FullyQualifiedName~ScanResultsViewModelTests"
  ```

  预期：全部通过（新参数可选，既有两参构造不受影响）。

- [ ] **Step 3: ScanResultsView.xaml 替换右下卡片**

  1. 根元素 `UserControl` 增加命名空间：

     ```xml
     xmlns:views="clr-namespace:SecurityReview.Desktop.Views"
     ```

  2. 右下卡片（原第 167-184 行，`<Border Grid.Row="2" Style="{StaticResource CardStyle}">…解密值/上下文…</Border>`）整段替换为：

     ```xml
             <Border Grid.Row="2" Style="{StaticResource CardStyle}" Padding="0">
                 <ScrollViewer VerticalScrollBarVisibility="Auto">
                     <views:FindingDetailView DataContext="{Binding Detail}" />
                 </ScrollViewer>
             </Border>
     ```

  3. 右侧两行的行高比例（`0.9*` / `1.1*`）保持不变。

- [ ] **Step 4: 整文件替换 FindingDetailView.xaml**

  变更点：新增“完整路径”行（脱敏显示 + “复制完整路径”按钮）、“行号”行、“预览”只读区、“文件已不存在”警示；按钮行保留“复制完整值/在资源管理器中定位/外部打开/清除”。XAML 缩进 2 空格。

  ```xml
  <UserControl x:Class="SecurityReview.Desktop.Views.FindingDetailView"
               xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
               xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
               xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
               xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
               xmlns:vm="clr-namespace:SecurityReview.Desktop.ViewModels"
               mc:Ignorable="d"
               d:DataContext="{d:DesignInstance Type=vm:FindingDetailViewModel}">

    <UserControl.Resources>
      <BooleanToVisibilityConverter x:Key="BooleanToVisibility" />
    </UserControl.Resources>

    <Grid>
      <!-- Detail content: visible when HasDetail and not IsLoading -->
      <GroupBox Header="发现详情" Margin="0">
        <GroupBox.Style>
          <Style TargetType="GroupBox" BasedOn="{StaticResource GroupBoxCardStyle}">
            <Setter Property="Visibility" Value="Collapsed"/>
            <Style.Triggers>
              <MultiDataTrigger>
                <MultiDataTrigger.Conditions>
                  <Condition Binding="{Binding HasDetail}" Value="True"/>
                  <Condition Binding="{Binding IsLoading}" Value="False"/>
                </MultiDataTrigger.Conditions>
                <Setter Property="Visibility" Value="Visible"/>
              </MultiDataTrigger>
            </Style.Triggers>
          </Style>
        </GroupBox.Style>
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="80"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>

          <!-- Row 0: Virtual Path -->
          <TextBlock Grid.Row="0" Grid.Column="0" Text="虚拟路径"
                     VerticalAlignment="Center" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="0" Grid.Column="1" Grid.ColumnSpan="2"
                   Text="{Binding VirtualPath, Mode=OneWay}"
                   IsReadOnly="True" Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   FontFamily="Cascadia Mono" FontSize="13"/>

          <!-- Row 1: Full Path (redacted) + Copy button -->
          <TextBlock Grid.Row="1" Grid.Column="0" Text="完整路径"
                     VerticalAlignment="Center" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="1" Grid.Column="1"
                   Text="{Binding FullPathDisplay, Mode=OneWay}"
                   IsReadOnly="True" Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   FontFamily="Cascadia Mono" FontSize="13"/>
          <Button Grid.Row="1" Grid.Column="2"
                  Content="复制完整路径" Command="{Binding CopyFullPathCommand}"
                  Padding="8,4" Margin="6,4,0,4"
                  Background="{StaticResource BrushSurface2}"
                  BorderBrush="{StaticResource BrushSurface2}"/>

          <!-- Row 2: Locator Display + Copy button -->
          <TextBlock Grid.Row="2" Grid.Column="0" Text="定位器"
                     VerticalAlignment="Center" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="2" Grid.Column="1"
                   Text="{Binding LocatorDisplay, Mode=OneWay}"
                   IsReadOnly="True" Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   FontFamily="Cascadia Mono" FontSize="13"/>
          <Button Grid.Row="2" Grid.Column="2"
                  Content="复制定位信息" Command="{Binding CopyLocatorCommand}"
                  Padding="8,4" Margin="6,4,0,4"
                  Background="{StaticResource BrushSurface2}"
                  BorderBrush="{StaticResource BrushSurface2}"/>

          <!-- Row 3: Computed line/column -->
          <TextBlock Grid.Row="3" Grid.Column="0" Text="行号"
                     VerticalAlignment="Center" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2"
                   Text="{Binding LineColumnDisplay, Mode=OneWay}"
                   IsReadOnly="True" Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   FontFamily="Cascadia Mono" FontSize="13"/>

          <!-- Row 4: File Hash -->
          <TextBlock Grid.Row="4" Grid.Column="0" Text="文件哈希"
                     VerticalAlignment="Center" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="2"
                   Text="{Binding FileHash, Mode=OneWay}"
                   IsReadOnly="True" Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   FontFamily="Cascadia Mono" FontSize="13"/>

          <!-- Row 5: Decrypted Value -->
          <TextBlock Grid.Row="5" Grid.Column="0" Text="解密值"
                     VerticalAlignment="Top" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="5" Grid.Column="1" Grid.ColumnSpan="2"
                   Text="{Binding DecryptedValue, Mode=OneWay}"
                   IsReadOnly="True" TextWrapping="Wrap"
                   FontFamily="Cascadia Mono" FontSize="13"
                   MinHeight="60" MaxHeight="120"
                   Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   VerticalScrollBarVisibility="Auto"/>

          <!-- Row 6: Decrypted Context -->
          <TextBlock Grid.Row="6" Grid.Column="0" Text="上下文"
                     VerticalAlignment="Top" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="6" Grid.Column="1" Grid.ColumnSpan="2"
                   Text="{Binding DecryptedContext, Mode=OneWay}"
                   IsReadOnly="True" TextWrapping="Wrap"
                   FontFamily="Cascadia Mono" FontSize="13"
                   MinHeight="60" MaxHeight="120"
                   Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   VerticalScrollBarVisibility="Auto"/>

          <!-- Row 7: Safe preview -->
          <TextBlock Grid.Row="7" Grid.Column="0" Text="预览"
                     VerticalAlignment="Top" Margin="0,4,8,4"
                     Foreground="{StaticResource BrushTextSecondary}"/>
          <TextBox Grid.Row="7" Grid.Column="1" Grid.ColumnSpan="2"
                   Text="{Binding PreviewText, Mode=OneWay}"
                   IsReadOnly="True" TextWrapping="NoWrap"
                   FontFamily="Cascadia Mono" FontSize="12"
                   MinHeight="80" MaxHeight="240"
                   Margin="0,4,0,4"
                   Background="{StaticResource BrushSurface1}"
                   VerticalScrollBarVisibility="Auto"
                   HorizontalScrollBarVisibility="Auto"/>

          <!-- Row 8: File-missing warning -->
          <TextBlock Grid.Row="8" Grid.Column="0" Grid.ColumnSpan="3"
                     Text="文件已不存在，无法定位或打开。"
                     Foreground="{StaticResource BrushWarn}" FontSize="12"
                     Margin="0,2,0,2">
            <TextBlock.Style>
              <Style TargetType="TextBlock">
                <Setter Property="Visibility" Value="Collapsed"/>
                <Style.Triggers>
                  <MultiDataTrigger>
                    <MultiDataTrigger.Conditions>
                      <Condition Binding="{Binding HasDetail}" Value="True"/>
                      <Condition Binding="{Binding FileExists}" Value="False"/>
                    </MultiDataTrigger.Conditions>
                    <Setter Property="Visibility" Value="Visible"/>
                  </MultiDataTrigger>
                </Style.Triggers>
              </Style>
            </TextBlock.Style>
          </TextBlock>

          <!-- Row 9: Action buttons -->
          <StackPanel Grid.Row="9" Grid.Column="0" Grid.ColumnSpan="3"
                      Orientation="Horizontal" Margin="0,8,0,0">
            <Button Content="复制完整值" Command="{Binding CopyFullValueCommand}"
                    Padding="8,4" Margin="0,0,6,0"
                    Foreground="White"
                    Background="{StaticResource BrushWarn}"
                    BorderBrush="{StaticResource BrushWarn}"/>
            <Button Content="在资源管理器中定位" Command="{Binding LocateInExplorerCommand}"
                    Padding="8,4" Margin="0,0,6,0"
                    Background="{StaticResource BrushSurface2}"
                    BorderBrush="{StaticResource BrushSurface2}"/>
            <Button Content="外部打开" Command="{Binding OpenExternallyCommand}"
                    Padding="8,4" Margin="0,0,6,0"
                    Background="{StaticResource BrushSurface2}"
                    BorderBrush="{StaticResource BrushSurface2}"/>
            <Button Content="清除" Command="{Binding ClearDetailCommand}"
                    Padding="8,4"
                    Background="{StaticResource BrushSurface2}"
                    BorderBrush="{StaticResource BrushSurface2}"/>
          </StackPanel>
        </Grid>
      </GroupBox>

      <!-- Loading state -->
      <TextBlock Text="正在加载…"
                 FontSize="16" FontWeight="SemiBold"
                 Foreground="{StaticResource BrushTextSecondary}"
                 HorizontalAlignment="Center" VerticalAlignment="Center"
                 Visibility="{Binding IsLoading, Converter={StaticResource BooleanToVisibility}}"/>

      <!-- Empty state -->
      <TextBlock Text="请选择一个发现出现以查看详情。"
                 FontSize="14"
                 Foreground="{StaticResource BrushTextSecondary}"
                 HorizontalAlignment="Center" VerticalAlignment="Center">
        <TextBlock.Style>
          <Style TargetType="TextBlock">
            <Setter Property="Visibility" Value="Collapsed"/>
            <Style.Triggers>
              <MultiDataTrigger>
                <MultiDataTrigger.Conditions>
                  <Condition Binding="{Binding HasDetail}" Value="False"/>
                  <Condition Binding="{Binding IsLoading}" Value="False"/>
                </MultiDataTrigger.Conditions>
                <Setter Property="Visibility" Value="Visible"/>
              </MultiDataTrigger>
            </Style.Triggers>
          </Style>
        </TextBlock.Style>
      </TextBlock>
    </Grid>
  </UserControl>
  ```

- [ ] **Step 5: 在 Windows 上构建 Desktop 项目，确认 XAML 编译通过**

  ```
  dotnet build src/SecurityReview.Desktop -c Release --no-restore
  ```

  预期：`Build succeeded. 0 Warning(s) 0 Error(s)`。

- [ ] **Step 6: 提交**

  ```
  git add src/SecurityReview.Desktop/ViewModels/ScanResultsViewModel.cs src/SecurityReview.Desktop/Views/ScanResultsView.xaml src/SecurityReview.Desktop/Views/FindingDetailView.xaml
  git commit -m "feat: wire finding detail panel into scan results view"
  ```

---

## Task 7: CompositionRoot 收尾 — 外部打开确认委托修复 + 两个 VM 挂接

**Files:**
- Modify: `src/SecurityReview.Desktop/CompositionRoot.cs`（第 433-435 行 ExplorerService 注册；`GetRuleManagementViewModel` 第 756-765 行；`GetScanResultsViewModel` 第 789-795 行）

**Interfaces:**
- Consumes（Task 1 产物）：`IRulePackPreviewProvider` 已 `Register<IRulePackPreviewProvider>(...)`，用 `TryGet<IRulePackPreviewProvider>()` 取。
- Consumes（Task 2 产物）：`RuleManagementViewModel` 第 5 个可选参数 `previewProviderFactory`。
- Consumes（Task 6 产物）：`ScanResultsViewModel` 第 3 个可选参数 `detail`。
- Consumes（既有）：`ExplorerService.GetExternalOpenWarning(string)` 静态方法生成确认文案；`TryGet<ExplorerService>()`（第 435 行 `RegisterConcrete(explorerService)` 已注册具体类）。

- [ ] **Step 1: 修复外部打开确认委托**

  将第 433-435 行：

  ```csharp
          var explorerService = new Services.ExplorerService(
              path => true); // Warning dialog will be shown by the ViewModel
  ```

  替换为：

  ```csharp
          var explorerService = new Services.ExplorerService(path =>
              System.Windows.MessageBox.Show(
                  Services.ExplorerService.GetExternalOpenWarning(path),
                  "外部打开确认",
                  System.Windows.MessageBoxButton.YesNo,
                  System.Windows.MessageBoxImage.Warning)
              == System.Windows.MessageBoxResult.Yes);
  ```

  （CompositionRoot 无 `using System.Windows;`，保持全限定名，与文件其余风格一致。）

- [ ] **Step 2: 挂接 RuleManagementViewModel 的预览端口**

  `GetRuleManagementViewModel` 整体替换为：

  ```csharp
      public RuleManagementViewModel GetRuleManagementViewModel()
      {
          var importSvc = TryGet<RulePackImportService>();
          var ruleStore = TryGet<IRulePackStore>();
          var preview = TryGet<IRulePackPreviewProvider>();
          return new RuleManagementViewModel(
              importSvc is not null ? () => importSvc : null!,
              ErrorSink,
              ruleStore is not null ? () => ruleStore : null,
              () => RefreshShellStatusAsync(),
              preview is not null ? () => preview : null);
      }
  ```

- [ ] **Step 3: 挂接 ScanResultsViewModel 的 FindingDetailViewModel**

  `GetScanResultsViewModel` 整体替换为：

  ```csharp
      public ScanResultsViewModel GetScanResultsViewModel()
      {
          var query = TryGet<ScanQueryService>();
          var explorer = TryGet<ExplorerService>();
          FindingDetailViewModel? detail = query is not null && explorer is not null
              ? new FindingDetailViewModel(() => query, () => explorer, ErrorSink)
              : null;
          return new ScanResultsViewModel(
              ErrorSink,
              query is not null ? () => query : null!,
              detail);
      }
  ```

- [ ] **Step 4: 在 Windows 上跑集成回归，确认 CompositionRoot 接线不破**

  ```
  dotnet test tests/SecurityReview.IntegrationTests --filter "FullyQualifiedName~CompositionRootTests|FullyQualifiedName~DesktopWorkflowTests"
  ```

  预期：全部通过（`CompositionRootTests` 会真实构建 CompositionRoot，覆盖新注册与两个工厂方法）。

- [ ] **Step 5: 提交**

  ```
  git add src/SecurityReview.Desktop/CompositionRoot.cs
  git commit -m "fix: require confirmation for external open and wire detail view models"
  ```

---

## Task 8: 验证收尾 — format、可追溯性、CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`（文件顶部新增 Unreleased 节）

**Interfaces:**
- Consumes：无新代码接口；纯验证与文档。

- [ ] **Step 1: 在 Windows 上跑全量单元测试车道**

  ```
  pwsh ./build/test.ps1 -Lane Unit
  ```

  预期：全部通过。若有失败，回到对应任务修复，不得跳过。

- [ ] **Step 2: 在 Windows 上跑 Contract + Integration 车道**

  ```
  pwsh ./build/test.ps1 -Lane Contract,Integration
  ```

  预期：全部通过（重点确认 `CompositionRootTests`、`DesktopWorkflowTests`、`RepositoryRoundTripTests`、`OccurrenceFileLocationTests`）。

- [ ] **Step 3: 在 Windows 上跑 dotnet format 校验**

  ```
  dotnet format SecurityReviewTool.sln --verify-no-changes
  ```

  预期：退出码 0。若有格式差异，先跑 `dotnet format SecurityReviewTool.sln` 修复并纳入 Task 8 的提交。

- [ ] **Step 4: 在 Windows 上跑可追溯性检查**

  ```
  pwsh build/verify-traceability.ps1
  ```

  预期：通过。本变更为既有需求的 UX 完善，预计无需新增 REQ/AC/SRS-F/VT 编号；若脚本报告缺口，按提示补齐后再继续。

- [ ] **Step 5: 更新 CHANGELOG.md**

  在 `# Changelog` 之后、 `## 1.0.10 - 2026-07-26` 之前插入：

  ```markdown
  ## Unreleased

  ### 新增

  - 规则管理页现在可预览活动规则包的全部规则条目：支持按规则 ID/类别名/检测器 ID 搜索、类别下拉筛选、只读详情（含检测器匹配参数与适用资产），并为活动包显示“内置/导入/未知”来源徽章。
  - 扫描结果页的出现位置详情现在提供应用内安全预览（高亮命中行、按字节偏移现算真实行号），以及“在资源管理器中定位”“外部打开”（每次强制确认）“复制完整路径”“复制定位信息”操作。

  ### 修复

  - 修复出现位置详情把相对虚拟路径当作文件系统路径解析、导致定位/打开必然失败的问题；现在经扫描配置快照的 RootPaths 与文件记录还原绝对路径，嵌套内容回退到外层容器。
  - 修复外部打开确认委托被 `path => true` 绕过的安全缺口，现在每次打开都必须经显式确认。
  - 超大文件预览只读取命中点前后窗口（64 KiB），不再全文加载。

  ### 验证

  - 新增规则条目预览视图模型、出现位置文件定位投影、发现详情视图模型与行号计算的单元测试，以及文件定位投影的 SQLite 集成测试（多根目录、嵌套虚拟路径、scanId 隔离）。
  - Windows 上 `pwsh ./build/test.ps1 -Lane Unit`、`pwsh ./build/test.ps1 -Lane Contract,Integration`、`dotnet format SecurityReviewTool.sln --verify-no-changes`、`pwsh build/verify-traceability.ps1` 全部通过（测试计数以实际运行为准并在此处补记）。
  ```

  注意：跑完 Step 1-2 后把实际测试计数补进“验证”节（对照既有条目格式，如 `Unit 802/802`）。

- [ ] **Step 6: 提交**

  ```
  git add CHANGELOG.md
  git commit -m "docs: record rule pack preview and finding location changes"
  ```

---

## 自检清单（全部任务完成后）

- [ ] `RuleManagementView` 显示规则条目区，搜索/筛选/详情/徽章均工作。
- [ ] `ScanResultsView` 选中出现位置后，详情区显示脱敏完整路径、定位信息、真实行号、预览片段与四个新按钮。
- [ ] 外部打开每次都弹 MessageBox 确认；拒绝时不打开。
- [ ] 文件已删除时定位/打开按钮禁用并显示“文件已不存在”。
- [ ] 嵌套内容显示“位于容器内”标注并回退到外层容器。
- [ ] 日志/错误上报中无敏感命中值（自查新增 `_errorSink.Report` 调用：只含稳定 code 与通用文案）。
- [ ] `dotnet format --verify-no-changes`、`verify-traceability.ps1`、Unit/Contract/Integration 车道全绿（Windows）。
