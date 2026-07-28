using SecurityReview.Application.Rules;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.UnitTests.Desktop;

public sealed class RuleManagementViewModelTests
{
    private static readonly string[] ExpectedCategoryFilters = { "全部", "凭据", "网络地址" };

    [Fact]
    public async Task Refresh_loads_active_rule_pack_pointer()
    {
        var active = new ActivePointer
        {
            RulePackId = "baseline",
            Version = "1.2.3",
            Sha256 = new string('a', 64),
        };
        var viewModel = new RuleManagementViewModel(
            () => throw new InvalidOperationException(),
            new TestErrorSink(),
            () => new TestRulePackStore(active));

        await viewModel.RefreshAsync();

        Assert.True(viewModel.HasActivePack);
        Assert.Equal("baseline", viewModel.ActiveRulePackId);
        Assert.Equal("1.2.3", viewModel.ActiveVersion);
        Assert.Equal(active.Sha256, viewModel.ActiveHash);
    }

    [Fact]
    public async Task Refresh_explains_when_no_rule_pack_is_active()
    {
        var viewModel = new RuleManagementViewModel(
            () => throw new InvalidOperationException(),
            new TestErrorSink(),
            () => new TestRulePackStore(null));

        await viewModel.RefreshAsync();

        Assert.False(viewModel.HasActivePack);
        Assert.Equal("尚未激活规则包", viewModel.LastImportStatus);
        Assert.Contains("可信发布者签名", viewModel.Warnings);
    }

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

        Assert.Equal(ExpectedCategoryFilters, viewModel.CategoryFilters);

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

    private static RulePackDocument BuildDocument() => new()
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

    private static RuleManagementViewModel CreateViewModel(
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

    private sealed class TestRulePackStore(ActivePointer? active) : IRulePackStore
    {
        public Task<StoreResult> StoreAsync(
            byte[] zipBytes,
            SecurityReview.RulePack.Packaging.RulePackManifest manifest,
            string sha256,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ActivePointer?> GetActiveAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(active);

        public Task SetActiveAsync(
            ActivePointer activePointer,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public bool TryRecoverStaging() => true;
    }

    private sealed class TestErrorSink : IUiErrorSink
    {
        public void Report(string code, string message)
        {
        }
    }

    private sealed class TestRulePackPreviewProvider(
        RulePackDocument? document,
        string? bundledHash) : IRulePackPreviewProvider
    {
        public Task<RulePackDocument?> GetActiveRulesAsync(
            CancellationToken cancellationToken) => Task.FromResult(document);

        public Task<string?> GetBundledBaselineSha256Async(
            CancellationToken cancellationToken) => Task.FromResult(bundledHash);
    }

    private sealed class ThrowingRulePackPreviewProvider : IRulePackPreviewProvider
    {
        public Task<RulePackDocument?> GetActiveRulesAsync(
            CancellationToken cancellationToken) =>
            throw new InvalidDataException("corrupt pack");

        public Task<string?> GetBundledBaselineSha256Async(
            CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }
}
