using SecurityReview.Application.Rules;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.UnitTests.Desktop;

public sealed class RuleManagementViewModelTests
{
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
}
