using SecurityReview.Application.Scans.Preflight;

namespace SecurityReview.UnitTests.Scans;

public sealed class ScanPreflightServiceTests
{
    private static readonly SandboxSelfTestResult PassingSandbox = new(
        true, "ok", new string('a', 64), "26200",
        "S-1-15-2-1-2-3-4-5-6-7", DateTimeOffset.UtcNow);

    private static ScanPreflightService CreateService(
        SandboxSelfTestResult? sandbox = null,
        bool baselineActive = true,
        bool spaceWritable = true,
        bool databaseHealthy = true) =>
        new(new StubSandboxSelfTest(sandbox ?? PassingSandbox),
            new StubSignedBaselineProvider(baselineActive),
            new StubAppDataSpaceProbe(spaceWritable),
            new StubDatabaseHealthCheck(databaseHealthy));

    private static ScanPreflightRequest ValidRoot(out DirectoryInfo root)
    {
        root = Directory.CreateTempSubdirectory("srt-preflight-");
        return new ScanPreflightRequest(root.FullName);
    }

    [Fact]
    public async Task preflight_passes_when_all_checks_pass()
    {
        ScanPreflightRequest request = ValidRoot(out _);
        ScanPreflightResult result = await CreateService()
            .ValidateAsync(request, TestContext.Current.CancellationToken);

        Assert.True(result.CanStart);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task preflight_fails_when_sandbox_self_test_fails()
    {
        ScanPreflightRequest request = ValidRoot(out _);
        var service = CreateService(
            sandbox: SandboxSelfTestResult.Failed("network_denial_failed"));

        ScanPreflightResult result = await service
            .ValidateAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Contains(result.Errors, x => x.Code == "sandbox_unavailable");
    }

    [Fact]
    public async Task preflight_fails_when_root_is_empty()
    {
        ScanPreflightResult result = await CreateService()
            .ValidateAsync(new ScanPreflightRequest(""), TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Contains(result.Errors, x => x.Code == "root_invalid");
    }

    [Fact]
    public async Task preflight_fails_when_root_does_not_exist()
    {
        string missing = Path.Combine(Path.GetTempPath(), "srt-preflight-missing-" + Guid.NewGuid().ToString("N"));
        ScanPreflightResult result = await CreateService()
            .ValidateAsync(new ScanPreflightRequest(missing), TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Contains(result.Errors, x => x.Code == "root_invalid");
    }

    [Fact]
    public async Task preflight_fails_when_baseline_is_inactive()
    {
        ScanPreflightRequest request = ValidRoot(out _);
        ScanPreflightResult result = await CreateService(baselineActive: false)
            .ValidateAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Contains(result.Errors, x => x.Code == "baseline_inactive");
    }

    [Fact]
    public async Task preflight_fails_when_app_data_space_is_not_writable()
    {
        ScanPreflightRequest request = ValidRoot(out _);
        ScanPreflightResult result = await CreateService(spaceWritable: false)
            .ValidateAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Contains(result.Errors, x => x.Code == "app_data_not_writable");
    }

    [Fact]
    public async Task preflight_fails_when_database_is_unhealthy()
    {
        ScanPreflightRequest request = ValidRoot(out _);
        ScanPreflightResult result = await CreateService(databaseHealthy: false)
            .ValidateAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Contains(result.Errors, x => x.Code == "database_unhealthy");
    }

    [Fact]
    public async Task preflight_aggregates_failures_and_reports_stable_codes()
    {
        string missing = Path.Combine(Path.GetTempPath(), "srt-preflight-missing-" + Guid.NewGuid().ToString("N"));
        var service = CreateService(
            sandbox: SandboxSelfTestResult.Failed("job_kill_failed"),
            baselineActive: false,
            spaceWritable: false,
            databaseHealthy: false);

        ScanPreflightResult result = await service
            .ValidateAsync(new ScanPreflightRequest(missing), TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.Equal(
            ["root_invalid", "baseline_inactive", "app_data_not_writable",
                "database_unhealthy", "sandbox_unavailable"],
            result.Errors.Select(x => x.Code).ToArray());
    }

    [Fact]
    public async Task preflight_exposes_no_continue_anyway_path()
    {
        // The result contract carries only CanStart plus errors; there is no
        // override flag for the UI to smuggle a "continue anyway" decision.
        ScanPreflightRequest request = ValidRoot(out _);
        ScanPreflightResult result = await CreateService(
                sandbox: SandboxSelfTestResult.Failed("job_kill_failed"))
            .ValidateAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.CanStart);
        Assert.DoesNotContain(typeof(ScanPreflightResult).GetProperties(),
            property => property.Name.Contains("override", StringComparison.OrdinalIgnoreCase)
                || property.Name.Contains("continue", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class StubSandboxSelfTest(SandboxSelfTestResult result) : ISandboxSelfTest
    {
        public Task<SandboxSelfTestResult> RunAsync(CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }

    private sealed class StubSignedBaselineProvider(bool active) : ISignedBaselineProvider
    {
        public Task<bool> HasActiveSignedBaselineAsync(CancellationToken cancellationToken) =>
            Task.FromResult(active);
    }

    private sealed class StubAppDataSpaceProbe(bool writable) : IAppDataSpaceProbe
    {
        public Task<bool> HasWritableSpaceAsync(CancellationToken cancellationToken) =>
            Task.FromResult(writable);
    }

    private sealed class StubDatabaseHealthCheck(bool healthy) : IDatabaseHealthCheck
    {
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken) =>
            Task.FromResult(healthy);
    }
}

public sealed class SandboxSelfTestCacheTests
{
    private static readonly SandboxSelfTestFingerprint Fingerprint = new(
        new string('a', 64), "26200", "S-1-15-2-1-2-3-4-5-6-7",
        new string('b', 64), new string('c', 64));

    private static SandboxSelfTestResult Success(DateTimeOffset checkedAt) =>
        new(true, "ok", Fingerprint.WorkerSha256, Fingerprint.OsBuild,
            Fingerprint.ProfileSid, checkedAt);

    [Fact]
    public void cache_returns_success_for_matching_fingerprint_within_24_hours()
    {
        var cache = new InMemorySandboxSelfTestCache();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        cache.Write(Fingerprint, Success(now));

        Assert.NotNull(cache.Read(Fingerprint, now.AddHours(23)));
    }

    [Fact]
    public void cache_ignores_entries_older_than_24_hours()
    {
        var cache = new InMemorySandboxSelfTestCache();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        cache.Write(Fingerprint, Success(now));

        Assert.Null(cache.Read(Fingerprint, now.AddHours(24).AddSeconds(1)));
    }

    [Fact]
    public void cache_ignores_entries_with_different_fingerprint()
    {
        var cache = new InMemorySandboxSelfTestCache();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        cache.Write(Fingerprint, Success(now));
        SandboxSelfTestFingerprint changed = Fingerprint with { PolicySha256 = new string('d', 64) };

        Assert.Null(cache.Read(changed, now));
    }

    [Fact]
    public void cache_never_stores_failures_as_success()
    {
        var cache = new InMemorySandboxSelfTestCache();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        cache.Write(Fingerprint, SandboxSelfTestResult.Failed("job_kill_failed"));

        Assert.Null(cache.Read(Fingerprint, now));
    }

    [Fact]
    public void cache_ignores_entries_from_the_future()
    {
        var cache = new InMemorySandboxSelfTestCache();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        cache.Write(Fingerprint, Success(now.AddMinutes(5)));

        Assert.Null(cache.Read(Fingerprint, now));
    }
}
