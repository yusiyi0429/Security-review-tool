using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Infrastructure.Windows;
using SecurityReview.Infrastructure.Windows.Sandbox;

namespace SecurityReview.WindowsSecurityTests.Sandbox;

public sealed class WindowsSandboxSelfTestTests
{
    private static SandboxSelfTestEnvironment CreateEnvironment()
    {
        WindowsSecurityGate.AssertEnabled();
        string staging = Environment.GetEnvironmentVariable(
            WindowsSecurityGate.ProbeWorkerDirectoryVariable)
            ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "WorkerProbe"));
        if (!File.Exists(Path.Combine(staging, "worker-manifest.json")))
        {
            Assert.Fail($"Probe worker staging directory '{staging}' is incomplete.");
        }

        return new SandboxSelfTestEnvironment(staging, "SecurityReview.Worker.exe");
    }

    private static string ExpectedWorkerSha256(SandboxSelfTestEnvironment environment)
    {
        string manifestPath = Path.Combine(environment.WorkerStagingDirectory,
            "worker-manifest.json");
        using JsonDocument manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        return manifest.RootElement.GetProperty("files")
            .GetProperty(environment.WorkerExecutableName).GetString()!;
    }

    [Fact]
    public async Task self_test_passes_and_reports_bound_fingerprint()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        SandboxSelfTestEnvironment environment = CreateEnvironment();
        var launcher = new AppContainerWorkerLauncher();
        var selfTest = new WindowsSandboxSelfTest(launcher, launcher, environment);

        SandboxSelfTestResult result = await selfTest.RunAsync(ct);

        Assert.True(result.Passed, $"self-test failed: {result.Code}");
        Assert.Equal("ok", result.Code);
        Assert.Equal(ExpectedWorkerSha256(environment), result.WorkerSha256);
        Assert.Equal(Environment.OSVersion.Version.Build.ToString(
            System.Globalization.CultureInfo.InvariantCulture), result.OsBuild);
        AppContainerProfileInfo profile = await launcher.PrepareAsync(
            environment.WorkerStagingDirectory, environment.WorkerExecutableName, ct);
        Assert.Equal(profile.SidString, result.ProfileSid);
    }

    [Fact]
    public async Task self_test_success_is_cached_for_matching_fingerprint()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        SandboxSelfTestEnvironment environment = CreateEnvironment();
        var real = new AppContainerWorkerLauncher();
        var counting = new CountingLauncher(real);
        var selfTest = new WindowsSandboxSelfTest(counting, real, environment);

        SandboxSelfTestResult first = await selfTest.RunAsync(ct);
        Assert.True(first.Passed, $"first run failed: {first.Code}");
        int launchesAfterFirst = counting.LaunchCount;
        Assert.True(launchesAfterFirst > 0);

        SandboxSelfTestResult second = await selfTest.RunAsync(ct);
        Assert.True(second.Passed, $"second run failed: {second.Code}");
        Assert.Equal(launchesAfterFirst, counting.LaunchCount);
        Assert.Equal(first.CheckedAtUtc, second.CheckedAtUtc);
    }

    [Fact]
    public async Task self_test_failure_is_never_cached_as_success()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        SandboxSelfTestEnvironment environment = CreateEnvironment();
        var cache = new InMemorySandboxSelfTestCache();
        var real = new AppContainerWorkerLauncher();
        var throwing = new ThrowingLauncher();

        var failing = new WindowsSandboxSelfTest(throwing, real, environment, cache);
        SandboxSelfTestResult failed = await failing.RunAsync(ct);
        Assert.False(failed.Passed);

        var passing = new WindowsSandboxSelfTest(real, real, environment, cache);
        SandboxSelfTestResult passed = await passing.RunAsync(ct);
        Assert.True(passed.Passed, $"run after failure failed: {passed.Code}");
        Assert.Equal("ok", passed.Code);
    }

    [Fact]
    public async Task self_test_failure_never_falls_back_to_unsandboxed_launch()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        SandboxSelfTestEnvironment environment = CreateEnvironment();
        var real = new AppContainerWorkerLauncher();
        var throwing = new ThrowingLauncher();
        var selfTest = new WindowsSandboxSelfTest(throwing, real, environment);

        SandboxSelfTestResult first = await selfTest.RunAsync(ct);
        Assert.False(first.Passed);
        Assert.Single(throwing.Requests);

        // A failure is not cached: a second run attempts the sandboxed launch
        // again instead of reporting a stale success or switching launchers.
        SandboxSelfTestResult second = await selfTest.RunAsync(ct);
        Assert.False(second.Passed);
        Assert.Equal(2, throwing.Requests.Count);
        Assert.All(throwing.Requests,
            request => Assert.Equal("SecurityReview.Worker.exe", request.WorkerExecutableName));
    }

    private sealed class CountingLauncher(IWorkerLauncher inner) : IWorkerLauncher
    {
        public int LaunchCount { get; private set; }

        public async Task<SandboxedWorkerProcess> LaunchAsync(WorkerLaunchRequest request,
            CancellationToken cancellationToken)
        {
            LaunchCount++;
            return await inner.LaunchAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class ThrowingLauncher : IWorkerLauncher
    {
        public List<WorkerLaunchRequest> Requests { get; } = [];

        public Task<SandboxedWorkerProcess> LaunchAsync(WorkerLaunchRequest request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            throw new WindowsSecurityException("CreateProcessW", 5);
        }
    }
}
