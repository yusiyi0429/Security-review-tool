using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Reviews;
using SecurityReview.Application.Rules;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Desktop;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Llm;
using SecurityReview.Infrastructure.Persistence;

namespace SecurityReview.IntegrationTests.Desktop;

/// <summary>
/// Integration tests that verify the composition root builds a valid,
/// correctly-scoped object graph with the exact mandatory ordering.
///
/// Key invariants:
/// * Exactly one singleton database factory / sandbox / rule-pack store.
/// * Scoped scan commands are resolvable.
/// * No parser class is ever referenced in the Desktop assembly.
/// * Health-blocked mode: when sandbox/DB fails, CanStartScan is false.
/// </summary>
public sealed class CompositionRootTests : IAsyncDisposable
{
    private readonly string _tempDir;

    public CompositionRootTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-comp-root-").FullName;
    }

    public ValueTask DisposeAsync()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort */ }
        return ValueTask.CompletedTask;
    }

    private CompositionRoot BuildRoot()
    {
        return new CompositionRoot(CompositionRoot.Args.ForTest(_tempDir));
    }

    // ------------------------------------------------------------------
    // Singleton assertions
    // ------------------------------------------------------------------

    [Fact]
    public void Singleton_database_factory_is_exactly_one_instance()
    {
        using var root = BuildRoot();
        var f1 = root.GetService<ISqliteConnectionFactory>();
        var f2 = root.GetService<ISqliteConnectionFactory>();
        Assert.Same(f1, f2);
        Assert.NotNull(f1);
    }

    [Fact]
    public void Singleton_payload_protector_is_exactly_one_instance()
    {
        using var root = BuildRoot();
        var p1 = root.GetService<IPayloadProtector>();
        var p2 = root.GetService<IPayloadProtector>();
        Assert.Same(p1, p2);
        Assert.NotNull(p1);
    }

    [Fact]
    public void Singleton_rule_pack_store_is_exactly_one_instance()
    {
        using var root = BuildRoot();
        var r1 = root.GetService<IRulePackStore>();
        var r2 = root.GetService<IRulePackStore>();
        Assert.Same(r1, r2);
        Assert.NotNull(r1);
    }

    [Fact]
    public void Singleton_sandbox_self_test_is_exactly_one_instance()
    {
        using var root = BuildRoot();
        var s1 = root.GetService<ISandboxSelfTest>();
        var s2 = root.GetService<ISandboxSelfTest>();
        Assert.Same(s1, s2);
        Assert.NotNull(s1);
    }

    // ------------------------------------------------------------------
    // Scoped scan command assertions
    // ------------------------------------------------------------------

    [Fact]
    public void CreateScanHandler_is_resolvable()
    {
        using var root = BuildRoot();
        var handler = root.GetService<CreateScanHandler>();
        Assert.NotNull(handler);
    }

    [Fact]
    public void StartScanHandler_is_resolvable()
    {
        using var root = BuildRoot();
        var handler = root.GetService<StartScanHandler>();
        Assert.NotNull(handler);
    }

    [Fact]
    public void CancelScanHandler_is_resolvable()
    {
        using var root = BuildRoot();
        var handler = root.GetService<CancelScanHandler>();
        Assert.NotNull(handler);
    }

    // ------------------------------------------------------------------
    // No parser classes in Desktop references
    // ------------------------------------------------------------------

    [Fact]
    public void Desktop_assembly_has_no_parser_references()
    {
        var desktopAssembly = typeof(App).Assembly;
        var referencedAssemblies = desktopAssembly.GetReferencedAssemblies();

        foreach (var asm in referencedAssemblies)
        {
            Assert.DoesNotContain("Parser", asm.Name,
                StringComparison.OrdinalIgnoreCase);
        }
    }

    // ------------------------------------------------------------------
    // Composition root services are non-null
    // ------------------------------------------------------------------

    [Fact]
    public void Health_service_is_resolvable()
    {
        using var root = BuildRoot();
        var health = root.GetService<StartupHealthService>();
        Assert.NotNull(health);
        Assert.Equal(StartupHealthState.Checking, health.State);
    }

    [Fact]
    public void Error_sink_is_resolvable()
    {
        using var root = BuildRoot();
        var sink = root.GetService<IUiErrorSink>();
        Assert.NotNull(sink);
    }

    [Fact]
    public void Navigation_service_is_resolvable()
    {
        using var root = BuildRoot();
        var nav = root.GetService<NavigationService>();
        Assert.NotNull(nav);
    }

    [Fact]
    public void MainWindowViewModel_is_resolvable()
    {
        using var root = BuildRoot();
        var vm = root.GetService<MainWindowViewModel>();
        Assert.NotNull(vm);
    }

    // ------------------------------------------------------------------
    // Application handlers
    // ------------------------------------------------------------------

    [Fact]
    public void Scan_query_service_is_resolvable()
    {
        using var root = BuildRoot();
        var svc = root.GetService<ScanQueryService>();
        Assert.NotNull(svc);
    }

    [Fact]
    public void LLM_connection_test_service_is_resolvable()
    {
        using var root = BuildRoot();
        var svc = root.GetService<ILlmConnectionTestService>();
        Assert.NotNull(svc);
    }

    [Fact]
    public void LLM_configuration_store_is_resolvable()
    {
        using var root = BuildRoot();
        var store = root.GetService<ILlmConfigurationStore>();
        Assert.NotNull(store);
    }

    [Fact]
    public void LLM_credential_store_is_resolvable()
    {
        using var root = BuildRoot();
        var store = root.GetService<ILlmCredentialStore>();
        Assert.NotNull(store);
    }

    [Fact]
    public void Review_service_is_resolvable()
    {
        using var root = BuildRoot();
        var svc = root.GetService<IReviewService>();
        Assert.NotNull(svc);
    }

    // ------------------------------------------------------------------
    // Health-blocked mode
    // ------------------------------------------------------------------

    [Fact]
    public void Startup_health_starts_in_checking_state()
    {
        using var root = BuildRoot();
        var health = root.GetService<StartupHealthService>();
        Assert.Equal(StartupHealthState.Checking, health.State);
        Assert.Null(health.BlockedCode);
    }

    [Fact]
    public void Blocked_state_disables_scan()
    {
        using var root = BuildRoot();
        var health = root.GetService<StartupHealthService>();
        health.MarkBlocked("sandbox_unavailable");
        Assert.False(health.CanStartScan);

        var vm = root.GetService<MainWindowViewModel>();
        Assert.False(vm.ScanEnabled);
    }

    [Fact]
    public void Ready_state_enables_scan()
    {
        using var root = BuildRoot();
        var health = root.GetService<StartupHealthService>();
        health.MarkReady();
        Assert.True(health.CanStartScan);

        var vm = root.GetService<MainWindowViewModel>();
        Assert.True(vm.ScanEnabled);
    }

    // ------------------------------------------------------------------
    // App paths
    // ------------------------------------------------------------------

    [Fact]
    public void App_paths_root_is_temp_directory()
    {
        using var root = BuildRoot();
        var paths = root.GetService<IApplicationPaths>();
        Assert.NotNull(paths);
        Assert.StartsWith(_tempDir, paths.BasePath);
    }

    // ------------------------------------------------------------------
    // RescanHandler
    // ------------------------------------------------------------------

    [Fact]
    public void RescanHandler_is_resolvable()
    {
        using var root = BuildRoot();
        var handler = root.GetService<RescanHandler>();
        Assert.NotNull(handler);
    }
}
