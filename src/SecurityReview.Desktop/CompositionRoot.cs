using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Caching;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.History;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Reviews;
using SecurityReview.Application.Rules;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Diagnostics;
using SecurityReview.Infrastructure.Llm;
using SecurityReview.Infrastructure.Manifest;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;
using SecurityReview.Infrastructure.Rules;
using SecurityReview.Infrastructure.Windows.Files;
using SecurityReview.Infrastructure.Windows.Identity;
using SecurityReview.Infrastructure.Windows.Sandbox;
using SecurityReview.RulePack.Signing;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.Desktop;

/// <summary>
/// Manual composition root for the desktop process.
/// Builds the full object graph in the exact mandatory order:
///
/// 1. App paths
/// 2. Startup recovery / SQLite factory
/// 3. Keyring / crypto
/// 4. Repositories
/// 5. Rule store / policy
/// 6. Sandbox / worker
/// 7. LLM adapters
/// 8. Application handlers / query
/// 9. View models / UI services
///
/// When keyring, DB, or sandbox is blocked, the shell opens in
/// health-blocked mode with scan disabled. No unsandboxed parser
/// path is ever constructed.
///
/// No DI/MVVM package — manual singleton management.
/// </summary>
public sealed class CompositionRoot : IDisposable
{
    private readonly ConcurrentDictionary<Type, object> _services = new();
    private readonly ConcurrentDictionary<Type, object> _concrete = new();
    private bool _disposed;

    public sealed record Args(
        string AppDataBasePath,
        bool IsTest = false,
        string? SandboxStagingDirectory = null,
        string? WorkerExecutableName = null)
    {
        public static Args ForProduction()
        {
            return new Args(System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecurityReviewTool"));
        }

        public static Args ForTest(string tempDir)
        {
            return new Args(tempDir, IsTest: true);
        }
    }

    private readonly Args _args;

    public CompositionRoot(Args args)
    {
        _args = args ?? throw new ArgumentNullException(nameof(args));
        Build();
    }

    private void Build()
    {
        // --- Step 1: App paths ---
        AppDataPaths paths = _args.IsTest
            ? AppDataPaths.CreateForTest(_args.AppDataBasePath)
            : AppDataPaths.CreateDefault();
        paths.EnsureCreated();
        Register<IApplicationPaths>(paths);
        RegisterConcrete(paths);

        var diagSink = new Infrastructure.Diagnostics.RedactedJsonlDiagnosticSink(
            paths.Diagnostics, "diagnostics");
        Register<IDiagnosticSink>(diagSink);
        RegisterConcrete(diagSink);

        // --- Step 2: SQLite connection factory ---
        var connectionFactory = new SqliteConnectionFactory(paths);
        Register<ISqliteConnectionFactory>(connectionFactory);
        RegisterConcrete(connectionFactory);

        bool databaseOk;
        try
        {
            var migrations = new MigrationRunner(
                connectionFactory,
                DefaultMigrations.Create(),
                paths);
            MigrationResult result = migrations.MigrateAsync()
                .GetAwaiter().GetResult();
            databaseOk = result.Success;
            if (!databaseOk)
                Health.MarkBlocked("database_migration_failed");
        }
        catch
        {
            databaseOk = false;
            Health.MarkBlocked("database_migration_failed");
        }

        // --- Step 3: Keyring / crypto ---
        WindowsDpapiKeyRing? keyring = null;
        HkdfSha256? hkdf = null;
        bool cryptoOk = true;

        if (_args.IsTest)
        {
            byte[] masterKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(masterKey);
            hkdf = new HkdfSha256(masterKey);
            var testProtector = new AesGcmPayloadProtector(hkdf.DeriveEncryptionKey(), "test-key");
            var testFp = new PersistentValueFingerprintService(hkdf.DeriveFingerprintKey());
            var testSecrets = new WindowsDpapiSecretStore(
                System.IO.Path.Combine(_args.AppDataBasePath, "secrets"));

            Register<IPayloadProtector>(testProtector);
            RegisterConcrete(testProtector);
            Register<IValueFingerprintService>(testFp);
            RegisterConcrete(testFp);
            Register<ISecretStore>(testSecrets);
            RegisterConcrete(testSecrets);
        }
        else
        {
            try
            {
                keyring = WindowsDpapiKeyRing.LoadOrCreate(paths);
                hkdf = keyring.Hkdf;
                var prodProtector = new AesGcmPayloadProtector(hkdf.DeriveEncryptionKey(), keyring.KeyId);
                var prodFp = new PersistentValueFingerprintService(hkdf.DeriveFingerprintKey());
                var prodSecrets = new WindowsDpapiSecretStore(paths);

                Register<IPayloadProtector>(prodProtector);
                RegisterConcrete(prodProtector);
                Register<IValueFingerprintService>(prodFp);
                RegisterConcrete(prodFp);
                Register<ISecretStore>(prodSecrets);
                RegisterConcrete(prodSecrets);
                RegisterConcrete(keyring);
            }
            catch
            {
                cryptoOk = false;
                Health.MarkBlocked("keyring_unavailable");
            }
        }

        // --- Step 4: Repositories ---
        // Correct constructors per the real implementations.
        IPayloadProtector? protector = TryGet<IPayloadProtector>();
        IValueFingerprintService? fp = TryGet<IValueFingerprintService>();

        if (databaseOk && protector is not null && fp is not null)
        {
            // SqliteScanRepository(ISqliteConnectionFactory, IPayloadProtector)
            Register<IScanRepository>(
                new SqliteScanRepository(connectionFactory, protector));

            // SqliteScanSnapshotRepository(ISqliteConnectionFactory) — 1 param
            Register<IScanSnapshotRepository>(
                new SqliteScanSnapshotRepository(connectionFactory));
            Register<IScanCreationRepository>(
                new SqliteScanCreationRepository(connectionFactory, protector));

            // SqliteFindingRepository(ISqliteConnectionFactory, IPayloadProtector, IValueFingerprintService)
            Register<IFindingRepository>(
                new SqliteFindingRepository(connectionFactory, protector, fp));

            // SqliteCoverageRepository(ISqliteConnectionFactory, IPayloadProtector)
            Register<ICoverageRepository>(
                new SqliteCoverageRepository(connectionFactory, protector));

            // SqliteFileRepository(ISqliteConnectionFactory, IPayloadProtector, IValueFingerprintService)
            Register<IFileRepository>(
                new SqliteFileRepository(connectionFactory, protector, fp));

            // SqliteCacheRepository(ISqliteConnectionFactory) — 1 param
            var cacheRepository = new SqliteCacheRepository(connectionFactory);
            Register<ICacheRepository>(cacheRepository);
            RegisterConcrete(cacheRepository);
            var cacheCoordinator = new CacheCoordinator(
                cacheRepository,
                protector,
                new FileSystemDiskCapacityProvider(paths.Data));
            RegisterConcrete(cacheCoordinator);

            // SqliteReviewRepository(ISqliteConnectionFactory, IPayloadProtector)
            Register<IReviewRepository>(
                new SqliteReviewRepository(connectionFactory, protector));

            // SqliteLlmReviewRepository(ISqliteConnectionFactory, IPayloadProtector)
            var llmRepository = new SqliteLlmReviewRepository(
                connectionFactory, protector);
            Register<ILlmAttemptRepository>(llmRepository);
            Register<ISemanticReviewPersister>(llmRepository);
            RegisterConcrete(llmRepository);

            // SqliteRulePackMetadataRepository(ISqliteConnectionFactory) — 1 param
            Register<IRulePackMetadataRepository>(
                new SqliteRulePackMetadataRepository(connectionFactory));

            var maintenance = new SqliteMaintenanceService(connectionFactory);
            Register<IDatabaseMaintenanceService>(maintenance);
            RegisterConcrete(maintenance);
        }

        // --- Step 5: Rule store ---
        var ruleStore = new FileRulePackStore(paths.Rules);
        Register<IRulePackStore>(ruleStore);
        RegisterConcrete(ruleStore);
        var ruleRuntimeProvider = new ActiveRulePackRuntimeProvider(ruleStore);
        RegisterConcrete(ruleRuntimeProvider);
        Register<IEffectivePolicyProvider>(ruleRuntimeProvider);
        var ruleDetectionPipeline = new RulePackDetectionPipelineAdapter(
            ruleRuntimeProvider);
        Register<IDetectionPipeline>(ruleDetectionPipeline);
        RegisterConcrete(ruleDetectionPipeline);

        string signerStorePath = System.IO.Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            "rules",
            "trusted-signers.json");
        string signerStoreJson = File.Exists(signerStorePath)
            ? File.ReadAllText(signerStorePath)
            : """{"signers":[]}""";
        var signerStore = TrustedSignerStore.Load(signerStoreJson);
        RegisterConcrete(signerStore);
        var ruleValidator = new RulePackageValidator();
        Register<IRulePackValidator>(ruleValidator);
        RegisterConcrete(ruleValidator);
        var ruleImportService = new RulePackImportService(
            ruleValidator,
            ruleStore,
            ruleRuntimeProvider,
            signerStore,
            typeof(CompositionRoot).Assembly.GetName().Version?.ToString(3)
                ?? "0.0.0");
        RegisterConcrete(ruleImportService);
        EnsureBundledBaselineIsActive(
            ruleStore,
            ruleRuntimeProvider,
            ruleImportService);

        // --- Step 6: Sandbox / worker ---
        if (!_args.IsTest)
        {
            try
            {
                string staging = _args.SandboxStagingDirectory
                    ?? System.IO.Path.Combine(AppContext.BaseDirectory, "worker");
                string workerExe = _args.WorkerExecutableName ?? "SecurityReview.Worker.exe";

                var launcher = new AppContainerWorkerLauncher(
                    new SandboxLaunchOptions(), diagnostics: TryGet<IDiagnosticSink>());
                var selfTest = new WindowsSandboxSelfTest(
                    launcher, launcher,
                    new SandboxSelfTestEnvironment(staging, workerExe));
                Register<IWorkerLauncher>(launcher);
                Register<IWorkerJobProcessor>(new SandboxWorkerJobProcessor(
                    launcher, staging, workerExe));
                Register<ISandboxSelfTest>(selfTest);
                RegisterConcrete(selfTest);
            }
            catch
            {
                Health.MarkBlocked("sandbox_unavailable");
            }
        }
        else
        {
            var stub = new StubSandboxSelfTest();
            Register<ISandboxSelfTest>(stub);
            RegisterConcrete(stub);
        }

        // --- Step 7: LLM adapters ---
        ISandboxSelfTest? sandbox = TryGet<ISandboxSelfTest>();
        if (cryptoOk)
        {
            ISecretStore? secrets = TryGet<ISecretStore>();
            if (secrets is not null)
            {
                var llmCredentials = new LlmCredentialStore(secrets);
                Register<ILlmCredentialStore>(llmCredentials);
                RegisterConcrete(llmCredentials);

                if (fp is not null)
                {
                    var llmConfig = new JsonLlmConfigurationStore(paths, secrets, fp);
                    Register<ILlmConfigurationStore>(llmConfig);
                    RegisterConcrete(llmConfig);
                }

                var llmTest = new LlmConnectionTestService(llmCredentials, diagSink);
                Register<ILlmConnectionTestService>(llmTest);

                // OpenAiSemanticReviewer requires HttpEndpoint, HttpClient etc —
                // we defer full composition until LLM configuration is set.
            }
        }

        // --- Step 8: Application handlers / query ---
        IScanRepository? sr = TryGet<IScanRepository>();
        IScanSnapshotRepository? ssr = TryGet<IScanSnapshotRepository>();

        if (sr is not null && ssr is not null && protector is not null)
        {
            var createScan = new CreateScanHandler(
                sr,
                ssr,
                protector,
                creationRepository: TryGet<IScanCreationRepository>());
            RegisterConcrete(createScan);

            if (sandbox is not null)
            {
                var preflight = new ScanPreflightService(
                    sandbox,
                    _args.IsTest
                        ? new StubBaselineProvider()
                        : new ActiveRulePackBaselineProvider(ruleRuntimeProvider),
                    _args.IsTest
                        ? new StubSpaceProbe()
                        : new AppDataSpaceProbe(paths.Data),
                    _args.IsTest
                        ? new StubDbHealthCheck()
                        : new SqliteDatabaseHealthCheck(connectionFactory));
                RegisterConcrete(preflight);
                var startScan = new StartScanHandler(sr, ssr, preflight, protector);
                RegisterConcrete(startScan);

                var cancelScan = new CancelScanHandler(sr);
                RegisterConcrete(cancelScan);

                var rescan = new RescanHandler(sr, createScan);
                RegisterConcrete(rescan);
            }

            // ReviewService needs IReviewRepository, IPayloadProtector,
            // IValueFingerprintService, IWindowsIdentityProvider.
            IReviewRepository? rr = TryGet<IReviewRepository>();
            IValueFingerprintService? fpSvc = TryGet<IValueFingerprintService>();

            if (rr is not null && fpSvc is not null)
            {
                IWindowsIdentityProvider identityProvider = _args.IsTest
                    ? new StubWindowsIdentityProvider()
                    : new WindowsIdentityProvider();
                var reviewSvc = new ReviewService(rr, protector, fpSvc, identityProvider);
                Register<IReviewService>(reviewSvc);

                IFindingRepository? fr = TryGet<IFindingRepository>();
                ICoverageRepository? cr = TryGet<ICoverageRepository>();
                IFileRepository? flr = TryGet<IFileRepository>();

                if (fr is not null && cr is not null && flr is not null)
                {
                    var scanQuery = new ScanQueryService(sr, fr, cr, flr, reviewSvc);
                    RegisterConcrete(scanQuery);

                    if (!_args.IsTest
                        && TryGet<IWorkerJobProcessor>() is { } processor
                        && TryGet<IDetectionPipeline>() is { } detectionPipeline
                        && TryGet<IDiagnosticSink>() is { } diagnostics
                        && TryGet<ScanPreflightService>() is { } scanPreflight)
                    {
                        var orchestratorState = new ScanOrchestratorState();
                        RegisterConcrete(orchestratorState);
                        var orchestrator = new ScanOrchestrator(
                            new WindowsInventoryService(),
                            sr,
                            scanPreflight,
                            new JsonManifestReader(),
                            processor,
                            detectionPipeline,
                            fr,
                            cr,
                            flr,
                            CreateSemanticReviewQueue,
                            diagnostics,
                            orchestratorState,
                            fileSnapshotService: new WindowsFileSnapshotService());
                        Register<IScanOrchestrator>(orchestrator);
                        RegisterConcrete(orchestrator);
                    }
                }
            }

            if (TryGet<IDatabaseMaintenanceService>() is { } maintenance)
            {
                var retention = new RetentionService(sr, maintenance);
                RegisterConcrete(retention);
            }
        }

        // --- Step 9: View models & UI services ---
        RegisterConcrete(Health);
        Register<IUiErrorSink>(ErrorSink);
        RegisterConcrete(ErrorSink);
        RegisterConcrete(NavigationService);
        RegisterConcrete(MainWindowViewModel);

        // Register UI services
        var safePreviewService = new Services.SafePreviewService();
        RegisterConcrete(safePreviewService);
        Register<IScanTargetPicker>(new WpfScanTargetPicker());

        var explorerService = new Services.ExplorerService(
            path => true); // Warning dialog will be shown by the ViewModel
        RegisterConcrete(explorerService);
    }

    private void EnsureBundledBaselineIsActive(
        FileRulePackStore ruleStore,
        ActiveRulePackRuntimeProvider runtimeProvider,
        RulePackImportService importService)
    {
        try
        {
            ActivePointer? active = ruleStore
                .GetActiveAsync(CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            if (active is not null)
            {
                try
                {
                    ActiveRulePackRuntime? runtime = runtimeProvider
                        .GetActiveAsync(CancellationToken.None)
                        .GetAwaiter()
                        .GetResult();
                    if (runtime is not null)
                        return;
                }
                catch (Exception ex) when (ex is IOException
                    or InvalidDataException
                    or InvalidOperationException
                    or UnauthorizedAccessException)
                {
                    // A stale/corrupt active pointer must not permanently
                    // disable scanning. The signed bundled package below is
                    // revalidated before it can replace the pointer.
                }
            }

            string bundledPath = System.IO.Path.Combine(
                AppContext.BaseDirectory,
                "Assets",
                "rules",
                "default-rule-pack.zip");
            if (!File.Exists(bundledPath))
            {
                ErrorSink.Report(
                    "bundled_rule_pack_missing",
                    "内置基线规则包缺失，请重新安装完整的应用程序。");
                return;
            }

            byte[] packageBytes = File.ReadAllBytes(bundledPath);
            ImportResult result = importService
                .ImportAsync(
                    new ImportRulePackCommand
                    {
                        ZipBytes = packageBytes,
                        AllowDowngrade = active is not null,
                    },
                    CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            if (!result.Success)
            {
                ErrorSink.Report(
                    "bundled_rule_pack_invalid",
                    "内置基线规则包无法通过完整性校验，请重新安装应用程序。");
            }
        }
        catch (Exception)
        {
            ErrorSink.Report(
                "bundled_rule_pack_activation_failed",
                "内置基线规则包激活失败，请查看诊断信息。");
        }
    }

    // ------------------------------------------------------------------ Service resolution

    public T GetService<T>() where T : class
    {
        Type key = typeof(T);
        if (_services.TryGetValue(key, out var value))
            return (T)value;
        if (_concrete.TryGetValue(key, out var concrete))
            return (T)concrete;
        throw new InvalidOperationException(
            $"Service of type {key.Name} is not registered in the composition root.");
    }

    // ------------------------------------------------------------------ Registration

    private void Register<T>(T instance) where T : class
    {
        _services[typeof(T)] = instance;
    }

    private void RegisterConcrete<T>(T instance) where T : class
    {
        _concrete[typeof(T)] = instance;
    }

    private T? TryGet<T>() where T : class
    {
        if (_services.TryGetValue(typeof(T), out var value))
            return (T)value;
        if (_concrete.TryGetValue(typeof(T), out var concrete))
            return (T)concrete;
        return null;
    }

    // ------------------------------------------------------------------ Pre-built UI services

    private readonly Lazy<StartupHealthService> _healthLazy = new(() => new StartupHealthService());
    private readonly Lazy<UiErrorSink> _errorSinkLazy = new(() => new UiErrorSink());
    private readonly Lazy<Services.NavigationService> _navLazy = new(() => new Services.NavigationService());

    public StartupHealthService Health => _healthLazy.Value;
    public UiErrorSink ErrorSink => _errorSinkLazy.Value;
    public Services.NavigationService NavigationService => _navLazy.Value;

    private MainWindowViewModel? _mainWindowViewModel;

    public MainWindowViewModel MainWindowViewModel
        => _mainWindowViewModel ??= new(NavigationService, Health, ErrorSink);

    // ------------------------------------------------------------------ ViewModel factories (lazy, re-created on navigation)

    public NewScanViewModel GetNewScanViewModel()
    {
        var createHandler = TryGet<CreateScanHandler>();
        var startHandler = TryGet<StartScanHandler>();
        var targetPicker = TryGet<IScanTargetPicker>();
        var ruleRuntimeProvider = TryGet<ActiveRulePackRuntimeProvider>();
        var sandbox = TryGet<ISandboxSelfTest>();
        return new NewScanViewModel(
            ErrorSink,
            createHandler is not null ? () => createHandler : null!,
            startHandler is not null ? () => startHandler : null!,
            targetPicker,
            ruleRuntimeProvider,
            sandbox,
            Health,
            TryGet<ILlmConfigurationStore>(),
            new JsonManifestReader(),
            TryGet<ILlmCredentialStore>());
    }

    public ScanProgressViewModel GetScanProgressViewModel(ScanId scanId)
    {
        var cancelHandler = TryGet<CancelScanHandler>();
        return new ScanProgressViewModel(
            ErrorSink,
            cancelHandler is not null ? () => cancelHandler : null!)
        {
            ScanId = scanId.Value.ToString("D"),
            Stage = ScanStage.Preflight,
        };
    }

    private ISemanticReviewQueue CreateSemanticReviewQueue()
    {
        ILlmConfigurationStore? configuration = TryGet<ILlmConfigurationStore>();
        ILlmCredentialStore? credentials = TryGet<ILlmCredentialStore>();
        IValueFingerprintService? fingerprints = TryGet<IValueFingerprintService>();
        CacheCoordinator? cache = TryGet<CacheCoordinator>();
        ILlmAttemptRepository? attempts = TryGet<ILlmAttemptRepository>();
        ISemanticReviewPersister? persister = TryGet<ISemanticReviewPersister>();
        IDiagnosticSink? diagnostics = TryGet<IDiagnosticSink>();
        if (configuration is null || credentials is null || fingerprints is null
            || cache is null || attempts is null || persister is null
            || diagnostics is null)
        {
            return new UnavailableSemanticReviewQueue();
        }

        try
        {
            LlmEndpointOptions? options = configuration
                .LoadAsync(CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            if (options is null)
            {
                return new UnavailableSemanticReviewQueue();
            }

            bool credentialReady = options.AuthMode == LlmAuthMode.None
                || options.CredentialReference is { Length: > 0 } reference
                && credentials.HasCredential(reference);
            if (!credentialReady)
            {
                return new UnavailableSemanticReviewQueue();
            }

            HttpClient client = OpenAiHttpClientFactory.Create(options, credentials);
            var reviewer = new OpenAiSemanticReviewer(
                options,
                fingerprints,
                client,
                cache,
                attempts,
                diagnostics,
                ownsHttpClient: true,
                credentialStore: credentials);
            return new SemanticReviewQueue(
                new SemanticReviewQueueOptions
                {
                    MaxConsumerCount = options.MaxConcurrency,
                    ReviewDeadline = options.Timeout,
                },
                reviewer,
                new AlwaysCurrentSemanticCandidateLifetime(),
                persister,
                new NullSemanticReviewProgressSink());
        }
        catch (Exception ex) when (ex is IOException
            or InvalidDataException
            or InvalidOperationException
            or UnauthorizedAccessException)
        {
            return new UnavailableSemanticReviewQueue();
        }
    }

    public async Task InitializeRuntimeAsync(
        CancellationToken cancellationToken = default)
    {
        await RefreshShellStatusAsync(cancellationToken);

        if (Health.State == StartupHealthState.Blocked)
        {
            return;
        }

        ISandboxSelfTest? sandbox = TryGet<ISandboxSelfTest>();
        if (sandbox is null)
        {
            Health.MarkBlocked(PreflightErrorCodes.SandboxUnavailable);
            return;
        }

        SandboxSelfTestResult result = await sandbox
            .RunAsync(cancellationToken);
        Health.SetDiagnostics(result.OsBuild, result.WorkerSha256);
        if (result.Passed)
        {
            Health.MarkReady();
        }
        else
        {
            Health.MarkBlocked(result.Code);
        }

        await RefreshShellStatusAsync(cancellationToken);
    }

    public async Task RefreshShellStatusAsync(
        CancellationToken cancellationToken = default)
    {
        MainWindowViewModel.AppVersion =
            typeof(CompositionRoot).Assembly.GetName().Version?.ToString(3)
            ?? "0.0.0";

        ActiveRulePackRuntimeProvider? ruleProvider =
            TryGet<ActiveRulePackRuntimeProvider>();
        try
        {
            ActiveRulePackRuntime? active = ruleProvider is null
                ? null
                : await ruleProvider
                    .GetActiveAsync(cancellationToken)
                    .ConfigureAwait(true);
            MainWindowViewModel.RulePackageVersion =
                active?.Active.Version ?? "未配置";
        }
        catch (Exception)
        {
            MainWindowViewModel.RulePackageVersion = "不可用";
        }

        ILlmConfigurationStore? configStore = TryGet<ILlmConfigurationStore>();
        if (configStore is null)
        {
            MainWindowViewModel.LlmState = "不可用";
            return;
        }

        try
        {
            LlmEndpointOptions? options = await configStore
                .LoadAsync(cancellationToken)
                .ConfigureAwait(true);
            if (options is null)
            {
                MainWindowViewModel.LlmState = "未配置";
                return;
            }

            bool credentialReady = options.AuthMode == LlmAuthMode.None
                || (options.CredentialReference is { Length: > 0 } reference
                    && TryGet<ILlmCredentialStore>()?.HasCredential(reference) == true);
            MainWindowViewModel.LlmState =
                credentialReady ? "已配置" : "凭据缺失";
        }
        catch (Exception)
        {
            MainWindowViewModel.LlmState = "加载失败";
        }
    }

    public HistoryViewModel GetHistoryViewModel()
    {
        var query = TryGet<ScanQueryService>();
        var rescan = TryGet<RescanHandler>();
        var retention = TryGet<RetentionService>();
        return new HistoryViewModel(
            query is not null ? () => query : null!,
            rescan is not null ? () => rescan : null!,
            retention is not null ? () => retention : null!,
            ErrorSink);
    }

    public RuleManagementViewModel GetRuleManagementViewModel()
    {
        var importSvc = TryGet<RulePackImportService>();
        var ruleStore = TryGet<IRulePackStore>();
        return new RuleManagementViewModel(
            importSvc is not null ? () => importSvc : null!,
            ErrorSink,
            ruleStore is not null ? () => ruleStore : null,
            () => RefreshShellStatusAsync());
    }

    public LlmSettingsViewModel GetLlmSettingsViewModel()
    {
        var configStore = TryGet<ILlmConfigurationStore>();
        var testSvc = TryGet<ILlmConnectionTestService>();
        var credentialStore = TryGet<ILlmCredentialStore>();
        return new LlmSettingsViewModel(
            configStore ?? new NullLlmConfigStore(),
            testSvc ?? new NullLlmTestService(),
            credentialStore ?? new NullLlmCredentialStore(),
            ErrorSink,
            () => RefreshShellStatusAsync(),
            TryGet<ICacheRepository>());
    }

    public CoverageViewModel GetCoverageViewModel()
    {
        var query = TryGet<ScanQueryService>();
        return new CoverageViewModel(
            ErrorSink,
            query is not null ? () => query : null!);
    }

    public ScanResultsViewModel GetScanResultsViewModel()
    {
        var query = TryGet<ScanQueryService>();
        return new ScanResultsViewModel(
            ErrorSink,
            query is not null ? () => query : null!);
    }

    // ------------------------------------------------------------------ IDisposable

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        ISqliteConnectionFactory? connectionFactory =
            TryGet<ISqliteConnectionFactory>();

        foreach (var kvp in _concrete)
        {
            if (kvp.Value is IDisposable d && kvp.Value != this)
            {
                try { d.Dispose(); } catch { }
            }
        }
        foreach (var kvp in _services)
        {
            if (kvp.Value is IDisposable d && kvp.Value != this)
            {
                try { d.Dispose(); } catch { }
            }
        }

        connectionFactory?.ClearPools();

        _services.Clear();
        _concrete.Clear();
    }
}

// ----------------------------------------------------------------------
// Default error sink
// ----------------------------------------------------------------------

public sealed class UiErrorSink : IUiErrorSink
{
    private const int MaxEntries = 20;
    private readonly List<UiErrorEntry> _entries = new(MaxEntries);
    private readonly object _gate = new();

    public event Action<UiErrorEntry>? ErrorReported;

    public void Report(string code, string message)
    {
        var entry = new UiErrorEntry(code, message, DateTimeOffset.UtcNow);
        lock (_gate)
        {
            if (_entries.Count >= MaxEntries)
                _entries.RemoveAt(0);
            _entries.Add(entry);
        }
        ErrorReported?.Invoke(entry);
    }

    public IReadOnlyList<UiErrorEntry> Recent => _entries.AsReadOnly();
}

public sealed record UiErrorEntry(string Code, string Message, DateTimeOffset TimestampUtc);

// ----------------------------------------------------------------------
// Test stubs
// ----------------------------------------------------------------------

file sealed class StubSandboxSelfTest : ISandboxSelfTest
{
    public Task<SandboxSelfTestResult> RunAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult(new SandboxSelfTestResult(
            true, SandboxSelfTestResult.OkCode,
            "0000000000000000000000000000000000000000000000000000000000000000",
            Environment.OSVersion.VersionString,
            "S-1-0-0", DateTimeOffset.UtcNow));
    }
}

file sealed class StubBaselineProvider : ISignedBaselineProvider
{
    public Task<bool> HasActiveSignedBaselineAsync(CancellationToken cancellationToken)
        => Task.FromResult(true);
}

file sealed class StubSpaceProbe : IAppDataSpaceProbe
{
    public Task<bool> HasWritableSpaceAsync(CancellationToken cancellationToken)
        => Task.FromResult(true);
}

file sealed class StubDbHealthCheck : IDatabaseHealthCheck
{
    public Task<bool> IsHealthyAsync(CancellationToken cancellationToken) => Task.FromResult(true);
}

file sealed class StubWindowsIdentityProvider : IWindowsIdentityProvider
{
    public WindowsIdentityInfo? GetCurrentUser()
    {
        return new WindowsIdentityInfo("S-1-5-21-stub", "TestUser");
    }
}

// ----------------------------------------------------------------------
// Null LLM stubs
// ----------------------------------------------------------------------

file sealed class NullLlmConfigStore : ILlmConfigurationStore
{
    public Task<LlmConfigurationReference> SaveAsync(LlmEndpointOptions options, CancellationToken ct = default)
        => Task.FromResult(new LlmConfigurationReference(1, "null-ref", "0000000000000000", DateTimeOffset.UtcNow));

    public Task<LlmEndpointOptions?> LoadAsync(CancellationToken ct = default)
        => Task.FromResult<LlmEndpointOptions?>(null);

    public Task ClearAsync(CancellationToken ct = default)
        => Task.CompletedTask;
}

file sealed class NullLlmTestService : ILlmConnectionTestService
{
    public Task<LlmConnectionTestResult> TestConnectionAsync(TestLlmConnectionCommand command, CancellationToken ct = default)
        => Task.FromResult(LlmConnectionTestResult.Failure(
            LlmConnectionTestFailureReason.OriginMismatch, null, TimeSpan.Zero, "0000000000000000"));
}

file sealed class NullLlmCredentialStore : ILlmCredentialStore
{
    public void SaveCredential(string logicalName, string value) =>
        throw new InvalidOperationException("LLM credential storage is unavailable.");

    public void DeleteCredential(string logicalName)
    {
        _ = logicalName;
    }

    public SensitiveCredentialBuffer OpenCredential(LlmEndpointOptions options) =>
        throw new InvalidOperationException("LLM credential storage is unavailable.");

    public bool HasCredential(string logicalName)
    {
        _ = logicalName;
        return false;
    }
}
