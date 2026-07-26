using System.Globalization;
using System.Windows;
using System.Windows.Input;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the LLM settings configuration.
/// Edit decrypted config, credential via password box (never display stored token),
/// test with fixed benign input, show last origin/status/time.
/// HTTPS/cert/no-redirect enforcement. Clear semantic cache on target/model/prompt change.
/// </summary>
public sealed class LlmSettingsViewModel : ObservableObject, IDisposable
{
    private const string DefaultCredentialReference = "llm-api-key";

    private readonly ILlmConfigurationStore _configStore;
    private readonly ILlmConnectionTestService _testService;
    private readonly ILlmCredentialStore _credentialStore;
    private readonly IUiErrorSink _errorSink;
    private readonly Func<Task>? _configurationChanged;
    private readonly ICacheRepository? _cacheRepository;

    // Config fields
    private string _baseUri = "";
    private LlmEndpointScope _endpointScope = LlmEndpointScope.CloudApi;
    private string _chatCompletionsPath = "/v1/chat/completions";
    private string _model = "";
    private LlmAuthMode _authMode = LlmAuthMode.None;
    private string _customHeaderName = "";
    private LlmResponseFormatMode _responseFormatMode = LlmResponseFormatMode.JsonSchema;
    private bool _sendTemperatureZero;
    private int _maxConcurrency = 4;
    private int _timeoutSeconds = 120;

    // Credential (never stored in memory after save)
    private string _credentialInput = "";

    // Test state
    private string _lastTestOrigin = "";
    private string _lastTestStatus = "";
    private string _lastTestTime = "";
    private bool _isTesting;
    private bool _hasConfig;
    private bool _hasStoredCredential;

    // Track last saved values for cache clearing detection
    private string _lastSavedTarget = "";
    private string _lastSavedModel = "";

    public LlmSettingsViewModel(
        ILlmConfigurationStore configStore,
        ILlmConnectionTestService testService,
        ILlmCredentialStore credentialStore,
        IUiErrorSink errorSink,
        Func<Task>? configurationChanged = null,
        ICacheRepository? cacheRepository = null)
    {
        _configStore = configStore;
        _testService = testService;
        _credentialStore = credentialStore;
        _errorSink = errorSink;
        _configurationChanged = configurationChanged;
        _cacheRepository = cacheRepository;

        SaveCommand = new AsyncRelayCommand(_ => SaveConfigAsync(), errorSink,
            _ => !IsTesting);
        TestCommand = new AsyncRelayCommand(_ => TestConnectionAsync(), errorSink,
            _ => !IsTesting);
        ClearCommand = new AsyncRelayCommand(_ => ClearConfigAsync(), errorSink,
            _ => !IsTesting && (HasConfig || HasStoredCredential));
        LoadCommand = new AsyncRelayCommand(_ => LoadConfigAsync(), errorSink);

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(IsTesting) or nameof(HasConfig)
                or nameof(HasStoredCredential))
                CommandManager.InvalidateRequerySuggested();
        };
    }

    // ------------------------------------------------------------------ Commands

    public ICommand SaveCommand { get; }
    public ICommand TestCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand LoadCommand { get; }

    // ------------------------------------------------------------------ Properties

    public string BaseUri
    {
        get => _baseUri;
        set => SetProperty(ref _baseUri, value);
    }

    public LlmEndpointScope EndpointScope
    {
        get => _endpointScope;
        set
        {
            if (SetProperty(ref _endpointScope, value))
                OnPropertyChanged(nameof(EndpointSecurityHint));
        }
    }

    public string EndpointSecurityHint => EndpointScope == LlmEndpointScope.CloudApi
        ? "第三方 API 必须使用 HTTPS；请确认组织的数据策略允许发送受限语义候选。"
        : "内网模型可使用 HTTPS，或受限的 HTTP；HTTP 内容不加密，且仅连接回环或私有网络地址。";

    public string ChatCompletionsPath
    {
        get => _chatCompletionsPath;
        set => SetProperty(ref _chatCompletionsPath, value);
    }

    public string Model
    {
        get => _model;
        set => SetProperty(ref _model, value);
    }

    public LlmAuthMode AuthMode
    {
        get => _authMode;
        set
        {
            if (SetProperty(ref _authMode, value))
            {
                OnPropertyChanged(nameof(IsBearerAuth));
                OnPropertyChanged(nameof(IsCustomHeaderAuth));
                OnPropertyChanged(nameof(UsesCredential));
                OnPropertyChanged(nameof(CredentialHint));
            }
        }
    }

    public bool IsBearerAuth => _authMode == LlmAuthMode.Bearer;

    public bool IsCustomHeaderAuth => _authMode == LlmAuthMode.CustomHeader;

    public bool UsesCredential => _authMode != LlmAuthMode.None;

    public string CustomHeaderName
    {
        get => _customHeaderName;
        set => SetProperty(ref _customHeaderName, value);
    }

    public LlmResponseFormatMode ResponseFormatMode
    {
        get => _responseFormatMode;
        set => SetProperty(ref _responseFormatMode, value);
    }

    public bool SendTemperatureZero
    {
        get => _sendTemperatureZero;
        set => SetProperty(ref _sendTemperatureZero, value);
    }

    public int MaxConcurrency
    {
        get => _maxConcurrency;
        set => SetProperty(ref _maxConcurrency, value);
    }

    public int TimeoutSeconds
    {
        get => _timeoutSeconds;
        set => SetProperty(ref _timeoutSeconds, value);
    }

    /// <summary>
    /// Credential input from a password box. Never displayed after entry.
    /// Cleared immediately on save.
    /// </summary>
    public string CredentialInput
    {
        get => _credentialInput;
        set => SetProperty(ref _credentialInput, value);
    }

    public string LastTestOrigin
    {
        get => _lastTestOrigin;
        set => SetProperty(ref _lastTestOrigin, value);
    }

    public string LastTestStatus
    {
        get => _lastTestStatus;
        set => SetProperty(ref _lastTestStatus, value);
    }

    public string LastTestTime
    {
        get => _lastTestTime;
        set => SetProperty(ref _lastTestTime, value);
    }

    public bool IsTesting
    {
        get => _isTesting;
        set
        {
            if (SetProperty(ref _isTesting, value))
                OnPropertyChanged(nameof(TestButtonText));
        }
    }

    public string TestButtonText => IsTesting ? "正在测试…" : "测试当前连接  →";

    public bool HasConfig
    {
        get => _hasConfig;
        set => SetProperty(ref _hasConfig, value);
    }

    public bool HasStoredCredential
    {
        get => _hasStoredCredential;
        private set
        {
            if (SetProperty(ref _hasStoredCredential, value))
                OnPropertyChanged(nameof(CredentialHint));
        }
    }

    public string CredentialHint => HasStoredCredential
        ? "已安全保存凭据。留空可继续使用，输入新值会在保存后替换。"
        : "凭据使用 Windows DPAPI 加密，仅当前 Windows 用户可读取。";

    // ------------------------------------------------------------------ Load/Save

    /// <summary>
    /// Load existing config from the store. Credential is never displayed.
    /// </summary>
    public async Task LoadConfigAsync()
    {
        try
        {
            var options = await _configStore.LoadAsync();
            if (options is null)
            {
                HasConfig = false;
                HasStoredCredential = HasCredential(DefaultCredentialReference);
                if (_configurationChanged is not null)
                    await _configurationChanged();
                return;
            }

            ApplyOptions(options);
            HasConfig = true;
            HasStoredCredential = options.CredentialReference is { Length: > 0 } reference
                && HasCredential(reference);
            _lastSavedTarget = options.BaseUri.ToString();
            _lastSavedModel = options.Model;
            LastTestOrigin = options.BaseUri.GetLeftPart(UriPartial.Authority);
            LastTestTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            if (_configurationChanged is not null)
                await _configurationChanged();
        }
        catch (Exception)
        {
            _errorSink.Report("llm_config_load_failed", $"加载LLM配置失败。");
        }
    }

    private void ApplyOptions(LlmEndpointOptions options)
    {
        BaseUri = options.BaseUri.ToString();
        EndpointScope = options.EndpointScope;
        ChatCompletionsPath = options.ChatCompletionsPath;
        Model = options.Model;
        AuthMode = options.AuthMode;
        CustomHeaderName = options.CustomHeaderName ?? "";
        ResponseFormatMode = options.ResponseFormatMode;
        SendTemperatureZero = options.SendTemperatureZero;
        MaxConcurrency = options.MaxConcurrency;
        TimeoutSeconds = (int)options.Timeout.TotalSeconds;
    }

    /// <summary>
    /// Save config. Credential is written to DPAPI store and cleared from memory.
    /// Clears semantic cache if target/model/prompt changed.
    /// </summary>
    private async Task SaveConfigAsync()
    {
        try
        {
            LlmEndpointOptions options = BuildOptions();

            if (options.AuthMode != LlmAuthMode.None)
            {
                if (!string.IsNullOrWhiteSpace(CredentialInput))
                {
                    _credentialStore.SaveCredential(
                        DefaultCredentialReference, CredentialInput);
                }
                else if (!HasCredential(DefaultCredentialReference))
                {
                    throw new ArgumentException(
                        "请选择认证方式并填写 API Key，或改为“无需认证”。");
                }
            }

            // Check if target/model changed → clear semantic cache
            string currentTarget = options.BaseUri.ToString();
            string currentModel = options.Model;
            bool cacheShouldClear =
                !string.IsNullOrEmpty(_lastSavedTarget) &&
                (!string.Equals(_lastSavedTarget, currentTarget, StringComparison.Ordinal) ||
                 !string.Equals(_lastSavedModel, currentModel, StringComparison.Ordinal));

            await _configStore.SaveAsync(options);

            if (options.AuthMode == LlmAuthMode.None)
            {
                DeleteCredentialIfPresent(DefaultCredentialReference);
                HasStoredCredential = false;
            }
            else
            {
                HasStoredCredential = true;
            }

            // Clear credential from memory immediately
            CredentialInput = "";

            _lastSavedTarget = currentTarget;
            _lastSavedModel = currentModel;
            HasConfig = true;
            LastTestOrigin = options.BaseUri.GetLeftPart(UriPartial.Authority);
            LastTestTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            if (_configurationChanged is not null)
                await _configurationChanged();

            if (cacheShouldClear)
            {
                if (_cacheRepository is not null)
                {
                    await _cacheRepository
                        .DeleteByStageAsync("llm_review")
                        .ConfigureAwait(true);
                }
                MessageBox.Show("LLM 配置已保存。\n\n检测到目标端点或模型更改，语义缓存已清除。",
                    "配置", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("LLM 配置已保存。", "配置", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            MessageBox.Show($"LLM 配置无效。\n\n{ex.Message}",
                "安全配置", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception)
        {
            _errorSink.Report("llm_config_save_failed", $"保存LLM配置失败。");
        }
    }

    /// <summary>
    /// Test connection with a fixed benign input. Enforces HTTPS/cert validation.
    /// </summary>
    private async Task TestConnectionAsync()
    {
        IsTesting = true;
        LastTestStatus = "正在测试…";
        string? temporaryCredentialReference = null;
        try
        {
            string? credentialReference = null;
            if (AuthMode != LlmAuthMode.None)
            {
                if (!string.IsNullOrWhiteSpace(CredentialInput))
                {
                    temporaryCredentialReference =
                        $"llm-api-key-test-{Guid.NewGuid():N}";
                    credentialReference = temporaryCredentialReference;
                }
                else if (HasCredential(DefaultCredentialReference))
                {
                    credentialReference = DefaultCredentialReference;
                }
                else
                {
                    throw new ArgumentException(
                        "当前认证方式需要 API Key。请输入后再测试连接。");
                }
            }

            // Build from the current form state. A newly entered credential is
            // stored under a short-lived DPAPI reference and removed after the
            // test, so testing does not silently save the configuration.
            LlmEndpointOptions options = BuildOptions(credentialReference);
            if (temporaryCredentialReference is not null)
            {
                _credentialStore.SaveCredential(
                    temporaryCredentialReference, CredentialInput);
            }

            var command = new TestLlmConnectionCommand(options);

            var result = await _testService.TestConnectionAsync(command);

            LastTestStatus = result.Succeeded ? "连接成功" : $"连接失败: {result.FailureReason}";
            LastTestTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            LastTestOrigin = options.BaseUri.GetLeftPart(UriPartial.Authority);

            if (result.Succeeded)
            {
                MessageBox.Show($"LLM 连接测试成功。\n\n端点: {LastTestOrigin}\n模型: {Model}",
                    "连接测试", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"LLM 连接测试失败。\n\n原因: {result.FailureReason}\n\n请检查端点地址、认证凭据和网络连接。",
                    "连接测试", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            LastTestStatus = "配置无效";
            MessageBox.Show($"LLM 配置无效。\n\n{ex.Message}",
                "安全配置", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception)
        {
            LastTestStatus = "测试出错";
            _errorSink.Report("llm_test_failed", $"LLM连接测试失败。");
        }
        finally
        {
            if (temporaryCredentialReference is not null)
                DeleteCredentialIfPresent(temporaryCredentialReference);
            IsTesting = false;
        }
    }

    /// <summary>
    /// Clear all LLM configuration.
    /// </summary>
    private async Task ClearConfigAsync()
    {
        var result = MessageBox.Show(
            "确定要清除所有 LLM 配置吗？\n\n此操作将删除保存的端点地址、模型和凭据。",
            "清除配置", MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            await _configStore.ClearAsync();
            DeleteCredentialIfPresent(DefaultCredentialReference);
            HasConfig = false;
            HasStoredCredential = false;
            BaseUri = "";
            EndpointScope = LlmEndpointScope.CloudApi;
            Model = "";
            CredentialInput = "";
            LastTestOrigin = "";
            LastTestStatus = "";
            LastTestTime = "";
            _lastSavedTarget = "";
            _lastSavedModel = "";
            if (_configurationChanged is not null)
                await _configurationChanged();
        }
        catch (Exception)
        {
            _errorSink.Report("llm_clear_failed", $"清除LLM配置失败。");
        }
    }

    public void Dispose()
    {
        CredentialInput = "";
    }

    private LlmEndpointOptions BuildOptions(string? credentialReference = null)
    {
        if (!Uri.TryCreate(BaseUri, UriKind.Absolute, out Uri? baseUri))
            throw new ArgumentException("服务基地址必须是完整的 HTTP 或 HTTPS URL。");

        return LlmEndpointOptions.Create(
            baseUri,
            chatCompletionsPath: ChatCompletionsPath,
            model: Model,
            authMode: AuthMode,
            responseFormatMode: ResponseFormatMode,
            sendTemperatureZero: SendTemperatureZero,
            customHeaderName: AuthMode == LlmAuthMode.CustomHeader
                && !string.IsNullOrWhiteSpace(CustomHeaderName)
                    ? CustomHeaderName
                    : null,
            credentialReference: AuthMode != LlmAuthMode.None
                ? credentialReference ?? DefaultCredentialReference
                : null,
            timeout: TimeSpan.FromSeconds(TimeoutSeconds),
            maxConcurrency: MaxConcurrency,
            endpointScope: EndpointScope);
    }

    private bool HasCredential(string logicalName)
    {
        try
        {
            return _credentialStore.HasCredential(logicalName);
        }
        catch
        {
            return false;
        }
    }

    private void DeleteCredentialIfPresent(string logicalName)
    {
        try
        {
            if (_credentialStore.HasCredential(logicalName))
                _credentialStore.DeleteCredential(logicalName);
        }
        catch
        {
            // Best effort for stale/test credentials. Configuration clearing
            // still reports its own failures through the UI error sink.
        }
    }
}
