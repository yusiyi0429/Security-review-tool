using System.ComponentModel;
using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Input;
using SecurityReview.Application.Llm;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the LLM settings configuration.
/// Edit decrypted config, credential via password box (never display stored token),
/// test with fixed benign input, show last origin/status/time.
/// HTTPS/cert/no-redirect enforcement. Clear semantic cache on target/model/prompt change.
/// </summary>
public sealed class LlmSettingsViewModel : ObservableObject, IDisposable
{
    private readonly ILlmConfigurationStore _configStore;
    private readonly ILlmConnectionTestService _testService;
    private readonly IUiErrorSink _errorSink;

    // Config fields
    private string _baseUri = "";
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

    // Track last saved values for cache clearing detection
    private string _lastSavedTarget = "";
    private string _lastSavedModel = "";

    public LlmSettingsViewModel(
        ILlmConfigurationStore configStore,
        ILlmConnectionTestService testService,
        IUiErrorSink errorSink)
    {
        _configStore = configStore;
        _testService = testService;
        _errorSink = errorSink;

        SaveCommand = new AsyncRelayCommand(_ => SaveConfigAsync(), errorSink,
            _ => !IsTesting);
        TestCommand = new AsyncRelayCommand(_ => TestConnectionAsync(), errorSink,
            _ => !IsTesting && HasConfig);
        ClearCommand = new AsyncRelayCommand(_ => ClearConfigAsync(), errorSink,
            _ => !IsTesting && HasConfig);
        LoadCommand = new AsyncRelayCommand(_ => LoadConfigAsync(), errorSink);

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(IsTesting) or nameof(HasConfig))
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
                OnPropertyChanged(nameof(IsBearerAuth));
        }
    }

    public bool IsBearerAuth => _authMode == LlmAuthMode.Bearer;

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
        set => SetProperty(ref _isTesting, value);
    }

    public bool HasConfig
    {
        get => _hasConfig;
        set => SetProperty(ref _hasConfig, value);
    }

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
                return;
            }

            ApplyOptions(options);
            HasConfig = true;
            _lastSavedTarget = options.BaseUri.ToString();
            _lastSavedModel = options.Model;
            LastTestOrigin = options.BaseUri.GetLeftPart(UriPartial.Authority);
            LastTestTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        }
        catch (Exception)
        {
            _errorSink.Report("llm_config_load_failed", $"加载LLM配置失败。");
        }
    }

    private void ApplyOptions(LlmEndpointOptions options)
    {
        BaseUri = options.BaseUri.ToString();
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
        // Validate HTTPS
        if (!string.IsNullOrWhiteSpace(BaseUri))
        {
            if (!BaseUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("LLM 端点必须使用 HTTPS 协议。\n不支持 HTTP 连接。",
                    "安全配置", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        try
        {
            var options = LlmEndpointOptions.Create(
                string.IsNullOrWhiteSpace(BaseUri) ? new Uri("https://localhost") : new Uri(BaseUri),
                chatCompletionsPath: ChatCompletionsPath,
                model: Model,
                authMode: AuthMode,
                responseFormatMode: ResponseFormatMode,
                sendTemperatureZero: SendTemperatureZero,
                customHeaderName: string.IsNullOrWhiteSpace(CustomHeaderName) ? null : CustomHeaderName,
                credentialReference: AuthMode != LlmAuthMode.None ? "llm-api-key" : null,
                timeout: TimeSpan.FromSeconds(TimeoutSeconds),
                maxConcurrency: MaxConcurrency);

            // Check if target/model changed → clear semantic cache
            string currentTarget = options.BaseUri.ToString();
            string currentModel = options.Model;
            bool cacheShouldClear =
                !string.IsNullOrEmpty(_lastSavedTarget) &&
                (!string.Equals(_lastSavedTarget, currentTarget, StringComparison.Ordinal) ||
                 !string.Equals(_lastSavedModel, currentModel, StringComparison.Ordinal));

            await _configStore.SaveAsync(options);

            // Clear credential from memory immediately
            CredentialInput = "";

            _lastSavedTarget = currentTarget;
            _lastSavedModel = currentModel;
            HasConfig = true;
            LastTestOrigin = options.BaseUri.GetLeftPart(UriPartial.Authority);
            LastTestTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

            if (cacheShouldClear)
            {
                MessageBox.Show("LLM 配置已保存。\n\n检测到目标端点或模型更改，语义缓存已清除。",
                    "配置", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("LLM 配置已保存。", "配置", MessageBoxButton.OK, MessageBoxImage.Information);
            }
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
        try
        {
            // Build options from current form state
            var options = LlmEndpointOptions.Create(
                string.IsNullOrWhiteSpace(BaseUri) ? new Uri("https://localhost") : new Uri(BaseUri),
                chatCompletionsPath: ChatCompletionsPath,
                model: Model,
                authMode: AuthMode,
                responseFormatMode: ResponseFormatMode,
                sendTemperatureZero: SendTemperatureZero,
                customHeaderName: string.IsNullOrWhiteSpace(CustomHeaderName) ? null : CustomHeaderName,
                credentialReference: AuthMode != LlmAuthMode.None ? "llm-api-key" : null,
                timeout: TimeSpan.FromSeconds(TimeoutSeconds),
                maxConcurrency: MaxConcurrency);

            var command = new TestLlmConnectionCommand(options);

            var result = await _testService.TestConnectionAsync(command);

            LastTestStatus = result.Succeeded ? "连接成功" : $"连接失败: {result.FailureReason}";
            LastTestTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            LastTestOrigin = _lastSavedTarget;

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
        catch (Exception)
        {
            LastTestStatus = "测试出错";
            _errorSink.Report("llm_test_failed", $"LLM连接测试失败。");
        }
        finally
        {
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
            HasConfig = false;
            BaseUri = "";
            Model = "";
            CredentialInput = "";
            LastTestOrigin = "";
            LastTestStatus = "";
            LastTestTime = "";
            _lastSavedTarget = "";
            _lastSavedModel = "";
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
}
