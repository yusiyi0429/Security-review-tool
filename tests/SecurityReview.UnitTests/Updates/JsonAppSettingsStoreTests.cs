using System.Text.Json;
using SecurityReview.Application.Updates;
using SecurityReview.Infrastructure.Updates;

namespace SecurityReview.UnitTests.Updates;

public sealed class JsonAppSettingsStoreTests : IDisposable
{
    private readonly string _configDirectory;

    public JsonAppSettingsStoreTests()
    {
        _configDirectory = Path.Combine(
            Path.GetTempPath(), "srt-appsettings-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_configDirectory))
            Directory.Delete(_configDirectory, recursive: true);
    }

    [Fact]
    public async Task Load_returns_default_when_file_is_missing()
    {
        var store = new JsonAppSettingsStore(_configDirectory);

        AppSettings settings = await store.LoadAsync();

        Assert.Equal(AppSettings.Default, settings);
        Assert.False(settings.AutoCheckUpdatesOnStartup);
    }

    [Fact]
    public async Task Save_then_load_round_trips_settings()
    {
        var store = new JsonAppSettingsStore(_configDirectory);
        await store.SaveAsync(new AppSettings(AutoCheckUpdatesOnStartup: true));

        AppSettings reloaded = await new JsonAppSettingsStore(_configDirectory).LoadAsync();

        Assert.True(reloaded.AutoCheckUpdatesOnStartup);
    }

    [Fact]
    public async Task Save_creates_config_directory_when_missing()
    {
        var store = new JsonAppSettingsStore(_configDirectory);

        await store.SaveAsync(AppSettings.Default);

        Assert.True(File.Exists(store.FilePath));
    }

    [Fact]
    public async Task Save_writes_schema_version_envelope()
    {
        var store = new JsonAppSettingsStore(_configDirectory);

        await store.SaveAsync(new AppSettings(AutoCheckUpdatesOnStartup: true));

        string json = await File.ReadAllTextAsync(store.FilePath);
        using JsonDocument document = JsonDocument.Parse(json);
        Assert.Equal(JsonAppSettingsStore.SchemaVersion,
            document.RootElement.GetProperty("SchemaVersion").GetInt32());
        Assert.True(document.RootElement.GetProperty("AutoCheckUpdatesOnStartup").GetBoolean());
    }

    [Fact]
    public async Task Load_returns_default_when_file_is_corrupt()
    {
        Directory.CreateDirectory(_configDirectory);
        var store = new JsonAppSettingsStore(_configDirectory);
        await File.WriteAllTextAsync(store.FilePath, "{ not valid json");

        AppSettings settings = await store.LoadAsync();

        Assert.Equal(AppSettings.Default, settings);
    }

    [Fact]
    public async Task Load_returns_default_when_file_is_empty()
    {
        Directory.CreateDirectory(_configDirectory);
        var store = new JsonAppSettingsStore(_configDirectory);
        await File.WriteAllTextAsync(store.FilePath, string.Empty);

        AppSettings settings = await store.LoadAsync();

        Assert.Equal(AppSettings.Default, settings);
    }

    [Fact]
    public async Task Load_returns_default_when_schema_version_is_unsupported()
    {
        Directory.CreateDirectory(_configDirectory);
        var store = new JsonAppSettingsStore(_configDirectory);
        await File.WriteAllTextAsync(store.FilePath,
            """{"SchemaVersion": 999, "AutoCheckUpdatesOnStartup": true}""");

        AppSettings settings = await store.LoadAsync();

        Assert.Equal(AppSettings.Default, settings);
        Assert.False(settings.AutoCheckUpdatesOnStartup);
    }

    [Fact]
    public async Task Save_overwrites_existing_document_atomically()
    {
        var store = new JsonAppSettingsStore(_configDirectory);
        await store.SaveAsync(new AppSettings(AutoCheckUpdatesOnStartup: true));
        await store.SaveAsync(new AppSettings(AutoCheckUpdatesOnStartup: false));

        AppSettings reloaded = await store.LoadAsync();

        Assert.False(reloaded.AutoCheckUpdatesOnStartup);
        Assert.Empty(Directory.GetFiles(_configDirectory, "*.tmp"));
    }

    [Fact]
    public async Task Save_rejects_null_settings()
    {
        var store = new JsonAppSettingsStore(_configDirectory);

        await Assert.ThrowsAsync<ArgumentNullException>(() => store.SaveAsync(null!));
    }

    [Fact]
    public void Constructor_rejects_null_config_directory()
    {
        Assert.Throws<ArgumentNullException>(() => new JsonAppSettingsStore(null!));
    }
}
