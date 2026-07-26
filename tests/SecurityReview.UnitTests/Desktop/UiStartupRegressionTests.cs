using System.Text.RegularExpressions;
using System.Windows;
using System.Xml.Linq;
using SecurityReview.Desktop;
using SecurityReview.Desktop.Services;

namespace SecurityReview.UnitTests.Desktop;

public sealed partial class UiStartupRegressionTests
{
    [Fact]
    public void Main_window_has_no_star_sized_framework_elements()
    {
        string xamlPath = Path.Combine(FindRepositoryRoot(),
            "src", "SecurityReview.Desktop", "MainWindow.xaml");
        XDocument document = XDocument.Load(xamlPath);

        var invalidAttributes = document
            .Descendants()
            .Where(element => element.Name.LocalName is not ("ColumnDefinition" or "RowDefinition"))
            .SelectMany(element => element.Attributes())
            .Where(attribute => attribute.Name.LocalName is "Width" or "Height")
            .Where(attribute => string.Equals(attribute.Value, "*", StringComparison.Ordinal))
            .ToArray();

        Assert.Empty(invalidAttributes);
    }

    [Fact]
    public void All_static_resources_are_defined_in_desktop_xaml()
    {
        string desktopRoot = Path.Combine(FindRepositoryRoot(),
            "src", "SecurityReview.Desktop");
        string[] xamlPaths = Directory.GetFiles(
            desktopRoot, "*.xaml", SearchOption.AllDirectories);
        XDocument[] documents = xamlPaths.Select(XDocument.Load).ToArray();

        var definitions = documents
            .SelectMany(document => document.Descendants())
            .SelectMany(element => element.Attributes())
            .Where(attribute => attribute.Name.LocalName == "Key")
            .Select(attribute => attribute.Value)
            .ToHashSet(StringComparer.Ordinal);

        var missing = documents
            .SelectMany(document => document.Descendants())
            .SelectMany(element => element.Attributes())
            .SelectMany(attribute => StaticResourceRegex().Matches(attribute.Value))
            .Select(match => match.Groups[1].Value)
            .Where(key => !definitions.Contains(key))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Empty(missing);
    }

    [Fact]
    public void Llm_settings_exposes_secure_credential_and_connection_test_controls()
    {
        string xamlPath = Path.Combine(FindRepositoryRoot(),
            "src", "SecurityReview.Desktop", "Views", "LlmSettingsView.xaml");
        XDocument document = XDocument.Load(xamlPath);

        Assert.Contains(document.Descendants(),
            element => element.Name.LocalName == "PasswordBox"
                && element.Attributes().Any(attribute =>
                    attribute.Name.LocalName == "PasswordChanged"));
        Assert.Contains(document.Descendants(),
            element => element.Name.LocalName == "Button"
                && element.Attributes().Any(attribute =>
                    attribute.Name.LocalName == "Command"
                    && attribute.Value.Contains("TestCommand", StringComparison.Ordinal)));
    }

    [GeneratedRegex(@"\{StaticResource\s+([^\s,}]+)")]
    private static partial Regex StaticResourceRegex();

    [Fact]
    public void Main_window_xaml_loads_on_sta_thread()
    {
        // Some isolated CI/test hosts omit the legacy Windows alias even though
        // SystemRoot is present. WPF's font cache still constructs its Fonts URI
        // from "windir" during Window type initialization.
        string? originalWindir = Environment.GetEnvironmentVariable("windir");
        if (string.IsNullOrWhiteSpace(originalWindir))
        {
            string? systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            Assert.False(string.IsNullOrWhiteSpace(systemRoot));
            Environment.SetEnvironmentVariable("windir", systemRoot);
        }

        string tempDirectory = Path.Combine(
            Path.GetTempPath(),
            $"security-review-ui-startup-{Guid.NewGuid():N}");
        Exception? startupException = null;
        bool initialBoundsFitWorkArea = false;

        var thread = new Thread(() =>
        {
            try
            {
                using var root = new CompositionRoot(
                    CompositionRoot.Args.ForTest(tempDirectory));
                var window = new MainWindow(root.MainWindowViewModel, root);
                Rect workArea = SystemParameters.WorkArea;
                initialBoundsFitWorkArea = window.Left >= workArea.Left
                    && window.Top >= workArea.Top
                    && window.Left + window.Width <= workArea.Right
                    && window.Top + window.Height <= workArea.Bottom;
                window.Close();
            }
            catch (Exception ex)
            {
                startupException = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        bool completed = thread.Join(TimeSpan.FromSeconds(15));
        try
        {
            Assert.True(completed,
                "Main window XAML loading did not finish within 15 seconds.");
            Assert.Null(startupException);
            Assert.True(initialBoundsFitWorkArea,
                "Main window initial bounds extend outside the Windows work area.");
        }
        finally
        {
            if (completed && Directory.Exists(tempDirectory))
            {
                DeleteTestDirectory(tempDirectory);
            }

            if (string.IsNullOrWhiteSpace(originalWindir))
            {
                Environment.SetEnvironmentVariable("windir", originalWindir);
            }
        }
    }

    private static void DeleteTestDirectory(string path)
    {
        foreach (string file in Directory.EnumerateFiles(
                     path, "*", SearchOption.AllDirectories))
        {
            FileAttributes attributes = File.GetAttributes(file);
            if ((attributes & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(
                    file,
                    attributes & ~FileAttributes.ReadOnly);
            }
        }

        Directory.Delete(path, recursive: true);
    }

    [Fact]
    public void Startup_failure_is_reported_with_stable_sanitized_message()
    {
        var sink = new TestErrorSink();
        Exception? loggedException = null;
        var boundary = new UiExceptionBoundary(sink, exception =>
        {
            loggedException = exception;
            return Task.CompletedTask;
        });
        var failure = new InvalidOperationException(
            @"Cannot load D:\sensitive\operator\MainWindow.xaml");

        boundary.ReportStartupFailure(failure);

        var error = Assert.Single(sink.Errors);
        Assert.Equal(UiExceptionBoundary.StartupFailureCode, error.Code);
        Assert.Equal(UiExceptionBoundary.StartupFailureMessage, error.Message);
        Assert.DoesNotContain("sensitive", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(failure, loggedException);
    }

    private static string FindRepositoryRoot()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "global.json")))
                return directory.FullName;
        }

        throw new DirectoryNotFoundException("Repository root not found.");
    }

    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<ErrorEntry> Errors { get; } = [];

        public void Report(string code, string message) => Errors.Add(new(code, message));
    }

    private sealed record ErrorEntry(string Code, string Message);
}
