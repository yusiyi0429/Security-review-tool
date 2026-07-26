using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Media;
using System.Xml.Linq;
using SecurityReview.Desktop;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Desktop.Views;

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
    public void Bound_run_text_elements_are_explicitly_one_way()
    {
        string desktopRoot = Path.Combine(FindRepositoryRoot(),
            "src", "SecurityReview.Desktop");

        var runBindings = Directory.GetFiles(
                desktopRoot, "*.xaml", SearchOption.AllDirectories)
            .SelectMany(path => XDocument.Load(path).Descendants())
            .Where(element => element.Name.LocalName == "Run")
            .Select(element => element.Attribute("Text")?.Value)
            .OfType<string>()
            .Where(value => value.StartsWith("{Binding", StringComparison.Ordinal))
            .ToArray();

        Assert.All(runBindings, binding =>
            Assert.Contains("Mode=OneWay", binding, StringComparison.Ordinal));
    }

    [Fact]
    public void Scan_results_status_binding_is_one_way_and_renders_on_sta_thread()
    {
        Exception? startupException = null;
        BindingMode? bindingMode = null;
        string? renderedStatus = null;

        var thread = new Thread(() =>
        {
            try
            {
                var viewModel = new ScanResultsViewModel(
                    new TestErrorSink(),
                    () => throw new InvalidOperationException("Query service is not used by this UI test."));
                var view = new ScanResultsView { DataContext = viewModel };

                Run statusRun = FindStatusRun(view);
                Binding binding = Assert.IsType<Binding>(
                    BindingOperations.GetBinding(statusRun, Run.TextProperty));
                bindingMode = binding.Mode;

                BindingOperations.GetBindingExpression(statusRun, Run.TextProperty)
                    ?.UpdateTarget();
                renderedStatus = statusRun.Text;
            }
            catch (Exception ex)
            {
                startupException = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        bool completed = thread.Join(TimeSpan.FromSeconds(15));

        Assert.True(completed,
            "Scan results XAML loading did not finish within 15 seconds.");
        Assert.Null(startupException);
        Assert.Equal(BindingMode.OneWay, bindingMode);
        Assert.False(string.IsNullOrWhiteSpace(renderedStatus));
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

    private static Run FindStatusRun(DependencyObject root)
    {
        foreach (TextBlock textBlock in FindTextBlocks(root))
        {
            foreach (Run run in textBlock.Inlines.OfType<Run>())
            {
                BindingBase? binding = BindingOperations.GetBinding(run, Run.TextProperty);
                if (binding is Binding { Path.Path: nameof(ScanResultsViewModel.ScanStatusDisplay) })
                    return run;
            }
        }

        throw new InvalidOperationException(
            "Scan results status Run binding was not found in the visual tree.");
    }

    private static IEnumerable<TextBlock> FindTextBlocks(DependencyObject root)
    {
        int childCount = VisualTreeHelper.GetChildrenCount(root);
        for (int index = 0; index < childCount; index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(root, index);
            if (child is TextBlock textBlock)
                yield return textBlock;

            foreach (TextBlock descendant in FindTextBlocks(child))
                yield return descendant;
        }
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
