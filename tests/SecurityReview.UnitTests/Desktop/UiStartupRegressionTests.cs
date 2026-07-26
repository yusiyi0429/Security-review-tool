using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Xml.Linq;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Desktop.Views;
using SecurityReview.Domain.Scans;

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
    public void Bound_progress_bar_values_are_explicitly_one_way()
    {
        string desktopRoot = Path.Combine(FindRepositoryRoot(),
            "src", "SecurityReview.Desktop");

        var valueBindings = Directory.GetFiles(
                desktopRoot, "*.xaml", SearchOption.AllDirectories)
            .SelectMany(path => XDocument.Load(path).Descendants())
            .Where(element => element.Name.LocalName == "ProgressBar")
            .Select(element => element.Attribute("Value")?.Value)
            .OfType<string>()
            .Where(value => value.StartsWith("{Binding", StringComparison.Ordinal))
            .ToArray();

        Assert.All(valueBindings, binding =>
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
                var app = new App();
                app.InitializeComponent();
                try
                {
                    var viewModel = new ScanResultsViewModel(
                        new TestErrorSink(),
                        () => throw new InvalidOperationException("Query service is not used by this UI test."));
                    viewModel.ScanStatus = ScanStatus.Completed;
                    var view = new ScanResultsView { DataContext = viewModel };
                    var host = new ContentControl { Content = view };
                    host.Measure(new Size(1280, 760));
                    host.Arrange(new Rect(0, 0, 1280, 760));
                    host.UpdateLayout();

                    Run statusRun = FindStatusRun(view);
                    Binding binding = Assert.IsType<Binding>(
                        BindingOperations.GetBinding(statusRun, Run.TextProperty));
                    bindingMode = binding.Mode;

                    BindingExpression expression = Assert.IsType<BindingExpression>(
                        BindingOperations.GetBindingExpression(statusRun, Run.TextProperty));
                    expression.UpdateTarget();
                    renderedStatus = statusRun.Text;
                }
                finally
                {
                    app.Shutdown();
                }
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
        Assert.Equal("已完成", renderedStatus);
    }

    [Fact]
    public void Scan_progress_percentage_binding_is_one_way_and_renders_on_sta_thread()
    {
        Exception? startupException = null;
        BindingMode? bindingMode = null;
        double renderedPercentage = 0;

        var thread = new Thread(() =>
        {
            try
            {
                var app = new App();
                app.InitializeComponent();
                try
                {
                    var viewModel = new ScanProgressViewModel(
                        new TestErrorSink(),
                        () => throw new InvalidOperationException(
                            "Cancel handler is not used by this UI test."));
                    viewModel.ApplyProgress(ScanProgress.Empty with
                    {
                        Stage = ScanStage.Running,
                        DiscoveredFiles = 10,
                        ProcessedFiles = 4,
                    });

                    var view = new ScanProgressView { DataContext = viewModel };
                    var host = new ContentControl { Content = view };
                    host.Measure(new Size(1280, 760));
                    host.Arrange(new Rect(0, 0, 1280, 760));
                    host.UpdateLayout();

                    ProgressBar progressBar = FindProgressBar(view);
                    Binding binding = Assert.IsType<Binding>(
                        BindingOperations.GetBinding(progressBar, ProgressBar.ValueProperty));
                    bindingMode = binding.Mode;

                    BindingExpression expression = Assert.IsType<BindingExpression>(
                        BindingOperations.GetBindingExpression(progressBar, ProgressBar.ValueProperty));
                    expression.UpdateTarget();
                    renderedPercentage = progressBar.Value;
                }
                finally
                {
                    app.Shutdown();
                }
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
            "Scan progress XAML loading did not finish within 15 seconds.");
        Assert.Null(startupException);
        Assert.Equal(BindingMode.OneWay, bindingMode);
        Assert.Equal(40, renderedPercentage);
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

    private static ProgressBar FindProgressBar(DependencyObject root)
    {
        foreach (object child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is ProgressBar progressBar)
                return progressBar;

            if (child is not DependencyObject dependencyObject)
                continue;

            try
            {
                return FindProgressBar(dependencyObject);
            }
            catch (InvalidOperationException)
            {
                // Continue searching sibling branches.
            }
        }

        throw new InvalidOperationException(
            "Scan progress Value binding was not found in the logical tree.");
    }

    private static IEnumerable<TextBlock> FindTextBlocks(DependencyObject root)
    {
        foreach (object child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is TextBlock textBlock)
                yield return textBlock;

            if (child is not DependencyObject dependencyObject)
                continue;

            foreach (TextBlock descendant in FindTextBlocks(dependencyObject))
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
