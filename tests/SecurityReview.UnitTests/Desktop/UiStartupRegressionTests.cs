using System.Xml.Linq;
using SecurityReview.Desktop.Services;

namespace SecurityReview.UnitTests.Desktop;

public sealed class UiStartupRegressionTests
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
