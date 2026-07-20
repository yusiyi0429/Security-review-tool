using SecurityReview.Domain;

namespace SecurityReview.UnitTests.Architecture;

public sealed class ProjectDependencyTests
{
    [Fact]
    public void Domain_has_no_infrastructure_or_ui_reference()
    {
        string[] forbidden = ["SecurityReview.Infrastructure", "SecurityReview.Desktop", "PresentationFramework"];
        string[] references = typeof(ScanId).Assembly.GetReferencedAssemblies().Select(x => x.Name ?? "").ToArray();
        Assert.DoesNotContain(references, name => forbidden.Contains(name, StringComparer.Ordinal));
    }
}
