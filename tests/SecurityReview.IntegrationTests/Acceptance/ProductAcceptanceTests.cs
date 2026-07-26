using System.Text.Json;
using SecurityReview.CorpusTool.Model;

namespace SecurityReview.IntegrationTests.Acceptance;

/// <summary>
/// Product-level acceptance tests that load all scenarios from
/// <c>tests/Acceptance/acceptance-manifest.json</c> and run each one
/// through the <see cref="AcceptanceScenarioRunner"/>.
/// </summary>
public sealed class ProductAcceptanceTests
{
    private static AcceptanceManifest? s_manifest;

    /// <summary>
    /// Runs every cross-platform acceptance scenario against the real
    /// Application-layer scan orchestration. Windows-only scenarios are
    /// skipped on non-Windows hosts.
    /// </summary>
    [Fact]
    public async Task all_acceptance_scenarios_pass()
    {
        AcceptanceManifest manifest = LoadManifest();

        int passed = 0;
        int skipped = 0;
        int failed = 0;
        var failures = new List<string>();

        foreach (AcceptanceScenario scenario in manifest.Scenarios)
        {
            // Windows-only scenarios produce a Skip (not Fail) on Linux.
            if (scenario.RequiredOsCapability is "windows-sandbox" or "windows-gui"
                && !OperatingSystem.IsWindows())
            {
                skipped++;
                continue;
            }

            await using var runner = new AcceptanceScenarioRunner(scenario);
            await runner.SetupAsync(TestContext.Current.CancellationToken);

            ScenarioActuals actuals = await runner.RunAsync(
                TestContext.Current.CancellationToken);

            ValidationResult result = runner.Validate(actuals);

            if (result.Passed)
            {
                passed++;
            }
            else
            {
                failed++;
                failures.Add(
                    $"  {scenario.Id}: {result.Detail}");
            }
        }

        Assert.True(
            failed == 0,
            $"Acceptance: {passed} passed, {skipped} skipped, {failed} failed of {manifest.Scenarios.Count} total.{Environment.NewLine}" +
            string.Join(Environment.NewLine, failures));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Resolves <c>tests/Acceptance/acceptance-manifest.json</c> from the
    /// test assembly location by walking up to the repository root.
    /// </summary>
    private static AcceptanceManifest LoadManifest()
    {
        if (s_manifest is not null)
            return s_manifest;

        string? manifestPath = null;
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(
                current.FullName,
                "tests",
                "Acceptance",
                "acceptance-manifest.json");
            if (File.Exists(candidate))
            {
                manifestPath = candidate;
                break;
            }

            current = current.Parent;
        }

        if (manifestPath is null)
        {
            throw new FileNotFoundException(
                "Could not locate tests/Acceptance/acceptance-manifest.json " +
                "from the test assembly directory.");
        }

        string json = File.ReadAllText(manifestPath);
        s_manifest = JsonSerializer.Deserialize(
            json, AcceptanceJsonContext.Default.AcceptanceManifest)
            ?? throw new InvalidOperationException(
                $"Failed to deserialize acceptance manifest at '{manifestPath}'.");

        return s_manifest;
    }
}
