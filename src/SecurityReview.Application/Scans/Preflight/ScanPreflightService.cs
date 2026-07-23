namespace SecurityReview.Application.Scans.Preflight;

public static class PreflightErrorCodes
{
    public const string RootInvalid = "root_invalid";
    public const string BaselineInactive = "baseline_inactive";
    public const string AppDataNotWritable = "app_data_not_writable";
    public const string DatabaseUnhealthy = "database_unhealthy";
    public const string SandboxUnavailable = "sandbox_unavailable";
}

public sealed record ScanPreflightRequest(string ScanRootPath);

public sealed record PreflightError(string Code, string Message);

public sealed record ScanPreflightResult(bool CanStart, IReadOnlyList<PreflightError> Errors);

// Ports whose real implementations arrive with the signed rule-pack baseline
// and the scan database; preflight only depends on their health verdicts.
public interface ISignedBaselineProvider
{
    Task<bool> HasActiveSignedBaselineAsync(CancellationToken cancellationToken);
}

public interface IAppDataSpaceProbe
{
    Task<bool> HasWritableSpaceAsync(CancellationToken cancellationToken);
}

public interface IDatabaseHealthCheck
{
    Task<bool> IsHealthyAsync(CancellationToken cancellationToken);
}

// Fail-closed scan preflight: every check must pass and there is deliberately
// no override or "continue anyway" path. The sandbox self-test always runs so
// a degraded sandbox is reported even when other checks also fail.
public sealed class ScanPreflightService(
    ISandboxSelfTest sandboxSelfTest,
    ISignedBaselineProvider baselineProvider,
    IAppDataSpaceProbe spaceProbe,
    IDatabaseHealthCheck databaseHealthCheck)
{
    public async Task<ScanPreflightResult> ValidateAsync(ScanPreflightRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var errors = new List<PreflightError>();
        if (!IsExistingTarget(request.ScanRootPath))
        {
            errors.Add(new PreflightError(PreflightErrorCodes.RootInvalid,
                "Scan target is missing or is not a regular file or directory."));
        }

        if (!await baselineProvider.HasActiveSignedBaselineAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            errors.Add(new PreflightError(PreflightErrorCodes.BaselineInactive,
                "No active signed rule baseline."));
        }

        if (!await spaceProbe.HasWritableSpaceAsync(cancellationToken).ConfigureAwait(false))
        {
            errors.Add(new PreflightError(PreflightErrorCodes.AppDataNotWritable,
                "App-data or temp space is not writable."));
        }

        if (!await databaseHealthCheck.IsHealthyAsync(cancellationToken).ConfigureAwait(false))
        {
            errors.Add(new PreflightError(PreflightErrorCodes.DatabaseUnhealthy,
                "Scan database health check failed."));
        }

        SandboxSelfTestResult sandbox = await sandboxSelfTest.RunAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!sandbox.Passed)
        {
            errors.Add(new PreflightError(PreflightErrorCodes.SandboxUnavailable,
                sandbox.Code));
        }

        return new ScanPreflightResult(errors.Count == 0, errors);
    }

    public static bool IsExistingTarget(string? path) =>
        !string.IsNullOrWhiteSpace(path)
        && (Directory.Exists(path) || File.Exists(path));
}
