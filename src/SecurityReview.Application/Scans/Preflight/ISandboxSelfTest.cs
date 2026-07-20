namespace SecurityReview.Application.Scans.Preflight;

public interface ISandboxSelfTest
{
    // Runs the bounded sandbox self-test. A passing result is valid only for
    // the worker build / OS build / profile / manifest / policy fingerprint it
    // was produced under; a failure must never be reported as a stale success.
    Task<SandboxSelfTestResult> RunAsync(CancellationToken cancellationToken);
}

public sealed record SandboxSelfTestFingerprint(string WorkerSha256, string OsBuild,
    string ProfileSid, string ManifestSha256, string PolicySha256);

public interface ISandboxSelfTestCache
{
    SandboxSelfTestResult? Read(SandboxSelfTestFingerprint fingerprint, DateTimeOffset nowUtc);
    void Write(SandboxSelfTestFingerprint fingerprint, SandboxSelfTestResult result);
}

// Process-local success cache. Success entries live at most 24 hours and only
// while the full fingerprint matches; failures are never stored.
public sealed class InMemorySandboxSelfTestCache : ISandboxSelfTestCache
{
    public static readonly TimeSpan SuccessLifetime = TimeSpan.FromHours(24);

    private readonly object _gate = new();
    private SandboxSelfTestFingerprint? _fingerprint;
    private SandboxSelfTestResult? _result;

    public SandboxSelfTestResult? Read(SandboxSelfTestFingerprint fingerprint,
        DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            if (_fingerprint is null || _result is null || _fingerprint != fingerprint
                || !_result.Passed || _result.CheckedAtUtc > nowUtc
                || nowUtc - _result.CheckedAtUtc > SuccessLifetime)
            {
                return null;
            }

            return _result;
        }
    }

    public void Write(SandboxSelfTestFingerprint fingerprint, SandboxSelfTestResult result)
    {
        if (!result.Passed)
        {
            return;
        }

        lock (_gate)
        {
            _fingerprint = fingerprint;
            _result = result;
        }
    }
}
