namespace SecurityReview.Application.Scans.Preflight;

public sealed record SandboxSelfTestResult(bool Passed, string Code, string WorkerSha256,
    string OsBuild, string ProfileSid, DateTimeOffset CheckedAtUtc)
{
    public const string OkCode = "ok";

    public static SandboxSelfTestResult Failed(string code) =>
        new(false, code, "", "", "", DateTimeOffset.UtcNow);
}
