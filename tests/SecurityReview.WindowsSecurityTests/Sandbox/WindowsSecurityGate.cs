namespace SecurityReview.WindowsSecurityTests.Sandbox;

public static class WindowsSecurityGate
{
    public const string EnableVariable = "SECURITY_REVIEW_RUN_WINDOWS_SECURITY";
    public const string ProbeWorkerDirectoryVariable = "SECURITY_REVIEW_PROBE_WORKER_DIR";

    public static void AssertEnabled()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(),
            "Windows security lane requires a Windows host.");
        Assert.SkipWhen(Environment.GetEnvironmentVariable(EnableVariable) != "1",
            $"Set {EnableVariable}=1 to run the Windows security lane.");
    }
}
