namespace SecurityReview.Infrastructure.Windows.Sandbox;

public sealed record SandboxLaunchOptions(
    string ProfileName = AppContainerProfile.ProfileName,
    int HandshakeTimeoutMilliseconds = 15_000);
