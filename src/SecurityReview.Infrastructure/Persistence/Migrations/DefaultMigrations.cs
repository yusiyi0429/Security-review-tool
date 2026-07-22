namespace SecurityReview.Infrastructure.Persistence.Migrations;

/// <summary>
/// Defines the ordered production database migration set. Keeping the list in
/// one place prevents the desktop startup path and focused integration tests
/// from silently creating different schemas.
/// </summary>
public static class DefaultMigrations
{
    public static IReadOnlyList<IMigration> Create() =>
    [
        new Migration001Initial(),
        new Migration002LlmAttempts(),
        new Migration003ScanSnapshots(),
    ];
}
