using SecurityReview.Application.Scans.Preflight;

namespace SecurityReview.Infrastructure.Persistence;

public sealed class AppDataSpaceProbe : IAppDataSpaceProbe
{
    private const long MinimumFreeBytes = 16L * 1024 * 1024;
    private readonly string _directory;

    public AppDataSpaceProbe(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = Path.GetFullPath(directory);
    }

    public async Task<bool> HasWritableSpaceAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(_directory);
            string root = Path.GetPathRoot(_directory)
                ?? throw new IOException("App-data path has no volume root.");
            if (new DriveInfo(root).AvailableFreeSpace < MinimumFreeBytes)
                return false;

            string probePath = Path.Combine(
                _directory,
                $".write-probe-{Guid.NewGuid():N}.tmp");
            await using var stream = new FileStream(
                probePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.Asynchronous | FileOptions.DeleteOnClose);
            await stream.WriteAsync(new byte[] { 0 }, cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException)
        {
            return false;
        }
    }
}

public sealed class SqliteDatabaseHealthCheck : IDatabaseHealthCheck
{
    private readonly ISqliteConnectionFactory _connectionFactory;

    public SqliteDatabaseHealthCheck(
        ISqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory
            ?? throw new ArgumentNullException(nameof(connectionFactory));
    }

    public async Task<bool> IsHealthyAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await _connectionFactory
                .OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            DatabaseHealthResult result = await DatabaseHealthCheck
                .RunAsync(connection, cancellationToken)
                .ConfigureAwait(false);
            return result.IsHealthy;
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or Microsoft.Data.Sqlite.SqliteException)
        {
            return false;
        }
    }
}
