using SecurityReview.Application.Abstractions;

namespace SecurityReview.Infrastructure.Persistence;

public sealed class FileSystemDiskCapacityProvider : IDiskCapacityProvider
{
    private readonly string _path;

    public FileSystemDiskCapacityProvider(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public long GetFreeBytes()
    {
        try
        {
            string root = Path.GetPathRoot(_path)
                ?? throw new IOException("Cache path has no volume root.");
            return new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or ArgumentException)
        {
            return 0;
        }
    }
}
