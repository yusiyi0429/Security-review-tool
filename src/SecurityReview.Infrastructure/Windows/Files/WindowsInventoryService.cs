using System.Runtime.InteropServices;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Windows.Files;

// Counts planned streams and sums lengths with checked 64-bit arithmetic.
// The tripping stream is included in the observed totals; an overflowing
// addition is rejected without wrapping.
public sealed class StreamBudgetAccumulator(long maxStreams, long maxTotalBytes)
{
    private bool _tripped;

    public long StreamCount { get; private set; }
    public long TotalBytes { get; private set; }
    public bool Exceeded => _tripped;

    public bool TryAdd(long length)
    {
        long newTotal;
        try
        {
            newTotal = checked(TotalBytes + length);
        }
        catch (OverflowException)
        {
            StreamCount++;
            _tripped = true;
            return false;
        }

        StreamCount++;
        TotalBytes = newTotal;
        if (StreamCount > maxStreams || TotalBytes > maxTotalBytes)
        {
            _tripped = true;
            return false;
        }

        return true;
    }
}

// Root-bounded NTFS inventory: explicit-stack traversal, per-entry root
// containment, reparse points inspected but never followed, hidden/system
// entries included, ADS enumerated as one record per named stream, stable
// (volume, fileId, stream) identity with duplicate suppression, and
// input-scope limits that stop before parser scheduling. Diagnostics carry
// root-relative paths only.
public sealed class WindowsInventoryService : IInventoryService
{
    private const string Stage = "inventory";

    private readonly Func<string, string?> _fileSystemNameResolver;
    private readonly WindowsFileIdentityReader _identityReader = new();
    private readonly ReparsePointInspector _reparseInspector = new();
    private readonly AlternateDataStreamEnumerator _streamEnumerator = new();

    public WindowsInventoryService(Func<string, string?>? fileSystemNameResolver = null)
    {
        _fileSystemNameResolver = fileSystemNameResolver ?? ReadFileSystemName;
    }

    public Task<InventoryResult> BuildAsync(InventoryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.Run(() => Build(request, cancellationToken), cancellationToken);
    }

    private InventoryResult Build(InventoryRequest request, CancellationToken cancellationToken)
    {
        var gaps = new List<CoverageGap>();
        var boundary = new List<InventoryBoundaryRecord>();
        string canonicalRoot;
        try
        {
            canonicalRoot = Path.GetFullPath(request.RootPath)
                .TrimEnd(Path.DirectorySeparatorChar);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException
            or PathTooLongException)
        {
            return RootFailed(request);
        }

        if (!Directory.Exists(canonicalRoot) || File.Exists(canonicalRoot))
        {
            return RootFailed(request);
        }

        // A root whose identity cannot be read is a task-level failure, never
        // a partial empty inventory.
        try
        {
            _ = _identityReader.Read(canonicalRoot);
        }
        catch (Exception ex) when (ex is WindowsSecurityException or IOException
            or UnauthorizedAccessException)
        {
            return RootFailed(request);
        }

        string? fsName = _fileSystemNameResolver(canonicalRoot);
        AdsCapability adsCapability = string.Equals(fsName, "NTFS",
            StringComparison.OrdinalIgnoreCase)
            ? AdsCapability.Available
            : AdsCapability.NotAvailableForFileSystem;

        var files = new List<FileRecord>();
        var metadata = new List<InventoryMetadataUnit>();
        var seen = new HashSet<StreamKey>();
        var budget = new StreamBudgetAccumulator(request.MaxStreams, request.MaxTotalBytes);
        string rootPrefix = canonicalRoot + Path.DirectorySeparatorChar;

        var stack = new Stack<string>();
        stack.Push(canonicalRoot);
        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string directory = stack.Pop();
            List<string> entries;
            try
            {
                entries = [.. Directory.EnumerateFileSystemEntries(directory)];
            }
            catch (UnauthorizedAccessException)
            {
                gaps.Add(Gap(request.ScanId, RelativeOf(directory, rootPrefix),
                    GapReason.AccessDenied, "directory_enumeration_denied"));
                continue;
            }
            catch (IOException)
            {
                gaps.Add(Gap(request.ScanId, RelativeOf(directory, rootPrefix),
                    GapReason.AccessDenied, "directory_enumeration_failed"));
                continue;
            }

            foreach (string entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string fullPath;
                try
                {
                    fullPath = Path.GetFullPath(entry);
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException
                    or PathTooLongException)
                {
                    boundary.Add(new InventoryBoundaryRecord(RelativeOf(entry, rootPrefix),
                        InventoryBoundaryRecord.RootEscapeRejected));
                    continue;
                }

                // Per-entry root containment: normalized path must stay below
                // the canonical root.
                if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    boundary.Add(new InventoryBoundaryRecord(RelativeOf(fullPath, rootPrefix),
                        InventoryBoundaryRecord.RootEscapeRejected));
                    continue;
                }

                string relativePath = RelativeOf(fullPath, rootPrefix);
                FileAttributes attributes;
                DateTimeOffset lastWriteUtc;
                try
                {
                    attributes = File.GetAttributes(fullPath);
                    lastWriteUtc = File.GetLastWriteTimeUtc(fullPath);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    gaps.Add(Gap(request.ScanId, relativePath, GapReason.AccessDenied,
                        "attributes_unavailable"));
                    continue;
                }

                // Reparse points are inspected, recorded, and never followed.
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    _ = _reparseInspector.ReadTag(fullPath);
                    boundary.Add(new InventoryBoundaryRecord(relativePath,
                        InventoryBoundaryRecord.ReparsePointNotFollowed));
                    continue;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    stack.Push(fullPath);
                    continue;
                }

                FileStreamIdentity identity;
                long length;
                try
                {
                    identity = _identityReader.Read(fullPath);
                    length = new FileInfo(fullPath).Length;
                }
                catch (Exception ex) when (ex is WindowsSecurityException or IOException
                    or UnauthorizedAccessException or FileNotFoundException)
                {
                    gaps.Add(Gap(request.ScanId, relativePath, GapReason.AccessDenied,
                        "identity_unavailable"));
                    continue;
                }

                if (!TryAddStream(request, files, metadata, seen, budget, boundary, identity,
                    relativePath, streamName: null, length, lastWriteUtc, attributes, gaps))
                {
                    return ScopeExceeded(budget, adsCapability);
                }

                if (adsCapability != AdsCapability.Available)
                {
                    continue;
                }

                IReadOnlyList<(string Name, long Size)> streams;
                try
                {
                    streams = _streamEnumerator.Enumerate(fullPath);
                }
                catch (WindowsSecurityException)
                {
                    gaps.Add(Gap(request.ScanId, relativePath, GapReason.AccessDenied,
                        "stream_enumeration_failed"));
                    continue;
                }

                foreach ((string name, long size) in streams)
                {
                    FileStreamIdentity streamIdentity = identity with { StreamName = name };
                    if (!TryAddStream(request, files, metadata, seen, budget, boundary,
                        streamIdentity, relativePath, name, size, lastWriteUtc, attributes,
                        gaps))
                    {
                        return ScopeExceeded(budget, adsCapability);
                    }
                }
            }
        }

        return new InventoryResult(
            [.. InventoryOrdering.Order(files)],
            metadata,
            gaps,
            boundary,
            InventoryOutcome.Completed,
            null,
            budget.StreamCount,
            budget.TotalBytes,
            adsCapability);
    }

    private static bool TryAddStream(InventoryRequest request, List<FileRecord> files,
        List<InventoryMetadataUnit> metadata, HashSet<StreamKey> seen,
        StreamBudgetAccumulator budget, List<InventoryBoundaryRecord> boundary,
        FileStreamIdentity identity, string relativePath,
        string? streamName, long length, DateTimeOffset lastWriteUtc,
        FileAttributes attributes, List<CoverageGap> gaps)
    {
        if (!seen.Add(new StreamKey(identity.VolumeSerial, identity.FileIndex,
            streamName ?? string.Empty)))
        {
            // Duplicate (volume, fileId, stream): cycle suppression (hardlinks,
            // repeated identities), recorded but not inventoried twice.
            boundary.Add(new InventoryBoundaryRecord(relativePath,
                InventoryBoundaryRecord.DuplicateIdentitySkipped));
            return true;
        }

        if (!budget.TryAdd(length))
        {
            return false;
        }

        FileId fileId = identity.DeriveFileId(request.ScanId);
        var record = new FileRecord(fileId, 0, relativePath, null, streamName, length,
            lastWriteUtc, attributes, identity, ComponentTypesOf(relativePath, request.Components),
            InventoryStatus.Complete, null, null, CoverageStatus.NotCovered);
        files.Add(record);

        InventoryStatus status = AddMetadataUnits(request.ScanId, metadata, gaps, fileId,
            relativePath, streamName);
        if (status == InventoryStatus.MetadataGap)
        {
            files[^1] = record with { Status = InventoryStatus.MetadataGap };
        }

        return true;
    }

    private static InventoryStatus AddMetadataUnits(ScanId scanId,
        List<InventoryMetadataUnit> metadata, List<CoverageGap> gaps, FileId fileId,
        string relativePath, string? streamName)
    {
        InventoryStatus status = InventoryStatus.Complete;
#pragma warning disable CS8600 // Local-function nullability inference treats captured 'string' as nullable; the inputs are non-null by construction.
        void Add(InventoryMetadataKind kind, string value)
        {
            var locator = new SourceLocator.PathLocator(
                kind == InventoryMetadataKind.AdsName ? PathKind.Stream : PathKind.Segment,
                value);
            InventoryMetadataUnit? unit = InventoryMetadataUnit.TryCreate(fileId, kind,
                value, locator);
            if (unit is null)
            {
                status = InventoryStatus.MetadataGap;
                gaps.Add(Gap(scanId, relativePath, GapReason.Corrupt,
                    "metadata_value_out_of_bounds"));
                return;
            }

            metadata.Add(unit);
        }

        Add(InventoryMetadataKind.RelativePath, relativePath);
        string directoryPart = Path.GetDirectoryName(relativePath);
        if (!string.IsNullOrEmpty(directoryPart))
        {
            foreach (string segment in directoryPart.Split('/',
                StringSplitOptions.RemoveEmptyEntries))
            {
                Add(InventoryMetadataKind.DirectorySegment, segment);
            }
        }

        string fileName = Path.GetFileName(relativePath);
        Add(InventoryMetadataKind.FileName, fileName);
        string extension = Path.GetExtension(fileName);
        if (extension.Length > 1)
        {
            Add(InventoryMetadataKind.Extension, extension[1..]);
        }

        if (streamName is not null)
        {
            Add(InventoryMetadataKind.AdsName, streamName);
        }
#pragma warning restore CS8600

        return status;
    }

    private static List<AssetTypeId> ComponentTypesOf(string relativePath,
        IReadOnlyList<AssetComponent> components)
    {
        var types = new List<AssetTypeId>(1);
        foreach (AssetComponent component in components)
        {
            if (component.RelativePath == "."
                || string.Equals(component.RelativePath, relativePath,
                    StringComparison.OrdinalIgnoreCase)
                || relativePath.StartsWith(component.RelativePath + "/",
                    StringComparison.OrdinalIgnoreCase))
            {
                types.Add(component.AssetType);
            }
        }

        return types;
    }

    private static string RelativeOf(string fullPath, string rootPrefix)
    {
        if (fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return fullPath[rootPrefix.Length..].Replace(Path.DirectorySeparatorChar, '/');
        }

        // The root itself reports as "."; nothing below it ever leaks a full path.
        return ".";
    }

    private static CoverageGap Gap(ScanId scanId, string relativePath, GapReason reason,
        string detailCode) =>
        new(Guid.NewGuid(), scanId, null, relativePath, string.Empty, Stage, reason,
            detailCode, null, null, DateTimeOffset.UtcNow);

    private static InventoryResult RootFailed(InventoryRequest request) => new(
        [], [], [], [], InventoryOutcome.RootFailed, InventoryFailureCodes.RootUnavailable,
        0, 0, AdsCapability.Available);

    private static InventoryResult ScopeExceeded(StreamBudgetAccumulator budget,
        AdsCapability adsCapability) => new(
        [], [], [], [], InventoryOutcome.InputScopeExceeded,
        InventoryFailureCodes.InputScopeExceeded,
        budget.StreamCount, budget.TotalBytes, adsCapability);

    private static string? ReadFileSystemName(string canonicalRoot)
    {
        string? volumeRoot = Path.GetPathRoot(canonicalRoot);
        if (string.IsNullOrEmpty(volumeRoot))
        {
            return null;
        }

        nint buffer = Marshal.AllocHGlobal(512);
        try
        {
            if (!InventoryNative.GetVolumeInformation(volumeRoot, nint.Zero, 0, nint.Zero,
                nint.Zero, nint.Zero, buffer, 256))
            {
                return null;
            }

            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private readonly record struct StreamKey(string VolumeSerial, UInt128 FileIndex,
        string StreamName);
}
