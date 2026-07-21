using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Hashing;
using SecurityReview.Infrastructure.Windows.Native;

namespace SecurityReview.Infrastructure.Windows.Files;

[SupportedOSPlatform("windows")]
public sealed class BrokeredReadHandle : IBrokeredReadHandle
{
    internal BrokeredReadHandle(FileSnapshot snapshot, string displayId, SafeFileHandle handle)
    {
        InitialSnapshot = snapshot;
        DisplayId = displayId;
        Handle = handle;
    }

    public FileSnapshot InitialSnapshot { get; }
    public string DisplayId { get; }
    internal SafeFileHandle Handle { get; }

    public void Dispose() => Handle.Dispose();
}

// Read-only file broker: every open goes through GENERIC_READ with full share
// mode and FILE_FLAG_SEQUENTIAL_SCAN, never granting any write or delete
// access. Identity and size are queried from the handle, not from path
// metadata. The trusted path assembly for ADS validates the stream name
// (no extra separator, no colon, no NUL, no dot) before joining.
public sealed class WindowsReadOnlyFileBroker : IFileHandleBroker
{
    private const uint GenericRead = 0x8000_0000;
    private const uint FileShareRead = 0x0000_0001;
    private const uint FileShareWrite = 0x0000_0002;
    private const uint FileShareDelete = 0x0000_0004;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x0000_0080;
    private const uint FileFlagSequentialScan = 0x0800_0000;

    private readonly Sha256StreamHasher _hasher = new();
    private readonly FileOpenRetryPolicy _retryPolicy;

    public WindowsReadOnlyFileBroker(FileOpenRetryPolicy? retryPolicy = null)
    {
        _retryPolicy = retryPolicy ?? new FileOpenRetryPolicy();
    }

    // Exposed for tests that need a custom retry delay without touching the
    // static Task.Delay path.
    internal WindowsReadOnlyFileBroker(Func<TimeSpan, CancellationToken, Task> delay)
        : this(new FileOpenRetryPolicy(delay: delay))
    {
    }

    public Task<BrokeredReadHandle> OpenAsync(string scanRootPath, FileRecord file,
        CancellationToken cancellationToken) =>
        OpenAsync(scanRootPath, file, eventLog: null, cancellationToken);

    public async Task<BrokeredReadHandle> OpenAsync(string scanRootPath, FileRecord file,
        List<FileOpenRetryEvent>? eventLog, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(scanRootPath);
        ArgumentNullException.ThrowIfNull(file);

        RetryOutcome<BrokeredReadHandle> outcome = await _retryPolicy.ExecuteAsync<BrokeredReadHandle>(
            async ct => await OpenKeepHandleAsync(file, scanRootPath, ct),
            eventLog, cancellationToken).ConfigureAwait(false);
        return outcome.Value;
    }

    // Open path, query identity/size/lastWrite, hash, return BrokeredReadHandle
    // that keeps the handle open for later duplication into a worker process.
    private async Task<BrokeredReadHandle> OpenKeepHandleAsync(FileRecord file, string scanRootPath,
        CancellationToken cancellationToken)
    {
        string fullPath = BuildAbsolutePath(scanRootPath, file);
        SafeFileHandle handle = FileBrokerNative.OpenForRead(
            InventoryNative.ToExtendedPath(fullPath));
        try
        {
            FileStreamIdentity identity = FileBrokerNative.ReadIdentity(handle, file.StreamName);
            long length = FileBrokerNative.ReadLength(handle);
            DateTimeOffset lastWrite = FileBrokerNative.ReadLastWriteUtc(handle);

            string hex = await HashHandleAsync(handle, length, cancellationToken).ConfigureAwait(false);
            string displayId = RedactedDisplayId(identity, length);
            var snapshot = new FileSnapshot(identity, length, lastWrite, hex, DateTimeOffset.UtcNow);
            return new BrokeredReadHandle(snapshot, displayId, handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // Open path, hash, close, return just the snapshot. Used by the file
    // snapshot service which never duplicates the handle into a worker.
    internal async Task<FileSnapshot> OpenAndSnapshotAsync(string scanRootPath, FileRecord file,
        CancellationToken cancellationToken)
    {
        string fullPath = BuildAbsolutePath(scanRootPath, file);
        SafeFileHandle handle = FileBrokerNative.OpenForRead(
            InventoryNative.ToExtendedPath(fullPath));
        try
        {
            FileStreamIdentity identity = FileBrokerNative.ReadIdentity(handle, file.StreamName);
            long length = FileBrokerNative.ReadLength(handle);
            DateTimeOffset lastWrite = FileBrokerNative.ReadLastWriteUtc(handle);
            string hex = await HashHandleAsync(handle, length, cancellationToken).ConfigureAwait(false);
            return new FileSnapshot(identity, length, lastWrite, hex, DateTimeOffset.UtcNow);
        }
        finally
        {
            handle.Dispose();
        }
    }

    // Reads from a handle into the ArrayPool hasher via ReadFile.
    private async Task<string> HashHandleAsync(SafeFileHandle handle, long length,
        CancellationToken cancellationToken)
    {
        using var stream = new ReadOnlyHandleStream(handle, Sha256StreamHasher.BufferSize);
        return await _hasher.ComputeAsync(stream, length, cancellationToken).ConfigureAwait(false);
    }

    private static string BuildAbsolutePath(string scanRootPath, FileRecord file)
    {
        string relative = file.RelativePath.Replace('/', Path.DirectorySeparatorChar);
        string basePath = Path.Combine(scanRootPath, relative);
        return file.StreamName is null
            ? basePath
            : AppendAds(basePath, file.StreamName);
    }

    private static string AppendAds(string basePath, string streamName)
    {
        ValidateStreamName(streamName);
        return basePath + ":" + streamName;
    }

    private static void ValidateStreamName(string streamName)
    {
        if (string.IsNullOrEmpty(streamName))
        {
            throw new WindowsSecurityException("ValidateStreamName", 87);
        }

        foreach (char c in streamName)
        {
            if (c == ':' || c == '/' || c == '\\' || c == '\0' || c == '.')
            {
                throw new WindowsSecurityException("ValidateStreamName", 87);
            }
        }
    }

    private static string RedactedDisplayId(FileStreamIdentity identity, long length) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            $"{identity.VolumeSerial}:{identity.FileIndex:X32}:{(identity.StreamName ?? string.Empty)}:{length}")))
        [..12].ToLowerInvariant();

    public Task<long> DuplicateReadOnlyAsync(SafeFileHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken) =>
        FileBrokerNative.DuplicateAsync(source, targetProcess, cancellationToken);

    public Task<long> DuplicateReadOnlyAsync(IBrokeredReadHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (source is not BrokeredReadHandle handle)
        {
            throw new WindowsSecurityException("BrokeredReadHandle", 6);
        }

        return FileBrokerNative.DuplicateAsync(handle.Handle, targetProcess, cancellationToken);
    }
}

// Minimal Stream adapter over a SafeFileHandle plus a reusable byte[]
// buffer. Reads synchronously via ReadFile and copies into the caller's
// Memory<byte> span. The handle is never closed by the stream (the owning
// BrokeredReadHandle or snapshot path is responsible for disposal).
[SupportedOSPlatform("windows")]
internal sealed partial class ReadOnlyHandleStream : Stream
{
    private readonly SafeFileHandle _handle;
    private readonly byte[] _buffer;
    private long _position;

    public ReadOnlyHandleStream(SafeFileHandle handle, int bufferSize)
    {
        _handle = handle;
        _buffer = new byte[bufferSize];
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count)
    {
        int want = Math.Min(count, _buffer.Length);
        int read = ReadInto(_buffer, want);
        if (read > 0)
        {
            Array.Copy(_buffer, 0, buffer, offset, read);
            _position += read;
        }
        return read;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> destination,
        CancellationToken cancellationToken = default)
    {
        int want = Math.Min(destination.Length, _buffer.Length);
        int read = ReadInto(_buffer, want);
        if (read > 0)
        {
            _buffer.AsSpan(0, read).CopyTo(destination.Span);
            _position += read;
        }
        return new ValueTask<int>(read);
    }

    private int ReadInto(byte[] destination, int want)
    {
        unsafe
        {
            fixed (byte* p = &MemoryMarshal.GetReference(destination.AsSpan()))
            {
                if (!ReadFile(_handle, (nint)p, (uint)want, out int read, nint.Zero))
                {
                    int err = Marshal.GetLastPInvokeError();
                    throw new WindowsSecurityException("ReadFile", err);
                }

                return read;
            }
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadFile")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReadFile(SafeFileHandle handle, nint buffer, uint bytesToRead,
        out int bytesRead, nint overlapped);
}

[SupportedOSPlatform("windows")]
internal static class FileBrokerNative
{
    public static SafeFileHandle OpenForRead(string extendedPath)
    {
        SafeFileHandle handle = NativeMethods.CreateFile(extendedPath,
            WindowsReadOnlyFileBrokerConstants.GenericRead,
            WindowsReadOnlyFileBrokerConstants.FileShareRead
                | WindowsReadOnlyFileBrokerConstants.FileShareWrite
                | WindowsReadOnlyFileBrokerConstants.FileShareDelete,
            nint.Zero, WindowsReadOnlyFileBrokerConstants.OpenExisting,
            WindowsReadOnlyFileBrokerConstants.FileAttributeNormal
                | WindowsReadOnlyFileBrokerConstants.FileFlagSequentialScan,
            nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new WindowsSecurityException("CreateFileW", error);
        }

        return handle;
    }

    public static FileStreamIdentity ReadIdentity(SafeFileHandle handle, string? streamName)
    {
        nint buffer = Marshal.AllocHGlobal(24);
        try
        {
            if (!NativeMethods.GetFileInformationByHandleEx(handle,
                InventoryNative.FileIdInfoClass, buffer, 24))
            {
                throw new WindowsSecurityException("GetFileInformationByHandleEx",
                    Marshal.GetLastPInvokeError());
            }

            long volumeSerial = Marshal.ReadInt64(buffer);
            ulong lo = (ulong)Marshal.ReadInt64(buffer + 8);
            ulong hi = (ulong)Marshal.ReadInt64(buffer + 16);
            return new FileStreamIdentity(
                volumeSerial.ToString("X16", CultureInfo.InvariantCulture),
                new UInt128(hi, lo),
                streamName);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static long ReadLength(SafeFileHandle handle)
    {
        long length;
        if (!NativeMethods.GetFileSizeEx(handle, out length))
        {
            throw new WindowsSecurityException("GetFileSizeEx", Marshal.GetLastPInvokeError());
        }

        return length;
    }

    public static DateTimeOffset ReadLastWriteUtc(SafeFileHandle handle)
    {
        long outValue;
        if (!NativeMethods.GetFileTime(handle, nint.Zero, nint.Zero, out outValue))
        {
            throw new WindowsSecurityException("GetFileTime", Marshal.GetLastPInvokeError());
        }

        return new DateTimeOffset(DateTime.FromFileTimeUtc(outValue), TimeSpan.Zero);
    }

    public static async Task<long> DuplicateAsync(SafeFileHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(targetProcess);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        if (!NativeMethods.DuplicateHandle(NativeMethods.GetCurrentProcess(), source,
            targetProcess, out nint duplicated, WindowsReadOnlyFileBrokerConstants.GenericRead, false, 0))
        {
            throw new WindowsSecurityException("DuplicateHandle",
                Marshal.GetLastPInvokeError());
        }

        return (long)duplicated;
    }

    public static SafeFileHandle OpenCurrentProcess() =>
        new(NativeMethods.GetCurrentProcess(), ownsHandle: false);
}

[SupportedOSPlatform("windows")]
internal static partial class NativeMethods
{
    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateFileW",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFileHandle CreateFile(string fileName, uint desiredAccess,
        uint shareMode, nint securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, nint templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandleEx(SafeFileHandle file,
        int informationClass, nint information, uint bufferSize);

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileSizeEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileSizeEx(SafeFileHandle file, out long fileSize);

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileTime")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileTime(SafeFileHandle file, nint lpCreationTime,
        nint lpLastAccessTime, out long lpLastWriteTime);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DuplicateHandle(nint sourceProcess, SafeFileHandle source,
        SafeHandle targetProcess, out nint targetHandle, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [LibraryImport("kernel32.dll")]
    internal static partial nint GetCurrentProcess();
}

[SupportedOSPlatform("windows")]
internal static class WindowsReadOnlyFileBrokerConstants
{
    public const uint GenericRead = 0x8000_0000;
    public const uint FileShareRead = 0x0000_0001;
    public const uint FileShareWrite = 0x0000_0002;
    public const uint FileShareDelete = 0x0000_0004;
    public const uint OpenExisting = 3;
    public const uint FileAttributeNormal = 0x0000_0080;
    public const uint FileFlagSequentialScan = 0x0800_0000;
}
