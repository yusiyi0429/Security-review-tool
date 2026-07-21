namespace SecurityReview.Parsers.Core;

/// <summary>
/// Handle-backed input for a single parse operation. The underlying OS file
/// handle is owned by the worker; this wrapper provides a managed stream view.
/// The caller must dispose this instance when the parse is complete.
/// </summary>
public sealed class ParserInput : IAsyncDisposable
{
    private readonly Stream _stream;
    private bool _disposed;

    public ParserInput(Stream stream, long declaredLength)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        DeclaredLength = declaredLength;
    }

    /// <summary>Declared length of the source in bytes (may be an estimate).</summary>
    public long DeclaredLength { get; }

    /// <summary>
    /// The seekable stream over the source. Callers must not dispose this
    /// stream directly — dispose <see cref="ParserInput"/> instead.
    /// </summary>
    public Stream Stream => _disposed
        ? throw new ObjectDisposedException(nameof(ParserInput))
        : _stream;

    public ValueTask DisposeAsync()
    {
        if (_disposed) return ValueTask.CompletedTask;
        _disposed = true;
        return _stream.DisposeAsync();
    }
}
