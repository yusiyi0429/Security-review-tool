namespace SecurityReview.Parsers.Text;

/// <summary>
/// Tracks line and column positions while streaming through a byte sequence.
/// Maintains continuous mapping even when a single logical line is split across
/// multiple chunks. Thread-safe only for sequential single-producer use.
/// </summary>
public sealed class StreamingLineMap
{
    private long _currentLine = 1;
    private long _currentColumn = 1;
    private long _currentByteOffset;
    private bool _pendingLineSplit;

    /// <summary>Current 1-based line number.</summary>
    public long CurrentLine => _currentLine;

    /// <summary>Current 1-based column number.</summary>
    public long CurrentColumn => _currentColumn;

    /// <summary>Current byte offset.</summary>
    public long CurrentByteOffset => _currentByteOffset;

    /// <summary>
    /// Records that the previous chunk ended mid-line, so the next chunk
    /// should continue the column count without incrementing the line.
    /// </summary>
    public bool PendingLineSplit
    {
        get => _pendingLineSplit;
        set => _pendingLineSplit = value;
    }

    /// <summary>
    /// Advance through <paramref name="text"/> and update line/column counters.
    /// Returns the starting line and column for this segment.
    /// </summary>
    public (long StartLine, long StartColumn, long StartByte) Advance(ReadOnlySpan<char> text)
    {
        long startLine = _currentLine;
        long startColumn = _currentColumn;
        long startByte = _currentByteOffset;

        if (_pendingLineSplit)
        {
            // Continue on same line, don't reset column
            _pendingLineSplit = false;
        }

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\n')
            {
                _currentLine++;
                _currentColumn = 1;
            }
            else if (c == '\r')
            {
                // Handle \r\n as single newline
                if (i + 1 < text.Length && text[i + 1] == '\n')
                {
                    i++;
                }
                _currentLine++;
                _currentColumn = 1;
            }
            else
            {
                _currentColumn++;
            }
        }

        // Determine if we ended mid-line (no trailing newline)
        if (text.Length > 0)
        {
            char last = text[^1];
            if (last != '\n' && last != '\r')
            {
                _pendingLineSplit = true;
            }
        }

        return (startLine, startColumn, startByte);
    }

    /// <summary>
    /// Advance byte offset by <paramref name="bytes"/> without changing
    /// line/column state (for binary gaps or raw byte tracking).
    /// </summary>
    public void AdvanceBytes(long bytes)
    {
        _currentByteOffset += bytes;
    }

    /// <summary>
    /// Reset to initial state. Use when starting a new file.
    /// </summary>
    public void Reset()
    {
        _currentLine = 1;
        _currentColumn = 1;
        _currentByteOffset = 0;
        _pendingLineSplit = false;
    }
}
