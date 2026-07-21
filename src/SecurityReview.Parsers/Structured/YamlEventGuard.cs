namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Guards YAML parsing against resource exhaustion. Counts depth, events,
/// aliases, per-scalar length, and per-anchor expansion factor. Rejects
/// alias cycles before expansion.
/// </summary>
internal sealed class YamlEventGuard
{
    public const int MaxDepth = 128;
    public const int MaxEvents = 1_000_000;
    public const int MaxAliases = 10_000;
    public const int MaxScalarLength = 1_048_576; // 1 MiB
    public const int AnchorExpansionFactor = 100;
    public const long MaxStructureSize = 67_108_864; // 64 MiB

    private int _eventCount;
    private int _aliasCount;
    private int _currentDepth;
    private readonly HashSet<string> _expandingAnchors = new();

    /// <summary>Current event count.</summary>
    public int EventCount => _eventCount;

    /// <summary>Current depth.</summary>
    public int Depth => _currentDepth;

    /// <summary>
    /// Record an event. Returns true if within limits, false otherwise.
    /// </summary>
    public bool RecordEvent()
    {
        _eventCount++;
        return _eventCount <= MaxEvents;
    }

    /// <summary>Begin a mapping or sequence, increasing depth.</summary>
    public bool EnterStructure()
    {
        _currentDepth++;
        return _currentDepth <= MaxDepth;
    }

    /// <summary>End a mapping or sequence, decreasing depth.</summary>
    public void ExitStructure()
    {
        if (_currentDepth > 0)
            _currentDepth--;
    }

    /// <summary>Register an alias reference. Returns true if within limits.</summary>
    public bool RecordAlias(string anchorName)
    {
        _aliasCount++;
        if (_aliasCount > MaxAliases)
            return false;

        // Check for cycles: an anchor being expanded within itself
        if (!_expandingAnchors.Add(anchorName))
            return false;

        return true;
    }

    /// <summary>Complete an alias expansion.</summary>
    public void CompleteAlias(string anchorName)
    {
        _expandingAnchors.Remove(anchorName);
    }

    /// <summary>Check if a scalar exceeds the per-scalar length limit.</summary>
    public static bool ScalarExceedsLimit(int length) => length > MaxScalarLength;

    /// <summary>Check if the total structure size exceeds the limit.</summary>
    public static bool StructureExceedsLimit(long size) => size > MaxStructureSize;
}
