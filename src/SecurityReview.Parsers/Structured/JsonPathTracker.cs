using System.Buffers;
using System.Text;

namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Tracks JSON Pointer (RFC 6901) paths during streaming JSON tokenization.
/// Maintains an internal stack of object property names and array indices,
/// emitting fully-escaped JSON Pointer paths on demand
/// (<c>~</c> → <c>~0</c>, <c>/</c> → <c>~1</c>).
/// </summary>
internal sealed class JsonPathTracker
{
    private readonly record struct PathSegment(string PropertyName, int ArrayIndex)
    {
        public bool IsArray => PropertyName.Length == 0 && ArrayIndex >= 0;
    }

    private readonly Stack<PathSegment> _stack = new();

    /// <summary>Current depth in the JSON structure (number of segments).</summary>
    public int Depth => _stack.Count;

    /// <summary>Push an object property name onto the path.</summary>
    public void PushProperty(string propertyName)
    {
        _stack.Push(new PathSegment(propertyName, -1));
    }

    /// <summary>Push an array index onto the path.</summary>
    public void PushIndex(int index)
    {
        _stack.Push(new PathSegment(string.Empty, index));
    }

    /// <summary>Pop the current segment (end of object/array).</summary>
    public void Pop()
    {
        if (_stack.Count > 0)
            _stack.Pop();
    }

    /// <summary>
    /// Returns the current JSON Pointer path as an RFC 6901-escaped string.
    /// Example: <c>/users/1/token</c>.
    /// </summary>
    public string ToJsonPointer()
    {
        if (_stack.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        // Stack is reversed (top is deepest), so collect in array and reverse
        var segments = _stack.Reverse().ToArray();

        foreach (var seg in segments)
        {
            sb.Append('/');
            if (seg.IsArray)
            {
                sb.Append(seg.ArrayIndex);
            }
            else
            {
                sb.Append(EscapeJsonPointer(seg.PropertyName));
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Escape a reference token per RFC 6901:
    /// <c>~</c> → <c>~0</c>, <c>/</c> → <c>~1</c>.
    /// </summary>
    private static string EscapeJsonPointer(string token)
    {
        if (token.IndexOf('~') < 0 && token.IndexOf('/') < 0)
            return token;

        var sb = new StringBuilder(token.Length + 4);
        foreach (char c in token)
        {
            switch (c)
            {
                case '~': sb.Append("~0"); break;
                case '/': sb.Append("~1"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}
