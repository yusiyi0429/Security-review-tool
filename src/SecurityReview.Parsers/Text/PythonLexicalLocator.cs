namespace SecurityReview.Parsers.Text;

/// <summary>
/// Lexical kind produced by <see cref="PythonLexicalLocator"/>.
/// </summary>
public enum PythonLexicalKind
{
    Comment,
    StringLiteral,
    RawString,
    Bytes,
    FString,
    TripleString,
    RawTripleString,
}

/// <summary>
/// A lexical occurrence in a Python source. Carries the original text plus
/// exact 1-based line and column coordinates.
/// </summary>
public readonly record struct PythonLexicalToken(
    PythonLexicalKind Kind,
    string Text,
    int StartLine,
    int StartColumn,
    int EndLine,
    int EndColumn)
{
    public int StartOffset { get; init; }
    public int EndOffset { get; init; }
}

/// <summary>
/// Result of <see cref="PythonLexicalLocator.Locate"/>. Static locator only:
/// no import, no compile, no execution, no environment discovery, and no
/// referenced-file resolution. The locator consumes already-decoded text.
/// </summary>
public readonly record struct PythonLexicalResult(
    IReadOnlyList<PythonLexicalToken> Tokens,
    bool HasInvalidTail)
{
    public static PythonLexicalResult Empty { get; } =
        new(Array.Empty<PythonLexicalToken>(), false);
}

/// <summary>
/// Static lexical locator for Python source code. Records comments, normal
/// strings, raw strings, bytes literals, f-strings, and triple-quoted
/// strings with exact line/column positions. Operates on decoded text only;
/// callers are expected to feed text decoded by
/// <see cref="TextEncodingDetector"/>.
/// </summary>
public static class PythonLexicalLocator
{
    /// <summary>
    /// Locate all comment / string / bytes / f-string lexical occurrences in
    /// <paramref name="source"/>. The locator does not validate syntax; it only
    /// recognizes the lexical structure required for security review.
    /// </summary>
    public static PythonLexicalResult Locate(string source)
    {
        if (string.IsNullOrEmpty(source))
            return PythonLexicalResult.Empty;

        var tokens = new List<PythonLexicalToken>();
        bool hasInvalidTail = false;

        int line = 1;
        int column = 1;
        int i = 0;

        while (i < source.Length)
        {
            char c = source[i];

            // Newline tracking
            if (c == '\n')
            {
                line++;
                column = 1;
                i++;
                continue;
            }

            if (c == '\r')
            {
                line++;
                column = 1;
                i++;
                if (i < source.Length && source[i] == '\n') i++;
                continue;
            }

            // Comments
            if (c == '#')
            {
                int startLine = line;
                int startColumn = column;
                int start = i;
                int endLine = line;
                int endColumn = column;
                while (i < source.Length && source[i] != '\n' && source[i] != '\r')
                {
                    i++;
                    endColumn++;
                }
                tokens.Add(new PythonLexicalToken(
                    PythonLexicalKind.Comment,
                    source[start..i],
                    startLine, startColumn,
                    endLine, endColumn)
                {
                    StartOffset = start,
                    EndOffset = i,
                });
                continue;
            }

            // String literals (possibly prefixed by r, b, f, rb, br, etc.)
            if (c == '\'' || c == '"')
            {
                int prefixStart = FindStringPrefixStart(source, i);
                int lineAtPrefix = line;
                int columnAtPrefix = column;
                for (int k = prefixStart; k < i; k++)
                {
                    if (source[k] == '\n')
                    {
                        lineAtPrefix++;
                        columnAtPrefix = 1;
                    }
                    else if (source[k] == '\r')
                    {
                        lineAtPrefix++;
                        columnAtPrefix = 1;
                        if (k + 1 < i && source[k + 1] == '\n') k++;
                    }
                    else
                    {
                        columnAtPrefix++;
                    }
                }

                ScanResult scan = ScanStringLiteral(source, i);
                if (scan.Kind is null)
                {
                    hasInvalidTail = true;
                    int startLine = lineAtPrefix;
                    int startColumn = columnAtPrefix;
                    int start = prefixStart;
                    while (i < source.Length && source[i] != '\n' && source[i] != '\r')
                        i++;
                    int endLine = line;
                    int endColumn = column;
                    tokens.Add(new PythonLexicalToken(
                        PythonLexicalKind.StringLiteral,
                        source[start..i],
                        startLine, startColumn,
                        endLine, endColumn)
                    {
                        StartOffset = start,
                        EndOffset = i,
                    });
                    continue;
                }

                int sl = lineAtPrefix;
                int sc = columnAtPrefix;
                int textStart = prefixStart;
                AdvanceThrough(source, ref i, ref line, ref column, scan.Length);
                int el = line;
                int ec = column;
                tokens.Add(new PythonLexicalToken(
                    scan.Kind!.Value,
                    source[textStart..i],
                    sl, sc,
                    el, ec)
                {
                    StartOffset = textStart,
                    EndOffset = i,
                });
                continue;
            }

            // Non-lexical character: advance by one
            column++;
            i++;
        }

        return new PythonLexicalResult(tokens, hasInvalidTail);
    }

    /// <summary>
    /// Determine the lexical kind of a string literal starting at
    /// <paramref name="start"/>. Returns null when the quote is unmatched and
    /// the caller should record a truncated token.
    /// </summary>
    private static ScanResult ScanStringLiteral(
        string source, int start)
    {
        // Walk backwards over prefix letters (r, b, f, u, R, B, F, U).
        // Python allows combinations such as rb, br, Rb, etc. Limit to two
        // prefix characters to match common practice; more than two never
        // changes the byte semantics we record.
        int prefixStart = start;
        int prefixCount = 0;
        int j = start - 1;
        while (j >= 0 && prefixCount < 2)
        {
            char p = source[j];
            if (p is 'r' or 'R' or 'b' or 'B' or 'f' or 'F' or 'u' or 'U')
            {
                prefixStart = j;
                j--;
                prefixCount++;
            }
            else break;
        }

        bool raw = false;
        bool bytes = false;
        bool fstring = false;
        for (int k = prefixStart; k < start; k++)
        {
            char p = source[k];
            if (p is 'r' or 'R') raw = true;
            else if (p is 'b' or 'B') bytes = true;
            else if (p is 'f' or 'F') fstring = true;
        }

        char quote = source[start];
        bool triple = start + 2 < source.Length
                      && source[start + 1] == quote
                      && source[start + 2] == quote;

        if (triple)
            return ScanTripleQuoted(source, start, quote, raw, bytes, fstring);

        return ScanSingleQuoted(source, start, quote, raw, bytes, fstring);
    }

    private static ScanResult ScanSingleQuoted(
        string source, int start, char quote, bool raw, bool bytes, bool fstring)
    {
        int i = start + 1;
        while (i < source.Length)
        {
            char c = source[i];
            if (c == '\\')
            {
                // Skip escape: backslash + next char
                i += 2;
                continue;
            }
            if (c == quote)
            {
                int length = (i + 1) - start;
                PythonLexicalKind kind = ChooseKind(raw, bytes, fstring, triple: false);
                return new ScanResult(kind, length);
            }
            if (c == '\n' || c == '\r')
                return ScanResult.Invalid;
            i++;
        }
        return ScanResult.Invalid;
    }

    private static ScanResult ScanTripleQuoted(
        string source, int start, char quote, bool raw, bool bytes, bool fstring)
    {
        int i = start + 3;
        while (i < source.Length)
        {
            char c = source[i];
            if (c == '\\' && !raw)
            {
                i += 2;
                continue;
            }
            if (c == quote
                && i + 2 < source.Length
                && source[i + 1] == quote
                && source[i + 2] == quote)
            {
                int length = (i + 3) - start;
                PythonLexicalKind kind = ChooseKind(raw, bytes, fstring, triple: true);
                return new ScanResult(kind, length);
            }
            i++;
        }
        return ScanResult.Invalid;
    }

    private static PythonLexicalKind ChooseKind(bool raw, bool bytes, bool fstring, bool triple)
    {
        if (triple)
        {
            if (raw) return PythonLexicalKind.RawTripleString;
            return PythonLexicalKind.TripleString;
        }

        // Per Python spec, raw+bytes / raw+f / bytes+f are invalid; we treat
        // them as Bytes/FString to preserve the literal for review.
        if (raw) return PythonLexicalKind.RawString;
        if (bytes) return PythonLexicalKind.Bytes;
        if (fstring) return PythonLexicalKind.FString;
        return PythonLexicalKind.StringLiteral;
    }

    private static void AdvanceThrough(string source, ref int i, ref int line, ref int column, int length)
    {
        int end = i + length;
        while (i < end && i < source.Length)
        {
            char c = source[i];
            if (c == '\n')
            {
                line++;
                column = 1;
                i++;
            }
            else if (c == '\r')
            {
                line++;
                column = 1;
                i++;
                if (i < source.Length && source[i] == '\n') i++;
            }
            else
            {
                column++;
                i++;
            }
        }
    }

    private readonly record struct ScanResult(PythonLexicalKind? Kind, int Length)
    {
        public static ScanResult Invalid { get; } = new(null, 0);
    }

    /// <summary>
    /// Walk backwards from <paramref name="quoteIndex"/> over prefix letters
    /// (r, b, f, u — case-insensitive). Returns the index of the leftmost
    /// prefix letter, or <paramref name="quoteIndex"/> when no prefix exists.
    /// Limits the walk to two prefix characters because Python only allows
    /// combinations like rb/br and never more.
    /// </summary>
    private static int FindStringPrefixStart(string source, int quoteIndex)
    {
        int start = quoteIndex;
        int count = 0;
        int j = quoteIndex - 1;
        while (j >= 0 && count < 2)
        {
            char p = source[j];
            if (p is 'r' or 'R' or 'b' or 'B' or 'f' or 'F' or 'u' or 'U')
            {
                start = j;
                j--;
                count++;
            }
            else break;
        }

        return start;
    }
}
