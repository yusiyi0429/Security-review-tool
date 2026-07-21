using System.Collections.Frozen;
using System.Text.RegularExpressions;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Compiles regular expressions with strict safety constraints:
/// NonBacktracking engine, CultureInvariant, 100 ms timeout (25 ms for built-in),
/// maximum pattern length 4,096, and no backreference/lookaround/conditional/balancing
/// constructs. Invalid patterns are rejected at import time.
/// </summary>
public static class SafeRegexFactory
{
    public const int MaxPatternLength = 4_096;

    // Built-in audited regexes → their actual compiled patterns.
    // Each built-in uses a 25 ms timeout and is validated for worst-case complexity.
    private static readonly FrozenDictionary<string, string> BuiltInPatterns =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["builtin-test-phone"] = @"\d{3}-\d{4}",
            ["builtin-email"] = @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ["builtin-ipv4"] = @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            ["builtin-url"] = @"https?://[^\s/$.?#].[^\s]*",
            ["builtin-ssh-private-key"] = @"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            ["builtin-pgp-private-key"] = @"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>
    /// Compile a safe regex from a user/signed-package pattern.
    /// </summary>
    public static Regex Create(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        if (pattern.Length == 0)
            throw new ArgumentException("Pattern must not be empty.", nameof(pattern));

        if (pattern.Length > MaxPatternLength)
            throw new ArgumentException(
                $"Pattern length {pattern.Length} exceeds maximum {MaxPatternLength}.", nameof(pattern));

        ValidateNoUnsafeConstructs(pattern);

        return new Regex(pattern,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            TimeSpan.FromMilliseconds(100));
    }

    /// <summary>
    /// Compile a built-in audited regex using the 25 ms timeout.
    /// Only patterns registered in the audited set are allowed.
    /// </summary>
    public static Regex CreateBuiltIn(string builtInKey)
    {
        ArgumentNullException.ThrowIfNull(builtInKey);

        if (!BuiltInPatterns.TryGetValue(builtInKey, out string? pattern))
        {
            throw new InvalidOperationException(
                $"'{builtInKey}' is not a registered built-in regex key.");
        }

        return new Regex(pattern,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            TimeSpan.FromMilliseconds(25));
    }

    /// <summary>
    /// Returns true if the key names a registered built-in audited pattern.
    /// </summary>
    public static bool IsBuiltIn(string key) => BuiltInPatterns.ContainsKey(key);

    private static void ValidateNoUnsafeConstructs(ReadOnlySpan<char> pattern)
    {
        // Walk the pattern looking for unsupported constructs.
        // NonBacktracking already rejects backreferences and lookaround at compile time,
        // but we reject them eagerly for clearer error messages during import.
        for (int i = 0; i < pattern.Length; i++)
        {
            char c = pattern[i];

            // Backslash sequences (backreferences, named backreferences, balancing)
            if (c == '\\' && i + 1 < pattern.Length)
            {
                char next = pattern[i + 1];
                if (next is >= '1' and <= '9')
                {
                    throw new ArgumentException(
                        "Pattern contains a backreference (\\1-\\9), which is not supported.", nameof(pattern));
                }

                if (next == 'k')
                {
                    throw new ArgumentException(
                        "Pattern contains a named backreference (\\k<name>), which is not supported.", nameof(pattern));
                }

                i++; // skip escaped character
                continue;
            }

            // Group constructs: (?
            if (c == '(' && i + 1 < pattern.Length && pattern[i + 1] == '?')
            {
                int groupStart = i + 2;
                if (groupStart >= pattern.Length) continue;

                char gc = pattern[groupStart];

                switch (gc)
                {
                    case '=':
                        throw new ArgumentException(
                            "Pattern contains a positive lookahead (?=...), which is not supported.", nameof(pattern));
                    case '!':
                        throw new ArgumentException(
                            "Pattern contains a negative lookahead (?!...), which is not supported.", nameof(pattern));
                    case '<':
                        {
                            if (groupStart + 1 >= pattern.Length) continue;
                            char afterAngle = pattern[groupStart + 1];
                            switch (afterAngle)
                            {
                                case '=':
                                    throw new ArgumentException(
                                        "Pattern contains a positive lookbehind (?<=...), which is not supported.", nameof(pattern));
                                case '!':
                                    throw new ArgumentException(
                                        "Pattern contains a negative lookbehind (?<!...), which is not supported.", nameof(pattern));
                            }

                            // Check for balancing group: (?<name1-name2>...)
                            if (IsBalancingGroup(pattern, groupStart))
                            {
                                throw new ArgumentException(
                                    "Pattern contains a balancing group definition, which is not supported.", nameof(pattern));
                            }

                            break;
                        }
                    case '(':
                        {
                            // Conditional: (?(condition)yes|no)
                            throw new ArgumentException(
                                "Pattern contains a conditional (?(...)...), which is not supported.", nameof(pattern));
                        }
                }
            }
        }
    }

    private static bool IsBalancingGroup(ReadOnlySpan<char> pattern, int posAfterQuestionMark)
    {
        // (?<name1-name2>...) — name1 and name2 separated by a hyphen inside angle brackets.
        // We need to find a name followed by '-' followed by another name, all within <...>
        int i = posAfterQuestionMark; // points to '<'
        if (i >= pattern.Length || pattern[i] != '<') return false;

        i++; // skip '<'
        bool sawHyphen = false;
        bool sawName2 = false;
        while (i < pattern.Length && pattern[i] != '>')
        {
            if (pattern[i] == '-')
            {
                sawHyphen = true;
            }
            else if (char.IsLetterOrDigit(pattern[i]) || pattern[i] == '_')
            {
                if (sawHyphen) sawName2 = true;
            }

            i++;
        }

        return sawHyphen && sawName2;
    }
}
