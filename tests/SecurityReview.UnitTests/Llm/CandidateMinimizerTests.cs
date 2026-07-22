using System.Text;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;

namespace SecurityReview.UnitTests.Llm;

/// <summary>
/// Tests for <see cref="CandidateMinimizer"/> and
/// <see cref="DeterministicSecretMasker"/>.
///
/// The brief fixes three concrete invariants:
///   1. Minimized context ≤ 16 KiB UTF-8.
///   2. Secrets are masked before cropping; overlap coalescing never unmasks.
///   3. Output carries candidate id, category hint, content kind, extension,
///      untrusted context, and truncation flags — but never an absolute path.
/// </summary>
public sealed class CandidateMinimizerTests
{
    public const int CandidateByteBudget = 16 * 1024;

    private static readonly CategoryId Sens001 = CategoryId.Parse("SENS-001");
    private static readonly CategoryId Sens002 = CategoryId.Parse("SENS-002");
    private static readonly RuleId RuleId = new("RULE-DET-001");
    private static readonly DetectorId DetectorId = new("DET-001");

    private static SemanticReviewRequest Build(
        string value,
        string context,
        SourceLocator locator,
        CategoryId category,
        string contentKind = "text",
        string extension = ".txt",
        string virtualPath = "docs/notes.txt",
        IReadOnlyList<DeterministicSecretSpan>? extraSecrets = null)
    {
        return new SemanticReviewRequest(
            CandidateId: new CandidateId(Guid.NewGuid()),
            CategoryHint: category,
            ContentKind: contentKind,
            Extension: extension,
            VirtualPath: virtualPath,
            FullContext: context,
            CandidateValue: value,
            CandidateLocator: locator,
            DeterministicSecrets: extraSecrets ?? Array.Empty<DeterministicSecretSpan>());
    }

    // ---------- DeterministicSecretMasker basics ----------

    [Fact]
    public void Masker_replaces_a_single_secret_with_redaction_token()
    {

        string masked = DeterministicSecretMasker.Mask(
            "header prefix 4111-1111-1111-1111 suffix",
            new[] { new DeterministicSecretSpan(14, 19, "SENS-005") });

        Assert.Equal("header prefix [REDACTED:SENS-005] suffix", masked);
    }

    [Fact]
    public void Masker_coalesces_overlapping_spans_into_a_single_token()
    {

        string masked = DeterministicSecretMasker.Mask(
            "AKIAABCDEFGHIJKLMNOP foo AKIAABCDEFGHIJKLMNOP",
            new[]
            {
                new DeterministicSecretSpan(0, 20, "SENS-002"),
                new DeterministicSecretSpan(25, 20, "SENS-002"),
            });

        Assert.Equal("[REDACTED:SENS-002] foo [REDACTED:SENS-002]", masked);
    }

    [Fact]
    public void Masker_does_not_unmask_through_overlap()
    {
        // Two overlapping spans on opposite sides of the same byte range —
        // the union must remain masked; the original secret bytes must
        // never reappear after merging.

        const string secret = "ABCDEFGHIJ0123456789";
        string masked = DeterministicSecretMasker.Mask(
            $"before-{secret}-after",
            new[]
            {
                // Both spans are well-formed and overlapping.
                new DeterministicSecretSpan(7, 16, "SENS-001"),
                new DeterministicSecretSpan(11, 16, "SENS-002"),
            });

        // The overlapping union must remain masked.
        Assert.DoesNotContain(secret.AsSpan(0, 16).ToString(), masked, StringComparison.Ordinal);
        Assert.DoesNotContain(secret.AsSpan(4, 16).ToString(), masked, StringComparison.Ordinal);
        // The whole original secret span must not be visible in plaintext.
        Assert.DoesNotContain(secret, masked, StringComparison.Ordinal);
    }

    [Fact]
    public void Masker_skips_zero_length_spans()
    {

        string masked = DeterministicSecretMasker.Mask("hello world",
            new[] { new DeterministicSecretSpan(0, 0, "SENS-001") });

        Assert.Equal("hello world", masked);
    }

    [Fact]
    public void Masker_normalizes_unsorted_spans()
    {

        // Caller passes spans out of order; the masker must still apply
        // them in left-to-right order without losing any byte.
        string masked = DeterministicSecretMasker.Mask(
            "AKIAABCDEFGHIJKLMNOP foo AKIAABCDEFGHIJKLMNOP",
            new[]
            {
                new DeterministicSecretSpan(25, 20, "SENS-002"),
                new DeterministicSecretSpan(0, 20, "SENS-002"),
            });

        Assert.Equal("[REDACTED:SENS-002] foo [REDACTED:SENS-002]", masked);
    }

    // ---------- CandidateMinimizer basics ----------

    [Fact]
    public void Minimizer_keeps_context_under_byte_budget()
    {
        const string target = "TARGET";
        string context = new string('x', CandidateByteBudget - 256) + target;
        var locator = new SourceLocator.TextLocator(1, 1, CandidateByteBudget - 256, target.Length);


        var result = CandidateMinimizer.Minimize(Build(target, context, locator, Sens001));

        Assert.True(result.PackedUtf8ByteLength <= CandidateByteBudget,
            $"Packed payload exceeded budget: {result.PackedUtf8ByteLength}");
    }

    [Fact]
    public void Minimizer_masks_secrets_before_byte_cropping()
    {
        const string secret = "AKIAABCDEFGHIJKLMNOPQ";
        string filler = new string('a', 4096);
        string context = $"{filler} {secret} {filler}";
        int secretStart = filler.Length + 1;
        var locator = new SourceLocator.TextLocator(1, 1, secretStart, secret.Length);


        var result = CandidateMinimizer.Minimize(Build(
            secret, context, locator, Sens002,
            extraSecrets: new[]
            {
                new DeterministicSecretSpan(secretStart, secret.Length, "SENS-002"),
            }));

        Assert.DoesNotContain(secret, result.UntrustedContext, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:SENS-002]", result.UntrustedContext, StringComparison.Ordinal);
        Assert.True(result.SecretRedactions > 0);
        Assert.True(result.PackedUtf8ByteLength <= CandidateByteBudget);
    }

    [Fact]
    public void Minimizer_does_not_emit_absolute_paths()
    {
        const string target = "TARGET";
        string context = "irrelevant context with target inside";
        var locator = new SourceLocator.TextLocator(1, 1, 30, target.Length);


        var result = CandidateMinimizer.Minimize(Build(
            target, context, locator, Sens001,
            contentKind: "archive",
            extension: ".xlsx",
            virtualPath: @"C:\Users\alice\Documents\confidential.xlsx"));

        Assert.DoesNotContain(@"C:\Users\alice", result.UntrustedContext, StringComparison.Ordinal);
        Assert.DoesNotContain("confidential.xlsx", result.UntrustedContext, StringComparison.Ordinal);
        Assert.Equal(".xlsx", result.Extension);
        Assert.Equal("archive", result.ContentKind);
    }

    [Fact]
    public void Minimizer_classifies_content_kind_from_extension()
    {


        var docx = CandidateMinimizer.Minimize(Build(
            "x", "y", new SourceLocator.TextLocator(1, 1, 0, 1), Sens001,
            contentKind: "archive", extension: ".docx",
            virtualPath: @"C:\temp\a.docx"));
        Assert.Equal("archive", docx.ContentKind);

        var bin = CandidateMinimizer.Minimize(Build(
            "x", "y", new SourceLocator.TextLocator(1, 1, 0, 1), Sens001,
            contentKind: "binary", extension: ".bin",
            virtualPath: @"C:\temp\a.bin"));
        Assert.Equal("binary", bin.ContentKind);

        var text = CandidateMinimizer.Minimize(Build(
            "x", "y", new SourceLocator.TextLocator(1, 1, 0, 1), Sens001,
            contentKind: "text", extension: ".md",
            virtualPath: "docs/readme.md"));
        Assert.Equal("text", text.ContentKind);
    }

    [Fact]
    public void Minimizer_crops_multibyte_chinese_text_on_scalar_boundaries()
    {
        const string sentence = "敏感数据在生产数据库中。";
        StringBuilder sb = new();
        while (Encoding.UTF8.GetByteCount(sb.ToString()) < CandidateByteBudget - 256)
        {
            sb.Append(sentence);
        }
        string context = sb.ToString();
        int byteOffset = Encoding.UTF8.GetByteCount(context) / 2;
        var locator = new SourceLocator.TextLocator(1, 1, byteOffset, 6);


        var result = CandidateMinimizer.Minimize(Build("sensitive", context, locator, Sens001));

        byte[] bytes = Encoding.UTF8.GetBytes(result.UntrustedContext);
        Assert.True(bytes.Length <= CandidateByteBudget);
        Assert.True(IsValidUtf8(bytes));
        Assert.False(HasUnpairedSurrogate(result.UntrustedContext));
    }

    [Fact]
    public void Minimizer_keeps_candidate_near_start_of_context()
    {
        const string target = "TARGET_HERE";
        string context = $"{target} " + new string('x', 8 * 1024);
        var locator = new SourceLocator.TextLocator(1, 1, 0, target.Length);


        var result = CandidateMinimizer.Minimize(Build(target, context, locator, Sens001));

        Assert.Contains(target, result.UntrustedContext, StringComparison.Ordinal);
        Assert.True(Encoding.UTF8.GetByteCount(result.UntrustedContext) <= CandidateByteBudget);
        Assert.Equal(0, result.ContextLeftTruncatedBytes);
    }

    [Fact]
    public void Minimizer_keeps_candidate_near_end_of_context()
    {
        const string target = "TARGET_HERE";
        string filler = new string('x', 8 * 1024);
        string context = $"{filler} {target}";
        int byteOffset = Encoding.UTF8.GetByteCount(filler) + 1;
        var locator = new SourceLocator.TextLocator(1, 1, byteOffset, target.Length);


        var result = CandidateMinimizer.Minimize(Build(target, context, locator, Sens001));

        Assert.Contains(target, result.UntrustedContext, StringComparison.Ordinal);
        Assert.True(Encoding.UTF8.GetByteCount(result.UntrustedContext) <= CandidateByteBudget);
        Assert.Equal(0, result.ContextRightTruncatedBytes);
    }

    [Fact]
    public void Minimizer_marks_truncation_flags_when_window_clipped()
    {
        const string target = "TARGET";
        string left = new string('L', 12 * 1024);
        string right = new string('R', 12 * 1024);
        string context = $"{left} {target} {right}";
        int targetStart = Encoding.UTF8.GetByteCount(left) + 1;
        var locator = new SourceLocator.TextLocator(1, 1, targetStart, target.Length);


        var result = CandidateMinimizer.Minimize(Build(target, context, locator, Sens001));

        Assert.True(result.ContextLeftTruncatedBytes > 0);
        Assert.True(result.ContextRightTruncatedBytes > 0);
        Assert.True(result.ContextTruncated);
        Assert.Contains(target, result.UntrustedContext, StringComparison.Ordinal);
    }

    [Fact]
    public void Minimizer_with_no_context_returns_empty_untrusted_context()
    {

        var result = CandidateMinimizer.Minimize(Build(
            "v", "", new SourceLocator.TextLocator(1, 1, 0, 1), Sens001));

        Assert.Equal(string.Empty, result.UntrustedContext);
        Assert.Equal(0, result.UntrustedContext.Length);
        Assert.False(result.ContextTruncated);
    }

    [Fact]
    public void Minimizer_coalesces_secret_masking_across_candidate_overlap()
    {
        const string secret = "AKIAABCDEFGHIJKLMNOPQ";
        string context = $"prefix {secret} suffix";
        int secretStart = "prefix ".Length;
        var locator = new SourceLocator.TextLocator(1, 1, secretStart, secret.Length);


        var result = CandidateMinimizer.Minimize(Build(
            secret, context, locator, Sens002,
            extraSecrets: new[]
            {
                new DeterministicSecretSpan(secretStart, secret.Length, "SENS-002"),
            }));

        Assert.DoesNotContain(secret, result.UntrustedContext, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:SENS-002]", result.UntrustedContext, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:SENS-002]", result.RedactedCandidateValue, StringComparison.Ordinal);
    }

    [Fact]
    public void Minimizer_drops_other_candidates_and_retains_only_target_provenance()
    {
        const string target = "TARGET";
        const string other = "OTHER";
        string context = $"{other} payload {target} after";
        int otherStart = 0;
        int targetStart = "OTHER payload ".Length;
        var locator = new SourceLocator.TextLocator(1, 1, targetStart, target.Length);


        var request = new SemanticReviewRequest(
            CandidateId: new CandidateId(Guid.NewGuid()),
            CategoryHint: Sens001,
            ContentKind: "text",
            Extension: ".txt",
            VirtualPath: "docs/notes.txt",
            FullContext: context,
            CandidateValue: target,
            CandidateLocator: locator,
            DeterministicSecrets: new[]
            {
                new DeterministicSecretSpan(otherStart, other.Length, "SENS-002"),
            });
        var result = CandidateMinimizer.Minimize(request);

        Assert.Equal(request.CandidateId, result.CandidateId);
        Assert.Equal(Sens001, result.CategoryHint);
        Assert.DoesNotContain(other, result.UntrustedContext, StringComparison.Ordinal);
        Assert.Contains(target, result.UntrustedContext, StringComparison.Ordinal);
    }

    [Fact]
    public void Minimizer_payload_invariant_is_stable_under_normalization()
    {
        const string target = "TARGET";
        string filler = new string('a', 4096);
        string context = $"{filler}\u0000\u0000\u0000{target}\u0000\u0000";
        int byteOffset = filler.Length + 3;
        var locator = new SourceLocator.TextLocator(1, 1, byteOffset, target.Length);


        var result = CandidateMinimizer.Minimize(Build(target, context, locator, Sens001));

        Assert.True(result.PackedUtf8ByteLength <= CandidateByteBudget);
        Assert.DoesNotContain("\u0000", result.UntrustedContext, StringComparison.Ordinal);
    }

    [Fact]
    public void Minimizer_redacts_secret_value_when_candidate_is_itself_a_secret()
    {
        const string secret = "AKIAABCDEFGHIJKLMNOPQ";
        string context = $"prefix {secret} suffix";
        int secretStart = "prefix ".Length;
        var locator = new SourceLocator.TextLocator(1, 1, secretStart, secret.Length);


        var result = CandidateMinimizer.Minimize(Build(
            secret, context, locator, Sens002,
            extraSecrets: new[]
            {
                new DeterministicSecretSpan(secretStart, secret.Length, "SENS-002"),
            }));

        // The candidate value field is redacted; the original secret never
        // reappears in any output field.
        Assert.DoesNotContain(secret, result.RedactedCandidateValue, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:SENS-002]", result.RedactedCandidateValue, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, result.UntrustedContext, StringComparison.Ordinal);
    }

    [Fact]
    public void Minimizer_preserves_candidate_value_when_not_a_secret()
    {
        const string value = "ordinary-text-not-a-secret";
        const string context = "before ordinary-text-not-a-secret after";


        var result = CandidateMinimizer.Minimize(Build(
            value, context,
            new SourceLocator.TextLocator(1, 1, 7, value.Length),
            Sens001));

        Assert.Equal(value, result.RedactedCandidateValue);
    }

    private static bool IsValidUtf8(byte[] bytes)
    {
        try
        {
            _ = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool HasUnpairedSurrogate(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1]))
                    return true;
                i++;
            }
            else if (char.IsLowSurrogate(s[i]))
            {
                return true;
            }
        }
        return false;
    }
}
