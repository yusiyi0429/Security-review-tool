using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using ReviewDecisionStatus = SecurityReview.Domain.Reviews.ReviewStatus;
using ReviewDecision = SecurityReview.Domain.Reviews.ReviewDecision;
using ExceptionBinding = SecurityReview.Domain.Reviews.ExceptionBinding;
using ExceptionGrant = SecurityReview.Domain.Reviews.ExceptionGrant;
namespace SecurityReview.Application.Reviews;

/// <summary>
/// Service that records append-only review decisions and manages exact,
/// time-bounded exception grants. All reasons are encrypted at rest.
/// </summary>
public sealed class ReviewService : IReviewService
{
    private readonly IReviewRepository _repository;
    private readonly IPayloadProtector _protector;
    private readonly IValueFingerprintService _fingerprint;
    private readonly IWindowsIdentityProvider _identityProvider;

    private const string Table = "review_decisions";
    private const string ExceptionTable = "exception_grants";
    private const string Field = "encrypted_payload";

    public ReviewService(
        IReviewRepository repository,
        IPayloadProtector protector,
        IValueFingerprintService fingerprint,
        IWindowsIdentityProvider identityProvider)
    {
        _repository = repository;
        _protector = protector;
        _fingerprint = fingerprint;
        _identityProvider = identityProvider;
    }

    public async Task<ReviewDecision> RecordReviewAsync(
        RecordReviewCommand command, CancellationToken ct = default)
    {
        var identity = _identityProvider.GetCurrentUser()
            ?? throw new InvalidOperationException("No Windows user identity available.");

        string userSidHmac = ComputeUserSidHmac(identity.UserSid);

        string? encryptedReason = null;
        if (command.Status != ReviewDecisionStatus.Pending)
        {
            encryptedReason = EncryptReason(command.Reason, Table, Guid.NewGuid().ToString());
        }

        var decision = ReviewDecision.Create(
            command.ScanId,
            command.GroupId,
            command.OccurrenceId,
            command.Status,
            command.ReasonCode,
            encryptedReason,
            userSidHmac,
            DateTimeOffset.UtcNow);

        await _repository.InsertDecisionAsync(decision, ct).ConfigureAwait(false);
        return decision;
    }

    public async Task<ExceptionGrant> GrantExceptionAsync(
        GrantExceptionCommand command, CancellationToken ct = default)
    {
        var identity = _identityProvider.GetCurrentUser()
            ?? throw new InvalidOperationException("No Windows user identity available.");

        string userSidHmac = ComputeUserSidHmac(identity.UserSid);

        // Compute HMAC bindings for exact matching.
        string assetIdHmac = ComputeHmac(command.AssetId);
        string assetVersionHmac = ComputeHmac(command.AssetVersion);
        string filePathHmac = ComputeHmac(command.FilePath);
        string locatorHmac = ComputeHmac(command.CanonicalLocator);
        string valueHmac = ComputeHmac(command.FindingValue);

        var binding = ExceptionBinding.Create(
            assetIdHmac, assetVersionHmac, filePathHmac, locatorHmac,
            valueHmac, command.RulePackHash, command.RuleId);

        // Encrypt the reason.
        string encryptedReason = EncryptReason(
            command.Reason, ExceptionTable, Guid.NewGuid().ToString());

        var grant = ExceptionGrant.Create(
            binding,
            command.RulePackHash,
            command.ValidUntilUtc,
            userSidHmac,
            encryptedReason);

        // Create the corresponding ApprovedException decision.
        var decision = ReviewDecision.Create(
            command.ScanId,
            groupId: null,
            command.OccurrenceId,
            ReviewDecisionStatus.ApprovedException,
            "exception_granted",
            encryptedReason,
            userSidHmac,
            DateTimeOffset.UtcNow);

        await _repository.InsertDecisionAsync(decision, ct).ConfigureAwait(false);
        await _repository.InsertExceptionGrantAsync(grant, ct).ConfigureAwait(false);
        return grant;
    }

    public async Task<EffectiveReviewResult> GetEffectiveStatusAsync(
        FindingOccurrenceId occurrenceId,
        string assetBindingHmac,
        string occurrenceBindingHmac,
        CancellationToken ct = default)
    {
        // 1. Get the latest decision for this occurrence.
        var decisions = await _repository.GetDecisionsByOccurrenceAsync(occurrenceId, ct)
            .ConfigureAwait(false);

        var latestDecision = decisions
            .OrderByDescending(d => d.DecidedAtUtc)
            .ThenByDescending(d => d.Id.Value)
            .FirstOrDefault();

        // 2. Check for active exception grants.
        var activeGrants = await _repository.GetActiveGrantsByBindingAsync(
            assetBindingHmac, occurrenceBindingHmac, ct).ConfigureAwait(false);

        var hasActiveGrant = activeGrants.Count > 0;

        if (hasActiveGrant)
        {
            // Exact match with an active grant → ApprovedException.
            return new EffectiveReviewResult(
                ReviewDecisionStatus.ApprovedException, "exception_granted", DateTimeOffset.UtcNow);
        }

        if (latestDecision is not null)
        {
            if (latestDecision.Status == ReviewDecisionStatus.ApprovedException && !hasActiveGrant)
            {
                // Grant expired or binding mismatch → no longer applicable.
                return new EffectiveReviewResult(
                    ReviewDecisionStatus.Pending, "exception_not_applicable", DateTimeOffset.UtcNow);
            }

            return new EffectiveReviewResult(
                latestDecision.Status,
                latestDecision.ReasonCode,
                latestDecision.DecidedAtUtc);
        }

        // No decision at all → Pending.
        return new EffectiveReviewResult(
            ReviewDecisionStatus.Pending, "not_reviewed", null);
    }

    /// <summary>
    /// Compute a keyed HMAC-SHA256 of the user SID for the searchable column.
    /// </summary>
    private string ComputeUserSidHmac(string userSid)
    {
        var fp = _fingerprint.Compute(userSid);
        return fp.HexString;
    }

    /// <summary>
    /// Compute a keyed HMAC for binding fields.
    /// </summary>
    private string ComputeHmac(string value)
    {
        var fp = _fingerprint.Compute(value);
        return fp.HexString;
    }

    /// <summary>
    /// Encrypt a reason string using the payload protector.
    /// Returns the serialized encrypted payload as a JSON string.
    /// </summary>
    private string EncryptReason(string reason, string table, string recordId)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(reason);
        var encrypted = _protector.Protect(table, recordId, Field, plaintext);
        return JsonSerializer.Serialize(encrypted, ReviewJsonContext.Default.EncryptedPayload);
    }
}

// ---------- JSON source-gen context ----------

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(EncryptedPayload))]
internal sealed partial class ReviewJsonContext : JsonSerializerContext;
