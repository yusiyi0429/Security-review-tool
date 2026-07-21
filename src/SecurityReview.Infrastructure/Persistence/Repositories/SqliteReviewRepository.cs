using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteReviewRepository : IReviewRepository
{
    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;

    private const string DecisionTable = "review_decisions";
    private const string GrantTable = "exception_grants";
    private const string DecisionField = "encrypted_payload";
    private const string GrantField = "encrypted_payload";

    public SqliteReviewRepository(
        ISqliteConnectionFactory factory,
        IPayloadProtector protector)
    {
        _factory = factory;
        _protector = protector;
    }

    // ---------- Decisions ----------

    public async Task InsertDecisionAsync(ReviewDecision decision, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO review_decisions (decision_id, scan_id, group_id, occurrence_id,
                status, user_sid_hmac, decided_at_utc, encrypted_payload)
            VALUES (@decisionId, @scanId, @groupId, @occurrenceId, @status, @userSidHmac,
                @decidedAtUtc, @encryptedPayload);
            """;

        byte[] encryptedPayloadJson = EncryptDecisionPayload(decision);

        cmd.Parameters.AddWithValue("@decisionId", decision.Id.Value.ToString());
        cmd.Parameters.AddWithValue("@scanId", decision.ScanId.Value.ToString());
        cmd.Parameters.AddWithValue("@groupId",
            (object?)decision.GroupId?.Value.ToString() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@occurrenceId",
            (object?)decision.OccurrenceId?.Value.ToString() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@status", (int)decision.Status);
        cmd.Parameters.AddWithValue("@userSidHmac", decision.UserSidHmac);
        cmd.Parameters.AddWithValue("@decidedAtUtc", decision.DecidedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@encryptedPayload", encryptedPayloadJson);

        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ReviewDecision>> GetDecisionsByOccurrenceAsync(
        FindingOccurrenceId occurrenceId, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT decision_id, scan_id, group_id, occurrence_id, status,
                user_sid_hmac, decided_at_utc, encrypted_payload
            FROM review_decisions
            WHERE occurrence_id = @occurrenceId
            ORDER BY decided_at_utc DESC, decision_id DESC;
            """;
        cmd.Parameters.AddWithValue("@occurrenceId", occurrenceId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var decisions = new List<ReviewDecision>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            decisions.Add(ReadDecision(reader));
        }

        return decisions;
    }

    public async Task<IReadOnlyList<ReviewDecision>> GetDecisionsByGroupAsync(
        FindingGroupId groupId, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT decision_id, scan_id, group_id, occurrence_id, status,
                user_sid_hmac, decided_at_utc, encrypted_payload
            FROM review_decisions
            WHERE group_id = @groupId
            ORDER BY decided_at_utc DESC, decision_id DESC;
            """;
        cmd.Parameters.AddWithValue("@groupId", groupId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var decisions = new List<ReviewDecision>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            decisions.Add(ReadDecision(reader));
        }

        return decisions;
    }

    public async Task<ReviewDecision?> GetDecisionByIdAsync(DecisionId id, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT decision_id, scan_id, group_id, occurrence_id, status,
                user_sid_hmac, decided_at_utc, encrypted_payload
            FROM review_decisions
            WHERE decision_id = @decisionId;
            """;
        cmd.Parameters.AddWithValue("@decisionId", id.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            return null;

        return ReadDecision(reader);
    }

    // ---------- Exception Grants ----------

    public async Task InsertExceptionGrantAsync(ExceptionGrant grant, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO exception_grants (exception_id, asset_binding_hmac,
                occurrence_binding_hmac, rule_pack_hash, valid_until_utc,
                created_at_utc, user_sid_hmac, encrypted_payload)
            VALUES (@exceptionId, @assetBindingHmac, @occurrenceBindingHmac,
                @rulePackHash, @validUntilUtc, @createdAtUtc, @userSidHmac,
                @encryptedPayload);
            """;

        byte[] encryptedPayloadJson = EncryptGrantPayload(grant);

        // The occurrence binding is (filePathHmac + locatorHmac + valueHmac + ruleId).
        string occurrenceBindingHmac = ComputeOccurrenceBinding(grant.Binding);

        cmd.Parameters.AddWithValue("@exceptionId", grant.Id.Value.ToString());
        cmd.Parameters.AddWithValue("@assetBindingHmac", ComputeAssetBinding(grant.Binding));
        cmd.Parameters.AddWithValue("@occurrenceBindingHmac", occurrenceBindingHmac);
        cmd.Parameters.AddWithValue("@rulePackHash", grant.RulePackHash);
        cmd.Parameters.AddWithValue("@validUntilUtc", grant.ValidUntilUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@createdAtUtc", grant.CreatedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@userSidHmac", grant.UserSidHmac);
        cmd.Parameters.AddWithValue("@encryptedPayload", encryptedPayloadJson);

        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ExceptionGrant>> GetActiveGrantsByBindingAsync(
        string assetBindingHmac, string occurrenceBindingHmac, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT exception_id, asset_binding_hmac, occurrence_binding_hmac,
                rule_pack_hash, valid_until_utc, created_at_utc, user_sid_hmac,
                encrypted_payload
            FROM exception_grants
            WHERE asset_binding_hmac = @assetBindingHmac
              AND occurrence_binding_hmac = @occurrenceBindingHmac
              AND valid_until_utc > @nowUtc
            ORDER BY created_at_utc DESC;
            """;
        cmd.Parameters.AddWithValue("@assetBindingHmac", assetBindingHmac);
        cmd.Parameters.AddWithValue("@occurrenceBindingHmac", occurrenceBindingHmac);
        cmd.Parameters.AddWithValue("@nowUtc", DateTimeOffset.UtcNow.ToString("O"));

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var grants = new List<ExceptionGrant>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            grants.Add(ReadGrant(reader));
        }

        return grants;
    }

    public async Task<ExceptionGrant?> GetGrantByIdAsync(ExceptionGrantId id, CancellationToken ct = default)
    {
        await using var connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT exception_id, asset_binding_hmac, occurrence_binding_hmac,
                rule_pack_hash, valid_until_utc, created_at_utc, user_sid_hmac,
                encrypted_payload
            FROM exception_grants
            WHERE exception_id = @exceptionId;
            """;
        cmd.Parameters.AddWithValue("@exceptionId", id.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            return null;

        return ReadGrant(reader);
    }

    // ---------- Private helpers ----------

    private byte[] EncryptDecisionPayload(ReviewDecision decision)
    {
        var payload = new ReviewDecisionPayload(
            EncryptedReason: decision.EncryptedReason ?? "",
            Status: (int)decision.Status,
            ReasonCode: decision.ReasonCode);

        byte[] jsonBytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(payload, ReviewRepositoryJsonContext.Default.ReviewDecisionPayload));
        var encrypted = _protector.Protect(
            DecisionTable, decision.Id.Value.ToString(), DecisionField, jsonBytes);
        return Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(encrypted, ReviewRepositoryJsonContext.Default.EncryptedPayload));
    }

    private ReviewDecision ReadDecision(SqliteDataReader reader)
    {
        var decisionId = new DecisionId(Guid.Parse(reader.GetString(0)));
        var scanId = new ScanId(Guid.Parse(reader.GetString(1)));
        string? groupIdText = reader.IsDBNull(2) ? null : reader.GetString(2);
        string? occurrenceIdText = reader.IsDBNull(3) ? null : reader.GetString(3);
        var status = (ReviewStatus)reader.GetInt32(4);
        string userSidHmac = reader.GetString(5);
        var decidedAtUtc = DateTimeOffset.Parse(reader.GetString(6), System.Globalization.CultureInfo.InvariantCulture);

        byte[] encryptedJson = GetBlobBytes(reader, 7);
        var encryptedPayload = JsonSerializer.Deserialize(
            Encoding.UTF8.GetString(encryptedJson),
            ReviewRepositoryJsonContext.Default.EncryptedPayload)!;

        byte[] plaintext = _protector.Unprotect(
            DecisionTable, decisionId.Value.ToString(), DecisionField, encryptedPayload);
        var payload = JsonSerializer.Deserialize(
            plaintext, ReviewRepositoryJsonContext.Default.ReviewDecisionPayload)!;

        FindingGroupId? groupId = groupIdText is not null
            ? new FindingGroupId(Guid.Parse(groupIdText)) : null;
        FindingOccurrenceId? occurrenceId = occurrenceIdText is not null
            ? new FindingOccurrenceId(Guid.Parse(occurrenceIdText)) : null;

        return new ReviewDecision(
            decisionId, scanId, groupId, occurrenceId, status,
            payload.ReasonCode, payload.EncryptedReason, userSidHmac, decidedAtUtc);
    }

    private byte[] EncryptGrantPayload(ExceptionGrant grant)
    {
        var bindingPayload = new ExceptionBindingPayload(
            AssetIdHmac: grant.Binding.AssetIdHmac,
            AssetVersionHmac: grant.Binding.AssetVersionHmac,
            FilePathHmac: grant.Binding.FilePathHmac,
            CanonicalLocatorHmac: grant.Binding.CanonicalLocatorHmac,
            ValueHmac: grant.Binding.ValueHmac,
            RuleId: grant.Binding.RuleId);

        var payload = new ExceptionGrantPayload(
            EncryptedReason: grant.EncryptedReason,
            Binding: bindingPayload);

        byte[] jsonBytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(payload, ReviewRepositoryJsonContext.Default.ExceptionGrantPayload));
        var encrypted = _protector.Protect(
            GrantTable, grant.Id.Value.ToString(), GrantField, jsonBytes);
        return Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(encrypted, ReviewRepositoryJsonContext.Default.EncryptedPayload));
    }

    private ExceptionGrant ReadGrant(SqliteDataReader reader)
    {
        var grantId = new ExceptionGrantId(Guid.Parse(reader.GetString(0)));
        string assetBindingHmac = reader.GetString(1);
        string occurrenceBindingHmac = reader.GetString(2);
        string rulePackHash = reader.GetString(3);
        var validUntilUtc = DateTimeOffset.Parse(reader.GetString(4), System.Globalization.CultureInfo.InvariantCulture);
        var createdAtUtc = DateTimeOffset.Parse(reader.GetString(5), System.Globalization.CultureInfo.InvariantCulture);
        string userSidHmac = reader.GetString(6);

        byte[] encryptedJson = GetBlobBytes(reader, 7);
        var encryptedPayload = JsonSerializer.Deserialize(
            Encoding.UTF8.GetString(encryptedJson),
            ReviewRepositoryJsonContext.Default.EncryptedPayload)!;

        byte[] plaintext = _protector.Unprotect(
            GrantTable, grantId.Value.ToString(), GrantField, encryptedPayload);
        var payload = JsonSerializer.Deserialize(
            plaintext, ReviewRepositoryJsonContext.Default.ExceptionGrantPayload)!;

        var binding = ExceptionBinding.Create(
            payload.Binding.AssetIdHmac,
            payload.Binding.AssetVersionHmac,
            payload.Binding.FilePathHmac,
            payload.Binding.CanonicalLocatorHmac,
            payload.Binding.ValueHmac,
            rulePackHash,
            payload.Binding.RuleId);

        return new ExceptionGrant(
            grantId, binding, rulePackHash, validUntilUtc, createdAtUtc,
            userSidHmac, payload.EncryptedReason);
    }

    private static string ComputeAssetBinding(ExceptionBinding binding)
    {
        // Asset binding = asset ID HMAC + asset version HMAC.
        return $"{binding.AssetIdHmac}|{binding.AssetVersionHmac}";
    }

    private static string ComputeOccurrenceBinding(ExceptionBinding binding)
    {
        // Occurrence binding = file path HMAC + locator HMAC + value HMAC + rule ID.
        return $"{binding.FilePathHmac}|{binding.CanonicalLocatorHmac}|{binding.ValueHmac}|{binding.RuleId}";
    }

    private static byte[] GetBlobBytes(SqliteDataReader reader, int ordinal)
    {
        using var stream = reader.GetStream(ordinal);
        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }
}

// ---------- Payload DTOs and JSON source-gen context ----------

internal sealed record ReviewDecisionPayload(
    string EncryptedReason,
    int Status,
    string ReasonCode);

internal sealed record ExceptionGrantPayload(
    string EncryptedReason,
    ExceptionBindingPayload Binding);

internal sealed record ExceptionBindingPayload(
    string AssetIdHmac,
    string AssetVersionHmac,
    string FilePathHmac,
    string CanonicalLocatorHmac,
    string ValueHmac,
    string RuleId);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ReviewDecisionPayload))]
[JsonSerializable(typeof(ExceptionGrantPayload))]
[JsonSerializable(typeof(ExceptionBindingPayload))]
[JsonSerializable(typeof(EncryptedPayload))]
internal partial class ReviewRepositoryJsonContext : JsonSerializerContext;
