using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteFindingRepository : IFindingRepository
{
    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;
    private readonly IValueFingerprintService _fingerprint;

    private const string Table = "finding_occurrences";
    private const string Field = "encrypted_payload";
    private const int BatchSize = 500;

    public SqliteFindingRepository(
        ISqliteConnectionFactory factory,
        IPayloadProtector protector,
        IValueFingerprintService fingerprint)
    {
        _factory = factory;
        _protector = protector;
        _fingerprint = fingerprint;
    }

    public async Task InsertGroupAsync(ScanId scanId, FindingGroup group, CancellationToken cancellationToken = default)
    {
        string valueHmac = _fingerprint.Compute(group.ValueFingerprint.HexString).HexString;
        int maxConfidence = group.Occurrences
            .SelectMany(o => o.Provenance)
            .Max(p => (int)p.Confidence);

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO finding_groups (group_id, scan_id, value_hmac, category_id,
                severity, confidence, difference_status)
            VALUES (@groupId, @scanId, @valueHmac, @categoryId, @severity,
                @confidence, @differenceStatus)
            ON CONFLICT(group_id) DO UPDATE SET
                severity = MIN(finding_groups.severity, excluded.severity),
                confidence = MAX(finding_groups.confidence, excluded.confidence);
            """;
        cmd.Parameters.AddWithValue("@groupId", group.Id.Value.ToString());
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());
        cmd.Parameters.AddWithValue("@valueHmac", valueHmac);
        cmd.Parameters.AddWithValue("@categoryId", (int)group.FindingKind);
        cmd.Parameters.AddWithValue("@severity", (int)group.Severity);
        cmd.Parameters.AddWithValue("@confidence", maxConfidence);
        cmd.Parameters.AddWithValue("@differenceStatus", (int)DifferenceStatus.New);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task InsertOccurrenceAsync(FileId fileId, FindingOccurrence occurrence, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = CreateOccurrenceInsertCommand(connection, fileId, occurrence);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task InsertOccurrenceBatchAsync(
        FileId fileId, IReadOnlyList<FindingOccurrence> occurrences, CancellationToken cancellationToken = default)
    {
        for (int offset = 0; offset < occurrences.Count; offset += BatchSize)
        {
            int batchCount = Math.Min(BatchSize, occurrences.Count - offset);
            await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var tx = connection.BeginTransaction();

            try
            {
                await using var cmd = connection.CreateCommand();
                PrepareOccurrenceInsertCommand(cmd);

                for (int i = 0; i < batchCount; i++)
                {
                    BindOccurrenceParameters(cmd, fileId, occurrences[offset + i]);
                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw;
            }
        }
    }

    public async Task<FindingGroup?> GetGroupByIdAsync(FindingGroupId id, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);

        // Read the group row.
        await using var groupCmd = connection.CreateCommand();
        groupCmd.CommandText = """
            SELECT group_id, scan_id, value_hmac, category_id, severity, confidence,
                difference_status
            FROM finding_groups
            WHERE group_id = @groupId;
            """;
        groupCmd.Parameters.AddWithValue("@groupId", id.Value.ToString());

        await using var groupReader = await groupCmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await groupReader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;

        var groupId = new FindingGroupId(Guid.Parse(groupReader.GetString(0)));
        var findingKind = (FindingKind)groupReader.GetInt32(3);
        var severity = (Severity)groupReader.GetInt32(4);
        string valueHmac = groupReader.GetString(2);

        // We store the HMAC of the fingerprint's hex string for searchability.
        // The read-back fingerprint is the HMAC itself (not reversible to original hex,
        // but sufficient for deduplication comparisons via the same HMAC).
        var fingerprint = new ValueFingerprint(valueHmac);

        await groupReader.DisposeAsync().ConfigureAwait(false);

        // Read occurrences.
        var occurrences = await GetOccurrencesByGroupIdAsync(groupId, cancellationToken).ConfigureAwait(false);

        return new FindingGroup(groupId, findingKind, severity, fingerprint, occurrences);
    }

    public async Task<IReadOnlyList<FindingGroup>> GetGroupsByScanIdAsync(
        ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);

        // Read group IDs.
        await using var groupCmd = connection.CreateCommand();
        groupCmd.CommandText = """
            SELECT DISTINCT group_id FROM finding_groups WHERE scan_id = @scanId;
            """;
        groupCmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        var groupIds = new List<FindingGroupId>();
        await using (var reader = await groupCmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                groupIds.Add(new FindingGroupId(Guid.Parse(reader.GetString(0))));
            }
        }

        var groups = new List<FindingGroup>();
        foreach (var groupId in groupIds)
        {
            var group = await GetGroupByIdAsync(groupId, cancellationToken).ConfigureAwait(false);
            if (group is not null)
                groups.Add(group);
        }

        return groups;
    }

    public async Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesByGroupIdAsync(
        FindingGroupId groupId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT occurrence_id, group_id, file_id, rule_id, detector_id,
                requires_semantic_review, encrypted_payload
            FROM finding_occurrences
            WHERE group_id = @groupId;
            """;
        cmd.Parameters.AddWithValue("@groupId", groupId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var occurrences = new List<FindingOccurrence>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            occurrences.Add(ReadOccurrence(groupId, reader));
        }

        return occurrences;
    }

    private SqliteCommand CreateOccurrenceInsertCommand(SqliteConnection connection, FileId fileId, FindingOccurrence occurrence)
    {
        var cmd = connection.CreateCommand();
        PrepareOccurrenceInsertCommand(cmd);
        BindOccurrenceParameters(cmd, fileId, occurrence);
        return cmd;
    }

    private static void PrepareOccurrenceInsertCommand(SqliteCommand cmd)
    {
        cmd.CommandText = """
            INSERT INTO finding_occurrences (occurrence_id, group_id, file_id, rule_id,
                detector_id, requires_semantic_review, encrypted_payload)
            VALUES (@occurrenceId, @groupId, @fileId, @ruleId, @detectorId,
                @requiresSemanticReview, @encryptedPayload)
            ON CONFLICT(occurrence_id) DO NOTHING;
            """;
        cmd.Parameters.Add("@occurrenceId", SqliteType.Text);
        cmd.Parameters.Add("@groupId", SqliteType.Text);
        cmd.Parameters.Add("@fileId", SqliteType.Text);
        cmd.Parameters.Add("@ruleId", SqliteType.Text);
        cmd.Parameters.Add("@detectorId", SqliteType.Text);
        cmd.Parameters.Add("@requiresSemanticReview", SqliteType.Integer);
        cmd.Parameters.Add("@encryptedPayload", SqliteType.Blob);
    }

    private void BindOccurrenceParameters(SqliteCommand cmd, FileId fileId, FindingOccurrence occurrence)
    {
        byte[] encryptedJson = EncryptOccurrencePayload(occurrence);
        bool requiresSemanticReview = occurrence.Provenance.Any(p => p.RequiresSemanticReview);

        // Use first provenance for top-level rule_id/detector_id columns.
        string ruleId = occurrence.Provenance.Count > 0 ? occurrence.Provenance[0].RuleId.Value : "RULE-UNKNOWN";
        string detectorId = occurrence.Provenance.Count > 0 ? occurrence.Provenance[0].DetectorId.Value : "DET-UNKNOWN";

        cmd.Parameters["@occurrenceId"].Value = occurrence.Id.Value.ToString();
        cmd.Parameters["@groupId"].Value = occurrence.GroupId.Value.ToString();
        cmd.Parameters["@fileId"].Value = fileId.Value.ToString();
        cmd.Parameters["@ruleId"].Value = ruleId;
        cmd.Parameters["@detectorId"].Value = detectorId;
        cmd.Parameters["@requiresSemanticReview"].Value = requiresSemanticReview ? 1 : 0;
        cmd.Parameters["@encryptedPayload"].Value = encryptedJson;
    }

    private byte[] EncryptOccurrencePayload(FindingOccurrence occurrence)
    {
        var provenancePayloads = occurrence.Provenance.Select(p => new FindingProvenancePayload(
            DetectorId: p.DetectorId.Value,
            RuleId: p.RuleId.Value,
            Confidence: (int)p.Confidence,
            RequiresSemanticReview: p.RequiresSemanticReview)).ToArray();

        var payload = new FindingOccurrencePayload(
            RawValue: occurrence.RawValue,
            RawContext: occurrence.RawContext,
            CanonicalLocatorJson: JsonSerializer.Serialize(occurrence.CanonicalLocator),
            VirtualPath: occurrence.VirtualPath,
            FileSha256: occurrence.FileSha256,
            Provenance: provenancePayloads);

        byte[] jsonBytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(payload, FindingJsonContext.Default.FindingOccurrencePayload));
        var encrypted = _protector.Protect(Table, occurrence.Id.Value.ToString(), Field, jsonBytes);
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(encrypted, FindingJsonContext.Default.EncryptedPayload));
    }

    private FindingOccurrence ReadOccurrence(FindingGroupId groupId, SqliteDataReader reader)
    {
        var occurrenceId = new FindingOccurrenceId(Guid.Parse(reader.GetString(0)));

        byte[] encryptedJson = GetBlobBytes(reader, 6);
        var encryptedPayload = JsonSerializer.Deserialize(
            Encoding.UTF8.GetString(encryptedJson), FindingJsonContext.Default.EncryptedPayload)!;

        byte[] plaintext = _protector.Unprotect(Table, occurrenceId.Value.ToString(), Field, encryptedPayload);
        var payload = JsonSerializer.Deserialize(plaintext, FindingJsonContext.Default.FindingOccurrencePayload)!;

        var provenance = payload.Provenance.Select(p => new FindingProvenance(
            DetectorId: new DetectorId(p.DetectorId),
            RuleId: new RuleId(p.RuleId),
            Confidence: (DetectionConfidence)p.Confidence,
            RequiresSemanticReview: p.RequiresSemanticReview)).ToArray();

        return new FindingOccurrence(
            Id: occurrenceId,
            GroupId: groupId,
            RawValue: payload.RawValue,
            RawContext: payload.RawContext,
            CanonicalLocator: JsonSerializer.Deserialize<SourceLocator>(payload.CanonicalLocatorJson)!,
            VirtualPath: payload.VirtualPath,
            FileSha256: payload.FileSha256,
            Provenance: provenance);
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

internal sealed record FindingOccurrencePayload(
    string RawValue,
    string RawContext,
    string CanonicalLocatorJson,
    string VirtualPath,
    string FileSha256,
    FindingProvenancePayload[] Provenance);

internal sealed record FindingProvenancePayload(
    string DetectorId,
    string RuleId,
    int Confidence,
    bool RequiresSemanticReview);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(FindingOccurrencePayload))]
[JsonSerializable(typeof(FindingProvenancePayload))]
[JsonSerializable(typeof(EncryptedPayload))]
internal partial class FindingJsonContext : JsonSerializerContext;
