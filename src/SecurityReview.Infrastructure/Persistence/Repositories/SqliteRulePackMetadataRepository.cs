using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain.Rules;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteRulePackMetadataRepository : IRulePackMetadataRepository
{
    private readonly ISqliteConnectionFactory _factory;

    public SqliteRulePackMetadataRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task InsertAsync(
        string rulePackHash,
        string rulePackId,
        string version,
        string signerId,
        string packagePathHmac,
        RulePackStatus status,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO rule_packs (rule_pack_hash, rule_pack_id, version, signer_id,
                imported_at_utc, status, package_path_hmac)
            VALUES (@hash, @id, @version, @signerId, @importedAt, @status, @pathHmac);
            """;
        cmd.Parameters.AddWithValue("@hash", rulePackHash);
        cmd.Parameters.AddWithValue("@id", rulePackId);
        cmd.Parameters.AddWithValue("@version", version);
        cmd.Parameters.AddWithValue("@signerId", signerId);
        cmd.Parameters.AddWithValue("@importedAt", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@status", (int)status);
        cmd.Parameters.AddWithValue("@pathHmac", packagePathHmac);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RulePackMetadata?> GetByHashAsync(string rulePackHash, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT rule_pack_hash, rule_pack_id, version, signer_id,
                package_path_hmac, imported_at_utc, status
            FROM rule_packs
            WHERE rule_pack_hash = @hash;
            """;
        cmd.Parameters.AddWithValue("@hash", rulePackHash);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;

        return ReadRulePackMetadata(reader);
    }

    public async Task<IReadOnlyList<RulePackMetadata>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT rule_pack_hash, rule_pack_id, version, signer_id,
                package_path_hmac, imported_at_utc, status
            FROM rule_packs
            ORDER BY imported_at_utc DESC;
            """;

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var packs = new List<RulePackMetadata>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            packs.Add(ReadRulePackMetadata(reader));
        }

        return packs;
    }

    public async Task UpdateStatusAsync(
        string rulePackHash, RulePackStatus status, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            UPDATE rule_packs
            SET status = @status
            WHERE rule_pack_hash = @hash;
            """;
        cmd.Parameters.AddWithValue("@status", (int)status);
        cmd.Parameters.AddWithValue("@hash", rulePackHash);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static RulePackMetadata ReadRulePackMetadata(SqliteDataReader reader)
    {
        return new RulePackMetadata(
            RulePackHash: reader.GetString(0),
            RulePackId: reader.GetString(1),
            Version: reader.GetString(2),
            SignerId: reader.GetString(3),
            PackagePathHmac: reader.GetString(4),
            ImportedAtUtc: DateTimeOffset.Parse(reader.GetString(5), System.Globalization.CultureInfo.InvariantCulture),
            Status: (RulePackStatus)reader.GetInt32(6));
    }
}
