using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using SecurityReview.Application.Rules;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Policy;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.Infrastructure.Rules;

/// <summary>
/// A hash-bound, validated rule package ready for deterministic detection.
/// </summary>
public sealed record LoadedRulePack(
    string Sha256,
    EffectivePolicy Policy,
    IReadOnlyList<RestrictedEntityEntry> RestrictedEntities);

public sealed record ActiveRulePackRuntime(
    ActivePointer Active,
    LoadedRulePack Package);

/// <summary>
/// Reloads immutable rule packages from the local store by SHA-256. Detection
/// asks for the hash captured in the scan snapshot, so changing the active
/// pointer during a scan cannot change that scan's policy.
/// </summary>
public sealed class ActiveRulePackRuntimeProvider : IEffectivePolicyProvider
{
    private readonly FileRulePackStore _store;
    private readonly ConcurrentDictionary<string, Task<LoadedRulePack>> _cache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions PackageModelJsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            UnmappedMemberHandling =
                System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        };

    public ActiveRulePackRuntimeProvider(FileRulePackStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public async Task<ActiveRulePackRuntime?> GetActiveAsync(
        CancellationToken cancellationToken)
    {
        ActivePointer? pointer = await _store
            .GetActiveAsync(cancellationToken)
            .ConfigureAwait(false);
        if (pointer is null)
        {
            return null;
        }

        LoadedRulePack package = await GetByHashAsync(
                pointer.Sha256, cancellationToken)
            .ConfigureAwait(false);
        return new ActiveRulePackRuntime(pointer, package);
    }

    public async Task<LoadedRulePack> GetByHashAsync(
        string sha256,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);
        string normalized = sha256.ToLowerInvariant();
        Task<LoadedRulePack> loadTask = _cache.GetOrAdd(
            normalized,
            hash => LoadAsync(hash, CancellationToken.None));

        try
        {
            return await loadTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (_cache.TryGetValue(normalized, out Task<LoadedRulePack>? current)
                && ReferenceEquals(current, loadTask))
            {
                _cache.TryRemove(normalized, out _);
            }
            throw;
        }
    }

    public async Task<EffectivePolicy> BuildAsync(
        ActivePointer active,
        string? localSupplementJson,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(active);
        LoadedRulePack package = await GetByHashAsync(
                active.Sha256, cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(localSupplementJson))
        {
            return package.Policy;
        }

        string localHash = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(localSupplementJson)));
        return EffectivePolicyBuilder.Build(
            package.Policy.Rules,
            assetIds: null,
            localSupplementJson,
            active.Sha256,
            localHash);
    }

    private async Task<LoadedRulePack> LoadAsync(
        string sha256,
        CancellationToken cancellationToken)
    {
        byte[] bytes = await _store
            .ReadPackageByHashAsync(sha256, cancellationToken)
            .ConfigureAwait(false);

        using var stream = new MemoryStream(bytes, writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);

        IReadOnlyList<CategoryDefinition> categories = ReadList(
            archive,
            "categories.json",
            RulePackJsonContext.Default.IReadOnlyListCategoryDefinition);
        IReadOnlyList<AssetPolicy> assets = ReadList(
            archive,
            "assets.json",
            RulePackJsonContext.Default.IReadOnlyListAssetPolicy);
        IReadOnlyList<RuleDefinition> rules = ReadList(
            archive,
            "rules.json",
            RulePackJsonContext.Default.IReadOnlyListRuleDefinition);
        IReadOnlyList<DetectorDefinition> detectors = ReadList(
            archive,
            "detectors.json",
            RulePackJsonContext.Default.IReadOnlyListDetectorDefinition);
        IReadOnlyList<ComplianceRule> compliance = ReadList(
            archive,
            "compliance.json",
            RulePackJsonContext.Default.IReadOnlyListComplianceRule);

        var document = new RulePackDocument
        {
            Categories = categories,
            Assets = assets,
            Rules = rules,
            Detectors = detectors,
            ComplianceRules = compliance,
        };

        IReadOnlyList<string> validationErrors = document.Validate();
        RuleGraphValidator.GraphValidationResult graph = RuleGraphValidator.Validate(document);
        if (validationErrors.Count > 0 || !graph.IsValid)
        {
            throw new InvalidDataException(
                "The active rule package is no longer valid.");
        }

        IReadOnlyList<RestrictedEntityEntry> entities =
            ReadModelList<RestrictedEntityEntry>(
            archive,
            "dictionaries/entities.json");

        EffectivePolicy policy = EffectivePolicyBuilder.Build(
            document,
            assetIds: null,
            localSupplementJson: null,
            packageHash: sha256,
            localHash: null);
        return new LoadedRulePack(sha256, policy, entities);
    }

    private static IReadOnlyList<T> ReadList<T>(
        ZipArchive archive,
        string entryName,
        JsonTypeInfo<IReadOnlyList<T>> typeInfo)
    {
        ZipArchiveEntry entry = archive.GetEntry(entryName)
            ?? throw new InvalidDataException(
                $"The active rule package is missing {entryName}.");
        using Stream entryStream = entry.Open();
        return JsonSerializer.Deserialize(entryStream, typeInfo)
            ?? throw new InvalidDataException(
                $"The active rule package contains invalid {entryName}.");
    }

    private static IReadOnlyList<T> ReadModelList<T>(
        ZipArchive archive,
        string entryName)
    {
        ZipArchiveEntry entry = archive.GetEntry(entryName)
            ?? throw new InvalidDataException(
                $"The active rule package is missing {entryName}.");
        using Stream entryStream = entry.Open();
        return JsonSerializer.Deserialize<IReadOnlyList<T>>(
                entryStream, PackageModelJsonOptions)
            ?? throw new InvalidDataException(
                $"The active rule package contains invalid {entryName}.");
    }
}

public sealed class ActiveRulePackBaselineProvider : ISignedBaselineProvider
{
    private readonly ActiveRulePackRuntimeProvider _runtimeProvider;

    public ActiveRulePackBaselineProvider(
        ActiveRulePackRuntimeProvider runtimeProvider)
    {
        _runtimeProvider = runtimeProvider
            ?? throw new ArgumentNullException(nameof(runtimeProvider));
    }

    public async Task<bool> HasActiveSignedBaselineAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            return await _runtimeProvider
                .GetActiveAsync(cancellationToken)
                .ConfigureAwait(false) is not null;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException
            or JsonException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
