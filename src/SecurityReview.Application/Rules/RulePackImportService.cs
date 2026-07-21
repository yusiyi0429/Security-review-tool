using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Signing;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.Application.Rules;

/// <summary>
/// Orchestrates the rule pack import flow: validation, downgrade/duplicate
/// guards, atomic store, and active-pointer switch. On any failure the
/// previous active pointer is left unchanged.
/// </summary>
public sealed class RulePackImportService
{
    private readonly IRulePackValidator _validator;
    private readonly IRulePackStore _store;
    private readonly IEffectivePolicyProvider _policyProvider;
    private readonly TrustedSignerStore _signerStore;
    private readonly string _appVersion;

    public RulePackImportService(
        IRulePackValidator validator,
        IRulePackStore store,
        IEffectivePolicyProvider policyProvider,
        TrustedSignerStore signerStore,
        string appVersion)
    {
        _validator = validator;
        _store = store;
        _policyProvider = policyProvider;
        _signerStore = signerStore;
        _appVersion = appVersion;
    }

    /// <summary>
    /// Imports and activates a rule pack ZIP. The flow:
    /// <list type="number">
    /// <item>Validate the ZIP</item>
    /// <item>Guard against downgrade (when a previous active exists)</item>
    /// <item>Guard against duplicate with different hash</item>
    /// <item>Store the package on disk</item>
    /// <item>Atomically switch the active pointer</item>
    /// </list>
    /// On any failure the previous active pointer is preserved.
    /// </summary>
    public async Task<ImportResult> ImportAsync(ImportRulePackCommand command, CancellationToken ct)
    {
        // 1. Validate the ZIP.
        var validation = _validator.Validate(command.ZipBytes, _signerStore, _appVersion);
        if (!validation.IsValid)
        {
            return new ImportResult
            {
                Success = false,
                ErrorCode = validation.ErrorCode,
                ErrorMessage = $"Rule pack validation failed: {validation.ErrorCode}",
                Validation = validation
            };
        }

        var manifest = validation.Manifest!;
        var packageSha256 = validation.PackageSha256;

        // 2. Check current active pointer.
        var currentActive = await _store.GetActiveAsync(ct);
        var isInitialImport = currentActive is null;

        if (!isInitialImport)
        {
            // 3. Downgrade guard.
            if (!command.AllowDowngrade && IsDowngrade(manifest.Version, currentActive!.Version))
            {
                return new ImportResult
                {
                    Success = false,
                    ErrorCode = "DOWNGRADE_NOT_ALLOWED",
                    ErrorMessage = $"Downgrade from {currentActive.Version} to {manifest.Version} is not allowed. " +
                                   "Set AllowDowngrade=true to proceed.",
                    Validation = validation
                };
            }

            // 4. Duplicate guard: same ID + version but different hash → reject.
            if (IsSameIdentity(currentActive!, manifest.RulePackId, manifest.Version) &&
                !string.Equals(currentActive!.Sha256, packageSha256, StringComparison.OrdinalIgnoreCase))
            {
                return new ImportResult
                {
                    Success = false,
                    ErrorCode = "DUPLICATE_VERSION_HASH_MISMATCH",
                    ErrorMessage = $"Rule pack {manifest.RulePackId} v{manifest.Version} already exists " +
                                   $"with a different hash. Existing: {currentActive.Sha256}, new: {packageSha256}.",
                    Active = currentActive,
                    Validation = validation
                };
            }
        }

        // 5. Store the package.
        var storeResult = await _store.StoreAsync(command.ZipBytes, manifest, packageSha256, ct);
        if (!storeResult.Success)
        {
            return new ImportResult
            {
                Success = false,
                ErrorCode = "STORE_FAILED",
                ErrorMessage = $"Failed to store rule pack: {storeResult.PackagePath}",
                Validation = validation
            };
        }

        // 6. Switch the active pointer.
        var newActive = new ActivePointer
        {
            RulePackId = manifest.RulePackId,
            Version = manifest.Version,
            Sha256 = packageSha256
        };

        await _store.SetActiveAsync(newActive, ct);

        return new ImportResult
        {
            Success = true,
            Active = newActive,
            Validation = validation
        };
    }

    private static bool IsDowngrade(string newVersion, string currentVersion)
    {
        if (TryParseVersion(newVersion, out var newVer) &&
            TryParseVersion(currentVersion, out var curVer))
        {
            return newVer < curVer;
        }

        // Fall back to ordinal string comparison when parsing fails.
        return string.CompareOrdinal(newVersion, currentVersion) < 0;
    }

    private static bool IsSameIdentity(ActivePointer active, string rulePackId, string version)
    {
        return string.Equals(active.RulePackId, rulePackId, StringComparison.Ordinal) &&
               string.Equals(active.Version, version, StringComparison.Ordinal);
    }

    private static bool TryParseVersion(string version, out System.Version parsed)
    {
        return System.Version.TryParse(version, out parsed!);
    }
}
