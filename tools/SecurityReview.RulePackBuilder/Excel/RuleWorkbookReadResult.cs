using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePackBuilder.Excel;

/// <summary>
/// Result produced by <see cref="RuleWorkbookReader.Read"/>.
/// </summary>
public sealed record RuleWorkbookReadResult(
    RulePackDocument? Document,
    IReadOnlyList<RestrictedEntityEntry> Entities,
    IReadOnlyList<SecurityPlaceholder> Placeholders,
    IReadOnlyList<ThirdPartyLicense> Licenses,
    IReadOnlyDictionary<string, string> PackageInfo,
    IReadOnlyList<WorkbookValidationError> Errors);
