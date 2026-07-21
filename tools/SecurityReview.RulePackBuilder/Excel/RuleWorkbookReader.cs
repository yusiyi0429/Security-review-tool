using System.Text.Json;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePackBuilder.Excel;

/// <summary>
/// Reads a structured Excel workbook and produces a <see cref="RuleWorkbookReadResult"/>
/// with all validation errors collected during parsing.
///
/// Expected sheets (all required):
///   规则包信息:      键 | 值
///   敏感类别:       类别ID | 名称 | 说明 | 默认严重度 | 启用
///   资产专项规则:    规则ID | 资产ID | 类别ID | 发现类型 | 检测器ID | 配置ID |
///                   严重度 | 置信度 | 需要语义复核 | 启用 | 说明
///   受限实体词典:    词典ID | 实体ID | 标准名称 | 变体 | 类别ID | 严重度 |
///                   资产范围 | 有效起始 | 有效结束
///   安全占位符:     占位符ID | 匹配类型 | 值 | 允许上下文 | 类别ID |
///                   有效起始 | 有效结束
///   检测器配置:     检测器ID | 类型 | 配置ID | 参数JSON | 最大每块命中数
///   第三方授权:     授权ID | 来源名称 | 标识或指纹 | 许可说明 | 证据引用 |
///                   有效起始 | 有效结束
///   合规规则:       规则ID | 资产ID | 证据字段 | 缺失结论 | 严重度 | 说明
/// </summary>
public static class RuleWorkbookReader
{
    private static readonly string[] ExpectedSheetNames =
    [
        "规则包信息",
        "敏感类别",
        "资产专项规则",
        "受限实体词典",
        "安全占位符",
        "检测器配置",
        "第三方授权",
        "合规规则",
    ];

    public static RuleWorkbookReadResult Read(Stream stream)
    {
        var errors = new List<WorkbookValidationError>();

        SpreadsheetDocument doc;
        try
        {
            doc = SpreadsheetDocument.Open(stream, false);
        }
        catch (Exception ex)
        {
            errors.Add(new WorkbookValidationError(
                WorkbookValidationError.InvalidJson, "", 0, "",
                $"Failed to open workbook: {ex.Message}"));
            return new RuleWorkbookReadResult(null, [], [], [], new Dictionary<string, string>(), errors);
        }

        using (doc)
        {
            var wbPart = doc.WorkbookPart;
            if (wbPart is null)
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.MissingSheet, "", 0, "",
                    "WorkbookPart is missing."));
                return new RuleWorkbookReadResult(null, [], [], [], new Dictionary<string, string>(), errors);
            }

            var workbook = wbPart.Workbook;
            if (workbook?.Sheets is null)
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.MissingSheet, "", 0, "",
                    "Workbook contains no sheets."));
                return new RuleWorkbookReadResult(null, [], [], [], new Dictionary<string, string>(), errors);
            }

            // Structural safety checks.
            WorkbookCellReader.DetectExternalLinks(doc, "", errors);
            WorkbookCellReader.DetectMacros(doc, "", errors);

            // Validate sheet names: report missing required sheets and extra sheets.
            var presentSheets = workbook.Sheets.Elements<Sheet>()
                .Select(s => s.Name?.Value ?? "")
                .ToHashSet(StringComparer.Ordinal);

            var expectedSet = ExpectedSheetNames.ToHashSet(StringComparer.Ordinal);

            foreach (var expected in ExpectedSheetNames)
            {
                if (!presentSheets.Contains(expected))
                {
                    errors.Add(new WorkbookValidationError(
                        WorkbookValidationError.MissingSheet, expected, 0, "",
                        $"Required sheet '{expected}' is missing."));
                }
            }

            foreach (var present in presentSheets)
            {
                if (!expectedSet.Contains(present))
                {
                    errors.Add(new WorkbookValidationError(
                        WorkbookValidationError.ExtraSheet, present, 0, "",
                        $"Unexpected sheet '{present}' is not recognized."));
                }
            }

            // Read all sheets, collecting errors as we go.
            var packageInfo = ReadPackageInfo(doc, wbPart, errors);
            var categories = ReadCategories(doc, wbPart, errors);
            var rules = ReadRules(doc, wbPart, errors);
            var entities = ReadRestrictedEntities(doc, wbPart, errors);
            var placeholders = ReadPlaceholders(doc, wbPart, errors);
            var detectors = ReadDetectors(doc, wbPart, errors);
            var licenses = ReadLicenses(doc, wbPart, errors);
            var complianceRules = ReadComplianceRules(doc, wbPart, errors);

            var document = new RulePackDocument
            {
                Categories = categories,
                Assets = Array.Empty<AssetPolicy>(),
                Detectors = detectors,
                Rules = rules,
                ComplianceRules = complianceRules,
            };

            return new RuleWorkbookReadResult(document, entities, placeholders, licenses, packageInfo, errors);
        }
    }

    // ------------------------------------------------------------------
    //  Sheet access helpers
    // ------------------------------------------------------------------

    private static (WorksheetPart? Part, string? SheetName) TryGetSheet(
        WorkbookPart wbPart, string sheetName)
    {
        var sheets = wbPart.Workbook?.Sheets;
        if (sheets is null)
            return (null, null);

        var sheet = sheets.Elements<Sheet>()
            .FirstOrDefault(s =>
                string.Equals(s.Name?.Value, sheetName, StringComparison.Ordinal));

        if (sheet?.Id?.Value is null)
            return (null, null);

        var part = (WorksheetPart)wbPart.GetPartById(sheet.Id.Value);
        return (part, sheetName);
    }

    /// <summary>
    /// Reads all rows from a worksheet in order. Returns an empty enumeration
    /// when the worksheet part is null.
    /// </summary>
    private static IEnumerable<Row> EnumerateRows(WorksheetPart? part)
    {
        if (part?.Worksheet is null)
            yield break;

        foreach (var row in part.Worksheet.Descendants<Row>())
        {
            yield return row;
        }
    }

    // ------------------------------------------------------------------
    //  Sheet 1: 规则包信息
    // ------------------------------------------------------------------

    private static Dictionary<string, string> ReadPackageInfo(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "规则包信息";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return new Dictionary<string, string>();

        var rows = EnumerateRows(part).ToList();
        if (rows.Count == 0)
            return new Dictionary<string, string>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return new Dictionary<string, string>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName, ["键", "值"], errors, 1))
            return new Dictionary<string, string>();

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var key = GetCellString(doc, row, colMap, "键");
            var value = GetCellString(doc, row, colMap, "值");

            WorkbookCellReader.CheckCellLength(key, sheetName, rowNum, "键", errors);
            WorkbookCellReader.CheckCellLength(value, sheetName, rowNum, "值", errors);

            if (!string.IsNullOrWhiteSpace(key))
            {
                result[key] = value ?? "";
            }
        }

        return result;
    }

    // ------------------------------------------------------------------
    //  Sheet 2: 敏感类别 → CategoryDefinition
    // ------------------------------------------------------------------

    private static IReadOnlyList<CategoryDefinition> ReadCategories(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "敏感类别";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<CategoryDefinition>();

        var categories = new List<CategoryDefinition>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<CategoryDefinition>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<CategoryDefinition>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName, ["类别ID", "名称", "说明", "默认严重度", "启用"], errors, 1))
            return Array.Empty<CategoryDefinition>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var catIdStr = GetCellString(doc, row, colMap, "类别ID");
            WorkbookCellReader.CheckCellLength(catIdStr, sheetName, rowNum, "类别ID", errors);

            if (string.IsNullOrWhiteSpace(catIdStr))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "类别ID",
                    "类别ID is required."));
                continue;
            }

            CategoryId catId;
            try
            {
                catId = CategoryId.Parse(catIdStr);
            }
            catch (ArgumentException)
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "类别ID",
                    "Unrecognized 类别ID."));
                continue;
            }

            var name = GetCellString(doc, row, colMap, "名称") ?? "";
            var desc = GetCellString(doc, row, colMap, "说明") ?? "";
            var enabled = GetCellBool(doc, row, colMap, "启用") ?? true;

            WorkbookCellReader.CheckCellLength(name, sheetName, rowNum, "名称", errors);
            WorkbookCellReader.CheckCellLength(desc, sheetName, rowNum, "说明", errors);

            categories.Add(new CategoryDefinition
            {
                CategoryId = catId,
                Name = name,
                Description = desc,
                Enabled = enabled,
            });
        }

        return categories;
    }

    // ------------------------------------------------------------------
    //  Sheet 3: 资产专项规则 → RuleDefinition
    // ------------------------------------------------------------------

    private static IReadOnlyList<RuleDefinition> ReadRules(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "资产专项规则";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<RuleDefinition>();

        var rules = new List<RuleDefinition>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<RuleDefinition>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<RuleDefinition>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName,
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID",
                 "严重度", "置信度", "需要语义复核", "启用", "说明"], errors, 1))
            return Array.Empty<RuleDefinition>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var ruleIdStr = GetCellString(doc, row, colMap, "规则ID");
            WorkbookCellReader.CheckCellLength(ruleIdStr, sheetName, rowNum, "规则ID", errors);

            if (string.IsNullOrWhiteSpace(ruleIdStr))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "规则ID",
                    "规则ID is required."));
                continue;
            }

            var catIdStr = GetCellString(doc, row, colMap, "类别ID");
            WorkbookCellReader.CheckCellLength(catIdStr, sheetName, rowNum, "类别ID", errors);

            if (string.IsNullOrWhiteSpace(catIdStr))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "类别ID",
                    "类别ID is required."));
                continue;
            }

            CategoryId catId;
            try
            {
                catId = CategoryId.Parse(catIdStr);
            }
            catch (ArgumentException)
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "类别ID",
                    "Unrecognized 类别ID."));
                continue;
            }

            var findingKindStr = GetCellString(doc, row, colMap, "发现类型");
            if (string.IsNullOrWhiteSpace(findingKindStr)
                || !Enum.TryParse<FindingKind>(findingKindStr, ignoreCase: true, out var findingKind))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "发现类型",
                    "Invalid or missing 发现类型."));
                continue;
            }

            var severityStr = GetCellString(doc, row, colMap, "严重度");
            if (string.IsNullOrWhiteSpace(severityStr)
                || !Enum.TryParse<Severity>(severityStr, ignoreCase: true, out var severity))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "严重度",
                    "Invalid or missing 严重度."));
                continue;
            }

            var confidenceStr = GetCellString(doc, row, colMap, "置信度");
            var confidence = DetectionConfidence.High;
            if (!string.IsNullOrWhiteSpace(confidenceStr)
                && !Enum.TryParse<DetectionConfidence>(confidenceStr, ignoreCase: true, out confidence))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "置信度",
                    "Invalid 置信度 value."));
                continue;
            }

            var detIdStr = GetCellString(doc, row, colMap, "检测器ID");
            WorkbookCellReader.CheckCellLength(detIdStr, sheetName, rowNum, "检测器ID", errors);

            if (string.IsNullOrWhiteSpace(detIdStr))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "检测器ID",
                    "检测器ID is required."));
                continue;
            }

            var detConfigId = GetCellString(doc, row, colMap, "配置ID") ?? "";
            var requiresReview = GetCellBool(doc, row, colMap, "需要语义复核") ?? false;
            var enabled = GetCellBool(doc, row, colMap, "启用") ?? true;

            WorkbookCellReader.CheckCellLength(detConfigId, sheetName, rowNum, "配置ID", errors);

            var appliesTo = ParseAppliesToAssets(
                doc, row, colMap, sheetName, rowNum, errors);

            rules.Add(new RuleDefinition
            {
                Id = new RuleId(ruleIdStr),
                CategoryId = catId,
                FindingKind = findingKind,
                Severity = severity,
                Confidence = confidence,
                DetectorId = new DetectorId(detIdStr),
                DetectorConfigId = detConfigId,
                AppliesToAssets = appliesTo,
                RequiresSemanticReview = requiresReview,
                Enabled = enabled,
            });
        }

        return rules;
    }

    private static HashSet<AssetTypeId> ParseAppliesToAssets(
        SpreadsheetDocument doc, Row row,
        Dictionary<string, int> colMap, string sheetName, int rowNum,
        List<WorkbookValidationError> errors)
    {
        var raw = GetCellString(doc, row, colMap, "资产ID");
        var result = new HashSet<AssetTypeId>();

        if (string.IsNullOrWhiteSpace(raw))
            return result;

        foreach (var part in raw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                result.Add(AssetTypeId.Parse(part));
            }
            catch (ArgumentException)
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "资产ID",
                    "Unrecognized AssetTypeId in 资产ID list."));
            }
        }

        return result;
    }

    // ------------------------------------------------------------------
    //  Sheet 4: 受限实体词典 → RestrictedEntityEntry
    // ------------------------------------------------------------------

    private static IReadOnlyList<RestrictedEntityEntry> ReadRestrictedEntities(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "受限实体词典";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<RestrictedEntityEntry>();

        var entities = new List<RestrictedEntityEntry>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<RestrictedEntityEntry>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<RestrictedEntityEntry>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName,
                ["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度",
                 "资产范围", "有效起始", "有效结束"], errors, 1))
            return Array.Empty<RestrictedEntityEntry>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var dictionaryId = GetCellString(doc, row, colMap, "词典ID") ?? "";
            var entityId = GetCellString(doc, row, colMap, "实体ID") ?? "";
            var standardName = GetCellString(doc, row, colMap, "标准名称") ?? "";
            var variant = GetCellString(doc, row, colMap, "变体") ?? "";
            var categoryId = GetCellString(doc, row, colMap, "类别ID") ?? "";
            var severity = GetCellString(doc, row, colMap, "严重度") ?? "";
            var assetScope = GetCellString(doc, row, colMap, "资产范围") ?? "";
            var validFrom = GetCellString(doc, row, colMap, "有效起始") ?? "";
            var validUntil = GetCellString(doc, row, colMap, "有效结束") ?? "";

            WorkbookCellReader.CheckCellLength(dictionaryId, sheetName, rowNum, "词典ID", errors);
            WorkbookCellReader.CheckCellLength(entityId, sheetName, rowNum, "实体ID", errors);
            WorkbookCellReader.CheckCellLength(standardName, sheetName, rowNum, "标准名称", errors);
            WorkbookCellReader.CheckCellLength(variant, sheetName, rowNum, "变体", errors);
            WorkbookCellReader.CheckCellLength(categoryId, sheetName, rowNum, "类别ID", errors);

            entities.Add(new RestrictedEntityEntry
            {
                DictionaryId = dictionaryId,
                EntityId = entityId,
                StandardName = standardName,
                Variant = variant,
                CategoryId = categoryId,
                Severity = severity,
                AssetScope = assetScope,
                ValidFrom = validFrom,
                ValidUntil = validUntil,
            });
        }

        return entities;
    }

    // ------------------------------------------------------------------
    //  Sheet 5: 安全占位符 → SecurityPlaceholder
    // ------------------------------------------------------------------

    private static IReadOnlyList<SecurityPlaceholder> ReadPlaceholders(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "安全占位符";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<SecurityPlaceholder>();

        var placeholders = new List<SecurityPlaceholder>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<SecurityPlaceholder>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<SecurityPlaceholder>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName,
                ["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"], errors, 1))
            return Array.Empty<SecurityPlaceholder>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var placeholderId = GetCellString(doc, row, colMap, "占位符ID") ?? "";
            var matchType = GetCellString(doc, row, colMap, "匹配类型") ?? "";
            var value = GetCellString(doc, row, colMap, "值") ?? "";
            var allowedContext = GetCellString(doc, row, colMap, "允许上下文") ?? "";
            var categoryId = GetCellString(doc, row, colMap, "类别ID") ?? "";
            var validFrom = GetCellString(doc, row, colMap, "有效起始") ?? "";
            var validUntil = GetCellString(doc, row, colMap, "有效结束") ?? "";

            WorkbookCellReader.CheckCellLength(placeholderId, sheetName, rowNum, "占位符ID", errors);
            WorkbookCellReader.CheckCellLength(matchType, sheetName, rowNum, "匹配类型", errors);
            WorkbookCellReader.CheckCellLength(value, sheetName, rowNum, "值", errors);
            WorkbookCellReader.CheckCellLength(allowedContext, sheetName, rowNum, "允许上下文", errors);
            WorkbookCellReader.CheckCellLength(categoryId, sheetName, rowNum, "类别ID", errors);

            placeholders.Add(new SecurityPlaceholder
            {
                PlaceholderId = placeholderId,
                MatchType = matchType,
                Value = value,
                AllowedContext = allowedContext,
                CategoryId = categoryId,
                ValidFrom = validFrom,
                ValidUntil = validUntil,
            });
        }

        return placeholders;
    }

    // ------------------------------------------------------------------
    //  Sheet 6: 检测器配置 → DetectorDefinition
    // ------------------------------------------------------------------

    private static IReadOnlyList<DetectorDefinition> ReadDetectors(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "检测器配置";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<DetectorDefinition>();

        var detectors = new List<DetectorDefinition>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<DetectorDefinition>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<DetectorDefinition>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName,
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"], errors, 1))
            return Array.Empty<DetectorDefinition>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var detIdStr = GetCellString(doc, row, colMap, "检测器ID");
            WorkbookCellReader.CheckCellLength(detIdStr, sheetName, rowNum, "检测器ID", errors);

            if (string.IsNullOrWhiteSpace(detIdStr))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "检测器ID",
                    "检测器ID is required."));
                continue;
            }

            var kindStr = GetCellString(doc, row, colMap, "类型");
            if (string.IsNullOrWhiteSpace(kindStr)
                || !Enum.TryParse<DetectorKind>(kindStr, ignoreCase: true, out var kind))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "类型",
                    "Invalid or missing DetectorKind."));
                continue;
            }

            var configId = GetCellString(doc, row, colMap, "配置ID") ?? "";
            var maxMatches = GetCellInt(doc, row, colMap, "最大每块命中数");

            WorkbookCellReader.CheckCellLength(configId, sheetName, rowNum, "配置ID", errors);

            var parameters = ParseParametersColumn(
                doc, row, colMap, sheetName, rowNum, errors);

            detectors.Add(new DetectorDefinition
            {
                Id = new DetectorId(detIdStr),
                Kind = kind,
                ConfigId = configId,
                Parameters = parameters,
                MaxMatchesPerChunk = maxMatches ?? 100,
            });
        }

        return detectors;
    }

    private static Dictionary<string, string> ParseParametersColumn(
        SpreadsheetDocument doc, Row row,
        Dictionary<string, int> colMap, string sheetName, int rowNum,
        List<WorkbookValidationError> errors)
    {
        var raw = GetCellString(doc, row, colMap, "参数JSON");
        if (string.IsNullOrWhiteSpace(raw))
            return new Dictionary<string, string>();

        WorkbookCellReader.CheckCellLength(raw, sheetName, rowNum, "参数JSON", errors);

        try
        {
            var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(raw);
            return dict ?? new Dictionary<string, string>();
        }
        catch (JsonException)
        {
            errors.Add(new WorkbookValidationError(
                WorkbookValidationError.InvalidJson,
                sheetName, rowNum, "参数JSON",
                "参数JSON must be a valid JSON object with string values."));
            return new Dictionary<string, string>();
        }
    }

    // ------------------------------------------------------------------
    //  Sheet 7: 第三方授权 → ThirdPartyLicense
    // ------------------------------------------------------------------

    private static IReadOnlyList<ThirdPartyLicense> ReadLicenses(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "第三方授权";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<ThirdPartyLicense>();

        var licenses = new List<ThirdPartyLicense>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<ThirdPartyLicense>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<ThirdPartyLicense>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName,
                ["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"], errors, 1))
            return Array.Empty<ThirdPartyLicense>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var licenseId = GetCellString(doc, row, colMap, "授权ID") ?? "";
            var sourceName = GetCellString(doc, row, colMap, "来源名称") ?? "";
            var fingerprint = GetCellString(doc, row, colMap, "标识或指纹") ?? "";
            var licenseNote = GetCellString(doc, row, colMap, "许可说明") ?? "";
            var evidenceRef = GetCellString(doc, row, colMap, "证据引用") ?? "";
            var validFrom = GetCellString(doc, row, colMap, "有效起始") ?? "";
            var validUntil = GetCellString(doc, row, colMap, "有效结束") ?? "";

            WorkbookCellReader.CheckCellLength(licenseId, sheetName, rowNum, "授权ID", errors);
            WorkbookCellReader.CheckCellLength(sourceName, sheetName, rowNum, "来源名称", errors);
            WorkbookCellReader.CheckCellLength(fingerprint, sheetName, rowNum, "标识或指纹", errors);
            WorkbookCellReader.CheckCellLength(licenseNote, sheetName, rowNum, "许可说明", errors);
            WorkbookCellReader.CheckCellLength(evidenceRef, sheetName, rowNum, "证据引用", errors);

            licenses.Add(new ThirdPartyLicense
            {
                LicenseId = licenseId,
                SourceName = sourceName,
                Fingerprint = fingerprint,
                LicenseNote = licenseNote,
                EvidenceRef = evidenceRef,
                ValidFrom = validFrom,
                ValidUntil = validUntil,
            });
        }

        return licenses;
    }

    // ------------------------------------------------------------------
    //  Sheet 8: 合规规则 → ComplianceRule
    // ------------------------------------------------------------------

    private static IReadOnlyList<ComplianceRule> ReadComplianceRules(
        SpreadsheetDocument doc, WorkbookPart wbPart, List<WorkbookValidationError> errors)
    {
        const string sheetName = "合规规则";
        var (part, _) = TryGetSheet(wbPart, sheetName);
        if (part is null)
            return Array.Empty<ComplianceRule>();

        var rules = new List<ComplianceRule>();
        var rows = EnumerateRows(part).ToList();

        if (rows.Count == 0)
            return Array.Empty<ComplianceRule>();

        if (WorkbookCellReader.CheckRowLimit(rows.Count, sheetName, errors))
            return Array.Empty<ComplianceRule>();

        var colMap = WorkbookCellReader.BuildColumnMap(rows[0], doc);
        if (!HasRequiredHeaders(colMap, sheetName,
                ["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"], errors, 1))
            return Array.Empty<ComplianceRule>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            var rowNum = (int)(row.RowIndex?.Value ?? 0);
            if (IsEmptyRow(row, doc))
                continue;

            WorkbookCellReader.DetectFormulas(row, doc, sheetName, rowNum, errors);

            var id = GetCellString(doc, row, colMap, "规则ID");
            WorkbookCellReader.CheckCellLength(id, sheetName, rowNum, "规则ID", errors);

            if (string.IsNullOrWhiteSpace(id))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "规则ID",
                    "规则ID is required."));
                continue;
            }

            var assetIdStr = GetCellString(doc, row, colMap, "资产ID");
            WorkbookCellReader.CheckCellLength(assetIdStr, sheetName, rowNum, "资产ID", errors);

            AssetTypeId assetId;
            if (string.IsNullOrWhiteSpace(assetIdStr))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "资产ID",
                    "资产ID is required."));
                continue;
            }

            try
            {
                assetId = AssetTypeId.Parse(assetIdStr);
            }
            catch (ArgumentException)
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.InvalidCellValue,
                    sheetName, rowNum, "资产ID",
                    "Unrecognized AssetTypeId."));
                continue;
            }

            var evidence = GetCellString(doc, row, colMap, "证据字段") ?? "";
            var requiredStatus = GetCellString(doc, row, colMap, "缺失结论") ?? "";
            var description = GetCellString(doc, row, colMap, "说明") ?? "";

            WorkbookCellReader.CheckCellLength(evidence, sheetName, rowNum, "证据字段", errors);
            WorkbookCellReader.CheckCellLength(requiredStatus, sheetName, rowNum, "缺失结论", errors);
            WorkbookCellReader.CheckCellLength(description, sheetName, rowNum, "说明", errors);

            rules.Add(new ComplianceRule
            {
                Id = id,
                AssetTypeId = assetId,
                Name = id,
                Description = description,
                EvidenceField = evidence,
                RequiredStatus = requiredStatus,
            });
        }

        return rules;
    }

    // ------------------------------------------------------------------
    //  Cell access helpers
    // ------------------------------------------------------------------

    private static string? GetCellString(
        SpreadsheetDocument doc, Row row, Dictionary<string, int> colMap, string header)
    {
        if (!colMap.TryGetValue(header, out var colIndex))
            return null;
        return WorkbookCellReader.GetStringValue(
            doc, WorkbookCellReader.GetCell(row, colIndex));
    }

    private static int? GetCellInt(
        SpreadsheetDocument doc, Row row, Dictionary<string, int> colMap, string header)
    {
        if (!colMap.TryGetValue(header, out var colIndex))
            return null;
        return WorkbookCellReader.GetIntValue(
            doc, WorkbookCellReader.GetCell(row, colIndex));
    }

    private static double? GetCellDouble(
        SpreadsheetDocument doc, Row row, Dictionary<string, int> colMap, string header)
    {
        if (!colMap.TryGetValue(header, out var colIndex))
            return null;
        return WorkbookCellReader.GetDoubleValue(
            doc, WorkbookCellReader.GetCell(row, colIndex));
    }

    private static bool? GetCellBool(
        SpreadsheetDocument doc, Row row, Dictionary<string, int> colMap, string header)
    {
        if (!colMap.TryGetValue(header, out var colIndex))
            return null;
        return WorkbookCellReader.GetBoolValue(
            doc, WorkbookCellReader.GetCell(row, colIndex));
    }

    // ------------------------------------------------------------------
    //  Utility
    // ------------------------------------------------------------------

    /// <summary>
    /// Returns true when every required header is present in the column map.
    /// Missing headers are reported as errors on the header row.
    /// </summary>
    private static bool HasRequiredHeaders(
        Dictionary<string, int> colMap, string sheetName,
        string[] requiredHeaders, List<WorkbookValidationError> errors, int headerRow)
    {
        var ok = true;
        foreach (var h in requiredHeaders)
        {
            if (!colMap.ContainsKey(h))
            {
                errors.Add(new WorkbookValidationError(
                    WorkbookValidationError.MissingHeader,
                    sheetName, headerRow, h,
                    $"Required column '{h}' is missing."));
                ok = false;
            }
        }

        return ok;
    }

    /// <summary>
    /// Determines whether a row is entirely empty (no non-whitespace cell content).
    /// </summary>
    private static bool IsEmptyRow(Row row, SpreadsheetDocument doc)
    {
        foreach (var cell in row.Elements<Cell>())
        {
            var value = WorkbookCellReader.GetStringValue(doc, cell);
            if (!string.IsNullOrWhiteSpace(value))
                return false;
        }

        return true;
    }
}
