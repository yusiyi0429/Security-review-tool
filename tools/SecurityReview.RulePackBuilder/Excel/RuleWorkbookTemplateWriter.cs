using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;

namespace SecurityReview.RulePackBuilder.Excel;

/// <summary>
/// Produces the supported Excel workbook format for rule-pack authors.
/// The generated workbook is intentionally kept in the same project as the
/// reader so template headers cannot silently drift from the importer schema.
/// </summary>
public static class RuleWorkbookTemplateWriter
{
    private static readonly TemplateSheet[] Sheets =
    [
        new(
            "规则包信息",
            ["键", "值"],
            [
                ["rulePackId", "security-review-rules"],
                ["version", "1.0.0"],
                ["schemaVersion", "1"],
                ["minClientVersion", "1.0.0"],
                ["createdAtUtc", "2026-07-24T00:00:00Z"],
                ["signerKeyId", "rules-team-prod-01"],
                ["changeSummary", "请填写本次规则变更说明"],
            ]),
        new(
            "敏感类别",
            ["类别ID", "名称", "说明", "默认严重度", "启用"],
            [
                ["SENS-001", "凭据和密钥", "API 密钥、密码和访问令牌", "Critical", "TRUE"],
            ]),
        new(
            "资产专项规则",
            ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
            [
                ["RULE-TEMPLATE-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEMPLATE-001", "default", "High", "High", "FALSE", "TRUE", "示例规则，请按实际需要修改"],
            ]),
        new(
            "受限实体词典",
            ["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"],
            [
                ["dict-template", "entity-template", "示例受限实体", "示例别名", "SENS-001", "High", "ASSET-001", "2026-01-01", "2026-12-31"],
            ]),
        new(
            "安全占位符",
            ["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"],
            [
                ["placeholder-template", "regex", "example_placeholder", "test", "SENS-001", "2026-01-01", "2026-12-31"],
            ]),
        new(
            "检测器配置",
            ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
            [
                ["DET-TEMPLATE-001", "KnownFormat", "default", "{\"format\":\"pem\"}", "100"],
            ]),
        new(
            "第三方授权",
            ["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"],
            [
                ["license-template", "示例依赖", "example-fingerprint", "MIT", "https://example.invalid/license", "2026-01-01", "2026-12-31"],
            ]),
        new(
            "合规规则",
            ["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"],
            [
                ["COMP-TEMPLATE-001", "ASSET-001", "evidence.json", "present", "High", "示例合规规则，请按实际需要修改"],
            ]),
    ];

    public static void Write(string outputPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

        string? directory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        using var document = SpreadsheetDocument.Create(
            outputPath, SpreadsheetDocumentType.Workbook);
        var workbookPart = document.AddWorkbookPart();
        workbookPart.Workbook = new Workbook();
        var sheets = workbookPart.Workbook.AppendChild(new Sheets());

        for (int index = 0; index < Sheets.Length; index++)
            AddSheet(workbookPart, sheets, Sheets[index], (uint)(index + 1));

        workbookPart.Workbook.Save();
    }

    private static void AddSheet(
        WorkbookPart workbookPart,
        Sheets sheets,
        TemplateSheet definition,
        uint sheetId)
    {
        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
        var sheetData = new SheetData();

        AppendRow(sheetData, 1, definition.Headers);
        for (int rowIndex = 0; rowIndex < definition.SampleRows.Length; rowIndex++)
            AppendRow(sheetData, (uint)(rowIndex + 2), definition.SampleRows[rowIndex]);

        worksheetPart.Worksheet = new Worksheet(sheetData);
        sheets.AppendChild(new Sheet
        {
            Id = workbookPart.GetIdOfPart(worksheetPart),
            SheetId = sheetId,
            Name = definition.Name,
        });
    }

    private static void AppendRow(SheetData sheetData, uint rowIndex, string[] values)
    {
        var row = new Row { RowIndex = rowIndex };
        for (int columnIndex = 0; columnIndex < values.Length; columnIndex++)
        {
            var text = new Text(values[columnIndex])
            {
                Space = SpaceProcessingModeValues.Preserve,
            };
            row.Append(new Cell
            {
                CellReference = $"{GetColumnName(columnIndex)}{rowIndex}",
                DataType = CellValues.InlineString,
                InlineString = new InlineString(text),
            });
        }

        sheetData.Append(row);
    }

    private static string GetColumnName(int zeroBasedColumn)
    {
        var result = new System.Text.StringBuilder();
        int column = zeroBasedColumn + 1;
        while (column > 0)
        {
            column--;
            result.Insert(0, (char)('A' + (column % 26)));
            column /= 26;
        }

        return result.ToString();
    }

    private sealed record TemplateSheet(string Name, string[] Headers, string[][] SampleRows);
}
