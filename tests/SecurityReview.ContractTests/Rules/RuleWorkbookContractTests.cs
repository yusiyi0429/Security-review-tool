using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Validation;
using SecurityReview.RulePackBuilder.Excel;

namespace SecurityReview.ContractTests.Rules;

public sealed class RuleWorkbookContractTests
{
    private static readonly string[] CategoryHeaders = ["类别ID", "名称", "说明", "默认严重度", "启用"];

    // ── Helpers ─────────────────────────────────────────────────────

    private static MemoryStream CreateWorkbook(Action<SpreadsheetDocument, WorkbookPart, Sheets> configure)
    {
        var ms = new MemoryStream();
        using (var doc = SpreadsheetDocument.Create(ms, SpreadsheetDocumentType.Workbook))
        {
            var wbPart = doc.AddWorkbookPart();
            wbPart.Workbook = new Workbook();
            var sheets = wbPart.Workbook.AppendChild(new Sheets());
            configure(doc, wbPart, sheets);
        }

        ms.Position = 0;
        return ms;
    }

    private static void AddSheet(
        WorkbookPart wbPart, Sheets sheets, string name, string[][] rows)
    {
        var part = wbPart.AddNewPart<WorksheetPart>();
        var sheetData = new SheetData();
        for (uint r = 0; r < rows.Length; r++)
        {
            var row = new Row { RowIndex = r + 1 };
            for (int c = 0; c < rows[r].Length; c++)
            {
                var cell = new Cell
                {
                    DataType = CellValues.InlineString,
                    CellReference = CellRef(c, (int)r),
                };
                cell.InlineString = new InlineString { Text = new Text(rows[r][c]) };
                row.AppendChild(cell);
            }

            sheetData.AppendChild(row);
        }

        part.Worksheet = new Worksheet(sheetData);
        sheets.AppendChild(new Sheet
        {
            Name = name,
            SheetId = (uint)(sheets.Count() + 1),
            Id = wbPart.GetIdOfPart(part),
        });
    }

    private static void AddFormulaCell(
        WorkbookPart wbPart, Sheets sheets, string name, string[][] rows,
        int formulaRow, int formulaCol)
    {
        var part = wbPart.AddNewPart<WorksheetPart>();
        var sheetData = new SheetData();
        for (uint r = 0; r < rows.Length; r++)
        {
            var row = new Row { RowIndex = r + 1 };
            for (int c = 0; c < rows[r].Length; c++)
            {
                Cell cell;
                if ((int)r == formulaRow && c == formulaCol)
                {
                    cell = new Cell
                    {
                        CellFormula = new CellFormula("1+1"),
                        CellReference = CellRef(c, (int)r),
                    };
                }
                else
                {
                    cell = new Cell
                    {
                        DataType = CellValues.InlineString,
                        CellReference = CellRef(c, (int)r),
                    };
                    cell.InlineString = new InlineString { Text = new Text(rows[r][c]) };
                }

                row.AppendChild(cell);
            }

            sheetData.AppendChild(row);
        }

        part.Worksheet = new Worksheet(sheetData);
        sheets.AppendChild(new Sheet
        {
            Name = name,
            SheetId = (uint)(sheets.Count() + 1),
            Id = wbPart.GetIdOfPart(part),
        });
    }

    private static string CellRef(int col, int row)
    {
        var sb = new StringBuilder();
        int c = col + 1;
        while (c > 0)
        {
            c--;
            sb.Insert(0, (char)('A' + (c % 26)));
            c /= 26;
        }

        sb.Append(row + 1);
        return sb.ToString();
    }

    // ── Minimal valid workbook ──────────────────────────────────────

    private static MemoryStream CreateValidMinimalWorkbook()
    {
        return CreateWorkbook((doc, wbPart, sheets) =>
        {
            // Sheet 1: 规则包信息
            AddSheet(wbPart, sheets, "规则包信息",
            [
                ["键", "值"],
                ["rulePackId", "test-pack"],
                ["version", "1.0.0"],
                ["schemaVersion", "1"],
                ["minClientVersion", "1.0.0"],
                ["createdAtUtc", "2025-01-01T00:00:00Z"],
                ["signerKeyId", "rules-team-prod-01"],
                ["changeSummary", "initial"],
            ]);

            // Sheet 2: 敏感类别
            AddSheet(wbPart, sheets, "敏感类别",
            [
                ["类别ID", "名称", "说明", "默认严重度", "启用"],
                ["SENS-001", "凭据和密钥", "API密钥、密码、令牌", "Critical", "TRUE"],
            ]);

            // Sheet 3: 资产专项规则
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "测试规则"],
            ]);

            // Sheet 4: 受限实体词典
            AddSheet(wbPart, sheets, "受限实体词典",
            [
                ["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"],
                ["dict-1", "ent-1", "test", "tst", "SENS-001", "High", "ASSET-001", "2025-01-01", "2025-12-31"],
            ]);

            // Sheet 5: 安全占位符
            AddSheet(wbPart, sheets, "安全占位符",
            [
                ["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"],
                ["ph-1", "regex", "test_pattern", "default", "SENS-001", "2025-01-01", "2025-12-31"],
            ]);

            // Sheet 6: 检测器配置
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{"format":"pem"}""", "100"],
            ]);

            // Sheet 7: 第三方授权
            AddSheet(wbPart, sheets, "第三方授权",
            [
                ["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"],
                ["lic-1", "test-lib", "abc123", "MIT", "https://example.com", "2025-01-01", "2025-12-31"],
            ]);

            // Sheet 8: 合规规则
            AddSheet(wbPart, sheets, "合规规则",
            [
                ["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"],
                ["COMP-001", "ASSET-001", "evidence.json", "present", "High", "合规测试"],
            ]);
        });
    }

    // ── Tests ───────────────────────────────────────────────────────

    [Fact]
    public void Valid_minimal_workbook_passes()
    {
        using var stream = CreateValidMinimalWorkbook();
        var result = RuleWorkbookReader.Read(stream);

        Assert.NotNull(result.Document);
        Assert.Empty(result.Errors);
        Assert.NotEmpty(result.Document!.Categories);
        Assert.NotEmpty(result.Document.Rules);
        Assert.NotEmpty(result.Document.Detectors);
        Assert.NotEmpty(result.Document.ComplianceRules);
        Assert.NotEmpty(result.Entities);
        Assert.NotEmpty(result.Placeholders);
        Assert.NotEmpty(result.Licenses);
    }

    [Fact]
    public void Generated_template_matches_the_supported_workbook_schema()
    {
        string path = Path.Combine(Path.GetTempPath(), $"srt-rules-template-{Guid.NewGuid():N}.xlsx");
        try
        {
            RuleWorkbookTemplateWriter.Write(path);

            using var stream = File.OpenRead(path);
            var result = RuleWorkbookReader.Read(stream);

            Assert.NotNull(result.Document);
            Assert.Empty(result.Errors);
            Assert.NotEmpty(result.Document!.Categories);
            Assert.NotEmpty(result.Document.Rules);
            Assert.NotEmpty(result.Document.Detectors);
            Assert.NotEmpty(result.Document.ComplianceRules);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void Missing_required_sheet_reports_MissingSheet()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            // Only add rules sheet, missing most required sheets
            AddSheet(wbPart, sheets, "规则包信息",
            [
                ["键", "值"],
                ["rulePackId", "test-pack"],
            ]);
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", ""],
            ]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{}""", "100"],
            ]);
        });

        var result = RuleWorkbookReader.Read(stream);

        Assert.Contains(result.Errors, e => e.Code == WorkbookValidationError.MissingSheet);
    }

    [Fact]
    public void Missing_required_header_reports_MissingHeader()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            // Sheet 敏感类别 with wrong header
            var part = wbPart.AddNewPart<WorksheetPart>();
            var sheetData = new SheetData();
            var row = new Row { RowIndex = 1 };
            var cell = new Cell
            {
                DataType = CellValues.InlineString,
                CellReference = "A1",
            };
            cell.InlineString = new InlineString { Text = new Text("WrongHeader") };
            row.AppendChild(cell);
            sheetData.AppendChild(row);
            part.Worksheet = new Worksheet(sheetData);
            sheets.AppendChild(new Sheet
            {
                Name = "敏感类别",
                SheetId = (uint)(sheets.Count() + 1),
                Id = wbPart.GetIdOfPart(part),
            });

            // Other required sheets with data
            AddSheet(wbPart, sheets, "规则包信息", [["键", "值"], ["rulePackId", "test"]]);
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", ""],
            ]);
            AddSheet(wbPart, sheets, "受限实体词典",
            [["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "安全占位符",
            [["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{}""", "100"],
            ]);
            AddSheet(wbPart, sheets, "第三方授权",
            [["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "合规规则",
            [["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"]]);
        });

        var result = RuleWorkbookReader.Read(stream);

        Assert.Contains(result.Errors, e => e.Code == WorkbookValidationError.MissingHeader
            && e.Sheet == "敏感类别");
    }

    [Fact]
    public void Formula_in_cell_reports_FormulaCell()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            // 敏感类别 sheet with formula in data row
            AddFormulaCell(wbPart, sheets, "敏感类别",
            [
                ["类别ID", "名称", "说明", "默认严重度", "启用"],
                ["SENS-001", "凭据", "desc", "Critical", "TRUE"],
            ],
            formulaRow: 1, formulaCol: 1); // "凭据" cell has formula

            AddSheet(wbPart, sheets, "规则包信息", [["键", "值"], ["rulePackId", "test"]]);
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", ""],
            ]);
            AddSheet(wbPart, sheets, "受限实体词典",
            [["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "安全占位符",
            [["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{}""", "100"],
            ]);
            AddSheet(wbPart, sheets, "第三方授权",
            [["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "合规规则",
            [["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"]]);
        });

        var result = RuleWorkbookReader.Read(stream);

        Assert.Contains(result.Errors, e => e.Code == WorkbookValidationError.FormulaCell);
    }

    [Fact]
    public void Cell_text_over_4096_chars_reports_CellTooLong()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            // Create a sheet where name column exceeds 4096 chars
            var part = wbPart.AddNewPart<WorksheetPart>();
            var sheetData = new SheetData();

            // Header
            var headerRow = new Row { RowIndex = 1 };
            foreach (var (h, i) in CategoryHeaders.Select((h, i) => (h, i)))
            {
                var cell = new Cell
                {
                    DataType = CellValues.InlineString,
                    CellReference = CellRef(i, 0),
                };
                cell.InlineString = new InlineString { Text = new Text(h) };
                headerRow.AppendChild(cell);
            }

            sheetData.AppendChild(headerRow);

            // Data row with overlong name
            var dataRow = new Row { RowIndex = 2 };
            var longName = new string('A', 4100);

            var catCell = new Cell
            {
                DataType = CellValues.InlineString,
                CellReference = CellRef(0, 1),
            };
            catCell.InlineString = new InlineString { Text = new Text("SENS-001") };
            dataRow.AppendChild(catCell);

            var nameCell = new Cell
            {
                DataType = CellValues.InlineString,
                CellReference = CellRef(1, 1),
            };
            nameCell.InlineString = new InlineString { Text = new Text(longName) };
            dataRow.AppendChild(nameCell);

            var descCell = new Cell
            {
                DataType = CellValues.InlineString,
                CellReference = CellRef(2, 1),
            };
            descCell.InlineString = new InlineString { Text = new Text("desc") };
            dataRow.AppendChild(descCell);

            var sevCell = new Cell
            {
                DataType = CellValues.InlineString,
                CellReference = CellRef(3, 1),
            };
            sevCell.InlineString = new InlineString { Text = new Text("Critical") };
            dataRow.AppendChild(sevCell);

            var enCell = new Cell
            {
                DataType = CellValues.InlineString,
                CellReference = CellRef(4, 1),
            };
            enCell.InlineString = new InlineString { Text = new Text("TRUE") };
            dataRow.AppendChild(enCell);

            sheetData.AppendChild(dataRow);
            part.Worksheet = new Worksheet(sheetData);
            sheets.AppendChild(new Sheet
            {
                Name = "敏感类别",
                SheetId = (uint)(sheets.Count() + 1),
                Id = wbPart.GetIdOfPart(part),
            });

            AddSheet(wbPart, sheets, "规则包信息", [["键", "值"], ["rulePackId", "test"]]);
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", ""],
            ]);
            AddSheet(wbPart, sheets, "受限实体词典",
            [["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "安全占位符",
            [["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{}""", "100"],
            ]);
            AddSheet(wbPart, sheets, "第三方授权",
            [["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "合规规则",
            [["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"]]);
        });

        var result = RuleWorkbookReader.Read(stream);

        Assert.Contains(result.Errors, e => e.Code == WorkbookValidationError.CellTooLong
            && e.Sheet == "敏感类别");
    }

    [Fact]
    public void Duplicate_rule_id_reports_DuplicateId_from_RulePackDocument()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            AddSheet(wbPart, sheets, "规则包信息",
            [
                ["键", "值"],
                ["rulePackId", "test-pack"],
                ["version", "1.0.0"],
                ["schemaVersion", "1"],
                ["minClientVersion", "1.0.0"],
            ]);
            AddSheet(wbPart, sheets, "敏感类别",
            [
                ["类别ID", "名称", "说明", "默认严重度", "启用"],
                ["SENS-001", "凭据和密钥", "API密钥、密码、令牌", "Critical", "TRUE"],
            ]);
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "dup1"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "dup2"],
            ]);
            AddSheet(wbPart, sheets, "受限实体词典",
            [["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "安全占位符",
            [["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{"format":"pem"}""", "100"],
            ]);
            AddSheet(wbPart, sheets, "第三方授权",
            [["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "合规规则",
            [["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"]]);
        });

        var result = RuleWorkbookReader.Read(stream);

        // The reader itself won't detect duplicate IDs; RulePackDocument.Validate() will
        if (result.Document is not null)
        {
            var validateErrors = result.Document.Validate();
            Assert.Contains(validateErrors, e => e.Contains("RULE-TEST-001", StringComparison.Ordinal)
                && (e.Contains("Duplicate", StringComparison.OrdinalIgnoreCase)
                    || e.Contains("duplicate", StringComparison.Ordinal)));
        }
    }

    [Fact]
    public void Dangling_detector_reference_detected_by_graph_validator()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            AddSheet(wbPart, sheets, "规则包信息",
            [
                ["键", "值"],
                ["rulePackId", "test-pack"],
                ["version", "1.0.0"],
                ["schemaVersion", "1"],
                ["minClientVersion", "1.0.0"],
            ]);
            AddSheet(wbPart, sheets, "敏感类别",
            [
                ["类别ID", "名称", "说明", "默认严重度", "启用"],
                ["SENS-001", "凭据和密钥", "API密钥、密码、令牌", "Critical", "TRUE"],
            ]);
            // Rule references DET-MISSING, but detectors sheet is empty
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-MISSING", "default", "High", "High", "FALSE", "TRUE", "悬空引用"],
            ]);
            AddSheet(wbPart, sheets, "受限实体词典",
            [["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "安全占位符",
            [["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", """{}""", "100"],
            ]);
            AddSheet(wbPart, sheets, "第三方授权",
            [["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "合规规则",
            [["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"]]);
        });

        var result = RuleWorkbookReader.Read(stream);

        if (result.Document is not null)
        {
            var graphResult = RuleGraphValidator.Validate(result.Document);
            Assert.False(graphResult.IsValid);
            Assert.Contains(graphResult.Errors,
                e => e.Contains("DET-MISSING", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Invalid_json_parameter_reports_InvalidJson()
    {
        using var stream = CreateWorkbook((doc, wbPart, sheets) =>
        {
            AddSheet(wbPart, sheets, "规则包信息",
            [
                ["键", "值"],
                ["rulePackId", "test-pack"],
                ["version", "1.0.0"],
                ["schemaVersion", "1"],
                ["minClientVersion", "1.0.0"],
            ]);
            AddSheet(wbPart, sheets, "敏感类别",
            [
                ["类别ID", "名称", "说明", "默认严重度", "启用"],
                ["SENS-001", "凭据和密钥", "API密钥、密码、令牌", "Critical", "TRUE"],
            ]);
            AddSheet(wbPart, sheets, "资产专项规则",
            [
                ["规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"],
                ["RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", ""],
            ]);
            AddSheet(wbPart, sheets, "受限实体词典",
            [["词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "安全占位符",
            [["占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "检测器配置",
            [
                ["检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"],
                ["DET-TEST-001", "KnownFormat", "default", "{invalid json}", "100"],
            ]);
            AddSheet(wbPart, sheets, "第三方授权",
            [["授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"]]);
            AddSheet(wbPart, sheets, "合规规则",
            [["规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"]]);
        });

        var result = RuleWorkbookReader.Read(stream);

        Assert.Contains(result.Errors, e => e.Code == WorkbookValidationError.InvalidJson);
    }
}
