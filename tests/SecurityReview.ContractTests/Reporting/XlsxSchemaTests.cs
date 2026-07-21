using SecurityReview.Infrastructure.Reporting;

namespace SecurityReview.ContractTests.Reporting;

public sealed class XlsxSchemaTests
{
    [Fact]
    public void Six_sheets_exact_names_and_order()
    {
        Assert.Equal(6, XlsxSheetSchemas.Sheets.Length);

        var expected = new[]
        {
            "扫描摘要",
            "敏感内容发现",
            "资产合规发现",
            "未覆盖内容",
            "文件清单",
            "复核记录",
        };

        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], XlsxSheetSchemas.Sheets[i].Name);
            Assert.Equal(i, XlsxSheetSchemas.IndexOf(expected[i]));
        }
    }

    [Fact]
    public void ScanSummary_sheet_has_exact_headers()
    {
        var expected = new[]
        {
            "扫描ID", "任务状态", "有界结论", "开始时间UTC", "结束时间UTC",
            "资产ID", "资产版本", "输入摘要", "规则包ID", "规则包版本",
            "规则包SHA256", "本地补充SHA256", "有效策略SHA256", "客户端版本",
            "解析器指纹", "检测器指纹", "提示模板版本", "LLM模型", "文件总数",
            "总字节数", "敏感发现数", "合规发现数", "未覆盖数", "缓存复用数",
            "内容转义单元格数", "是否旧规则", "是否本地补充",
        };

        Assert.Equal(expected, XlsxSheetSchemas.ScanSummaryHeaders);
        Assert.Equal(expected.Length, XlsxSheetSchemas.ScanSummaryHeaders.Length);
    }

    [Fact]
    public void SensitiveFinding_sheet_has_exact_headers()
    {
        var expected = new[]
        {
            "扫描ID", "资产ID", "资产版本", "发现组ID", "发现位置ID",
            "差异状态", "类别ID", "类别", "风险等级", "置信度",
            "完整命中值", "上下文", "资产类型", "相对或虚拟路径", "位置类型",
            "精确位置", "规则ID", "检测器ID", "规则版本", "LLM状态",
            "LLM分类", "LLM置信度", "LLM理由", "人工状态", "例外有效期UTC",
        };

        Assert.Equal(expected, XlsxSheetSchemas.SensitiveFindingHeaders);
    }

    [Fact]
    public void ComplianceFinding_sheet_has_exact_headers()
    {
        var expected = new[]
        {
            "扫描ID", "资产ID", "资产版本", "发现组ID", "发现位置ID",
            "差异状态", "资产类型", "合规规则ID", "结论", "风险等级",
            "证据状态", "证据引用", "相对或虚拟路径", "精确位置", "人工状态", "人工理由",
        };

        Assert.Equal(expected, XlsxSheetSchemas.ComplianceFindingHeaders);
    }

    [Fact]
    public void CoverageGap_sheet_has_exact_headers()
    {
        var expected = new[]
        {
            "缺口ID", "阶段", "原因代码", "说明代码", "格式",
            "相对或虚拟路径", "计划字节数", "处理字节数", "解析器ID",
            "解析器版本", "记录时间UTC",
        };

        Assert.Equal(expected, XlsxSheetSchemas.CoverageGapHeaders);
    }

    [Fact]
    public void FileRecord_sheet_has_exact_headers()
    {
        var expected = new[]
        {
            "文件ID", "相对或虚拟路径", "数据流", "资产类型", "格式",
            "大小", "内容SHA256", "解析器ID", "解析器版本", "覆盖状态",
            "是否扩展名不一致", "是否缓存复用",
        };

        Assert.Equal(expected, XlsxSheetSchemas.FileRecordHeaders);
    }

    [Fact]
    public void ReviewRecord_sheet_has_exact_headers()
    {
        var expected = new[]
        {
            "决策ID", "发现组ID", "发现位置ID", "状态", "操作者",
            "记录时间UTC", "理由", "例外绑定摘要", "例外有效期UTC",
        };

        Assert.Equal(expected, XlsxSheetSchemas.ReviewRecordHeaders);
    }

    [Fact]
    public void Max_data_rows_is_excel_hard_limit()
    {
        Assert.Equal(1_048_575, XlsxSheetSchemas.MaxDataRows);
    }
}
