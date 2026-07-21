namespace SecurityReview.Infrastructure.Reporting;

/// <summary>
/// Frozen definitions for the six-sheet XLSX report. Every sheet name, order,
/// and column header is a product contract — change nothing without updating
/// acceptance tests and documentation.
/// </summary>
public static class XlsxSheetSchemas
{
    /// <summary>
    /// Maximum data rows per sheet (XLSX hard limit). Each sheet may contain at
    /// most this many data rows plus one header row.
    /// </summary>
    public const int MaxDataRows = 1_048_575;

    public static readonly (string Name, string[] Headers)[] Sheets =
    [
        ("扫描摘要", ScanSummaryHeaders!),
        ("敏感内容发现", SensitiveFindingHeaders!),
        ("资产合规发现", ComplianceFindingHeaders!),
        ("未覆盖内容", CoverageGapHeaders!),
        ("文件清单", FileRecordHeaders!),
        ("复核记录", ReviewRecordHeaders!),
    ];

    public static readonly string[] ScanSummaryHeaders =
    [
        "扫描ID",
        "任务状态",
        "有界结论",
        "开始时间UTC",
        "结束时间UTC",
        "资产ID",
        "资产版本",
        "输入摘要",
        "规则包ID",
        "规则包版本",
        "规则包SHA256",
        "本地补充SHA256",
        "有效策略SHA256",
        "客户端版本",
        "解析器指纹",
        "检测器指纹",
        "提示模板版本",
        "LLM模型",
        "文件总数",
        "总字节数",
        "敏感发现数",
        "合规发现数",
        "未覆盖数",
        "缓存复用数",
        "内容转义单元格数",
        "是否旧规则",
        "是否本地补充",
    ];

    public static readonly string[] SensitiveFindingHeaders =
    [
        "扫描ID",
        "资产ID",
        "资产版本",
        "发现组ID",
        "发现位置ID",
        "差异状态",
        "类别ID",
        "类别",
        "风险等级",
        "置信度",
        "完整命中值",
        "上下文",
        "资产类型",
        "相对或虚拟路径",
        "位置类型",
        "精确位置",
        "规则ID",
        "检测器ID",
        "规则版本",
        "LLM状态",
        "LLM分类",
        "LLM置信度",
        "LLM理由",
        "人工状态",
        "例外有效期UTC",
    ];

    public static readonly string[] ComplianceFindingHeaders =
    [
        "扫描ID",
        "资产ID",
        "资产版本",
        "发现组ID",
        "发现位置ID",
        "差异状态",
        "资产类型",
        "合规规则ID",
        "结论",
        "风险等级",
        "证据状态",
        "证据引用",
        "相对或虚拟路径",
        "精确位置",
        "人工状态",
        "人工理由",
    ];

    public static readonly string[] CoverageGapHeaders =
    [
        "缺口ID",
        "阶段",
        "原因代码",
        "说明代码",
        "格式",
        "相对或虚拟路径",
        "计划字节数",
        "处理字节数",
        "解析器ID",
        "解析器版本",
        "记录时间UTC",
    ];

    public static readonly string[] FileRecordHeaders =
    [
        "文件ID",
        "相对或虚拟路径",
        "数据流",
        "资产类型",
        "格式",
        "大小",
        "内容SHA256",
        "解析器ID",
        "解析器版本",
        "覆盖状态",
        "是否扩展名不一致",
        "是否缓存复用",
    ];

    public static readonly string[] ReviewRecordHeaders =
    [
        "决策ID",
        "发现组ID",
        "发现位置ID",
        "状态",
        "操作者",
        "记录时间UTC",
        "理由",
        "例外绑定摘要",
        "例外有效期UTC",
    ];

    /// <summary>
    /// Returns the 0-based index of the sheet matching <paramref name="name"/>,
    /// or -1 when no sheet matches.
    /// </summary>
    public static int IndexOf(string name)
    {
        for (int i = 0; i < Sheets.Length; i++)
        {
            if (string.Equals(Sheets[i].Name, name, StringComparison.Ordinal))
                return i;
        }

        return -1;
    }
}
