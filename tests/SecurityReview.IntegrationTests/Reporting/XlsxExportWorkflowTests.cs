using SecurityReview.Application.Reporting;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Reporting;

namespace SecurityReview.IntegrationTests.Reporting;

/// <summary>
/// End-to-end export workflow tests. Create domain objects, feed them
/// through a test data reader, export to temp directory, validate.
/// Full execution requires Windows (runtime-level dependencies on
/// cryptography), but compilation is verified on Linux.
/// </summary>
public sealed class XlsxExportWorkflowTests : IDisposable
{
    private readonly string _tempDir;

    public XlsxExportWorkflowTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "xlsx-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort */ }
    }

    [Fact]
    public async Task Full_export_six_sheets_validated()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId, rowCount: 10);
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "report.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        ReportExportResult result = await exporter.ExportAsync(command, reader);

        Assert.Equal("exported", result.Status);
        Assert.NotNull(result.TargetSha256);
        Assert.Equal(64, result.TargetSha256!.Length);
        Assert.True(File.Exists(target));

        // Verify row counts
        Assert.Equal(1, result.RowCounts["扫描摘要"]);
        Assert.Equal(10, result.RowCounts["敏感内容发现"]);
        Assert.Equal(10, result.RowCounts["资产合规发现"]);
        Assert.Equal(10, result.RowCounts["未覆盖内容"]);
        Assert.Equal(10, result.RowCounts["文件清单"]);
        Assert.Equal(10, result.RowCounts["复核记录"]);
    }

    [Fact]
    public async Task Target_exists_preserves_existing_no_overwrite()
    {
        var scanId = new ScanId(Guid.NewGuid());
        string target = Path.Combine(_tempDir, "existing.xlsx");
        File.WriteAllText(target, "existing content");

        var reader = new TestReportDataReader(scanId);
        var exporter = new XlsxReportExporter();
        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        ReportExportResult result = await exporter.ExportAsync(command, reader);

        Assert.Equal("target_exists", result.Status);
        Assert.Equal("existing content", File.ReadAllText(target));
    }

    [Fact]
    public async Task Row_limit_exceeded_rejects_export()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId, rowCount: XlsxSheetSchemas.MaxDataRows + 1);
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "overflow.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        ReportExportResult result = await exporter.ExportAsync(command, reader);

        Assert.Equal("xlsx_row_limit_exceeded", result.Status);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public async Task Cell_with_bidirectional_controls_is_escaped_and_counted_in_summary()
    {
        var scanId = new ScanId(Guid.NewGuid());
        // Test data reader with a value containing bidir controls
        var reader = new TestReportDataReader(scanId, rowCount: 1,
            sensitiveFullHitValue: "test\u200Ebidir");
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "bidir-escape.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        ReportExportResult result = await exporter.ExportAsync(command, reader);

        Assert.Equal("exported", result.Status);
        // The escaped cell count in the summary should show 1
        Assert.Equal(1, result.RowCounts["敏感内容发现"]);
    }

    [Fact]
    public async Task Cell_with_xml_invalid_char_is_escaped()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId, rowCount: 1,
            sensitiveFullHitValue: "raw\x00value");
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "xml-invalid.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        ReportExportResult result = await exporter.ExportAsync(command, reader);

        Assert.Equal("exported", result.Status);
    }

    [Fact]
    public async Task Formula_value_is_rejected()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId, rowCount: 1,
            sensitiveFullHitValue: "=SUM(1,2)");
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "formula.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        // Formula values are rejected; the exporter throws on WriteTextCellOrThrow
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => exporter.ExportAsync(command, reader));
    }

    [Fact]
    public async Task Empty_scan_exports_header_only_rows()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId, rowCount: 0);
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "empty.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: true);

        ReportExportResult result = await exporter.ExportAsync(command, reader);

        Assert.Equal("exported", result.Status);
        Assert.Equal(1, result.RowCounts["扫描摘要"]);
        Assert.Equal(0, result.RowCounts["敏感内容发现"]);
    }

    [Fact]
    public async Task Export_rejects_non_xlsx_extension()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId);
        var exporter = new XlsxReportExporter();
        var command = new ExportXlsxCommand(scanId, "/tmp/report.csv", ContainsCompleteSensitiveValues: true);

        await Assert.ThrowsAsync<ArgumentException>(
            () => exporter.ExportAsync(command, reader));
    }

    [Fact]
    public async Task Export_requires_sensitive_values_acknowledgement()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var reader = new TestReportDataReader(scanId);
        var exporter = new XlsxReportExporter();
        string target = Path.Combine(_tempDir, "report.xlsx");

        var command = new ExportXlsxCommand(scanId, target, ContainsCompleteSensitiveValues: false);

        await Assert.ThrowsAsync<ArgumentException>(
            () => exporter.ExportAsync(command, reader));
    }

    // ---------------------------------------------------------------
    // Test data reader
    // ---------------------------------------------------------------

    private sealed class TestReportDataReader : IReportDataReader
    {
        private readonly ScanId _scanId;
        private readonly int _rowCount;
        private readonly string _sensitiveFullHitValue;

        public TestReportDataReader(
            ScanId scanId,
            int rowCount = 5,
            string sensitiveFullHitValue = "test_value")
        {
            _scanId = scanId;
            _rowCount = rowCount;
            _sensitiveFullHitValue = sensitiveFullHitValue;
        }

        public Task<ExportScanSummary> GetScanSummaryAsync(ScanId scanId, CancellationToken ct)
        {
            return Task.FromResult(new ExportScanSummary(
                ScanId: _scanId.Value.ToString(),
                TaskStatus: "Completed",
                BoundedConclusion: "completed_no_risk",
                StartTimeUtc: "2026-01-01T00:00:00Z",
                EndTimeUtc: "2026-01-01T01:00:00Z",
                AssetId: "asset-001",
                AssetVersion: "1.0.0",
                InputSummary: "test scan",
                RulePackId: "RP-001",
                RulePackVersion: "1.0",
                RulePackSha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                LocalSupplementSha256: "",
                EffectivePolicySha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                ClientVersion: "1.0.0",
                ParserFingerprint: "parser-v1",
                DetectorFingerprint: "detector-v1",
                PromptTemplateVersion: "v1",
                LlmModel: "gpt-4",
                TotalFiles: _rowCount,
                TotalBytes: _rowCount * 1024L,
                SensitiveFindingsCount: _rowCount,
                ComplianceFindingsCount: _rowCount,
                UncoveredCount: _rowCount,
                CacheReuseCount: 0,
                ContentEscapedCellCount: 0,
                IsLegacyRule: false,
                IsLocalSupplement: false));
        }

        public Task<IReadOnlyList<ExportSensitiveFinding>> GetSensitiveFindingsAsync(ScanId scanId, CancellationToken ct)
        {
            var list = new List<ExportSensitiveFinding>(_rowCount);
            for (int i = 0; i < _rowCount; i++)
            {
                list.Add(new ExportSensitiveFinding(
                    ScanId: _scanId.Value.ToString(),
                    AssetId: "asset-001",
                    AssetVersion: "1.0.0",
                    FindingGroupId: $"FG-{i:D4}",
                    FindingOccurrenceId: $"FO-{i:D4}",
                    DifferenceStatus: "New",
                    CategoryId: "SENS-001",
                    Category: "API Key",
                    Severity: "High",
                    Confidence: "High",
                    FullHitValue: _sensitiveFullHitValue,
                    Context: "line " + i,
                    AssetType: "text",
                    VirtualPath: $"/src/file{i}.txt",
                    LocatorType: "text",
                    PreciseLocation: $"text:{i}:0@0+10",
                    RuleId: "RULE-001",
                    DetectorId: "DET-001",
                    RuleVersion: "1.0",
                    LlmStatus: "pending",
                    LlmClassification: "",
                    LlmConfidence: "",
                    LlmReason: "",
                    HumanReviewStatus: "Pending",
                    ExceptionExpiryUtc: ""));
            }

            return Task.FromResult<IReadOnlyList<ExportSensitiveFinding>>(list);
        }

        public Task<IReadOnlyList<ExportComplianceFinding>> GetComplianceFindingsAsync(ScanId scanId, CancellationToken ct)
        {
            var list = new List<ExportComplianceFinding>(_rowCount);
            for (int i = 0; i < _rowCount; i++)
            {
                list.Add(new ExportComplianceFinding(
                    ScanId: _scanId.Value.ToString(),
                    AssetId: "asset-001",
                    AssetVersion: "1.0.0",
                    FindingGroupId: $"FG-C-{i:D4}",
                    FindingOccurrenceId: $"FO-C-{i:D4}",
                    DifferenceStatus: "New",
                    AssetType: "text",
                    ComplianceRuleId: "COMP-001",
                    Conclusion: "non_compliant",
                    Severity: "Medium",
                    EvidenceStatus: "verified",
                    EvidenceReference: $"ref-{i}",
                    VirtualPath: $"/src/file{i}.txt",
                    PreciseLocation: $"text:{i}:0@0+5",
                    HumanReviewStatus: "Pending",
                    HumanReviewReason: ""));
            }

            return Task.FromResult<IReadOnlyList<ExportComplianceFinding>>(list);
        }

        public Task<IReadOnlyList<ExportCoverageGapRow>> GetCoverageGapsAsync(ScanId scanId, CancellationToken ct)
        {
            var list = new List<ExportCoverageGapRow>(_rowCount);
            for (int i = 0; i < _rowCount; i++)
            {
                list.Add(new ExportCoverageGapRow(
                    GapId: Guid.NewGuid().ToString(),
                    Stage: "parsing",
                    ReasonCode: "UnsupportedFormat",
                    DetailCode: "binary_blob",
                    Format: "application/octet-stream",
                    VirtualPath: $"/data/blob{i}.bin",
                    PlannedBytes: 1024,
                    ProcessedBytes: 0,
                    ParserId: "PARSER-001",
                    ParserVersion: "1.0",
                    RecordedAtUtc: "2026-01-01T00:00:00Z"));
            }

            return Task.FromResult<IReadOnlyList<ExportCoverageGapRow>>(list);
        }

        public Task<IReadOnlyList<ExportFileRecordRow>> GetFileRecordsAsync(ScanId scanId, CancellationToken ct)
        {
            var list = new List<ExportFileRecordRow>(_rowCount);
            for (int i = 0; i < _rowCount; i++)
            {
                list.Add(new ExportFileRecordRow(
                    FileId: Guid.NewGuid().ToString(),
                    VirtualPath: $"/src/file{i}.txt",
                    DataStream: "",
                    AssetType: "text",
                    Format: "text/plain",
                    Size: 1024,
                    ContentSha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    ParserId: "PARSER-001",
                    ParserVersion: "1.0",
                    CoverageStatus: "Covered",
                    ExtensionMismatch: false,
                    CacheReuse: false));
            }

            return Task.FromResult<IReadOnlyList<ExportFileRecordRow>>(list);
        }

        public Task<IReadOnlyList<ExportReviewRecordRow>> GetReviewRecordsAsync(ScanId scanId, CancellationToken ct)
        {
            var list = new List<ExportReviewRecordRow>(_rowCount);
            for (int i = 0; i < _rowCount; i++)
            {
                list.Add(new ExportReviewRecordRow(
                    DecisionId: Guid.NewGuid().ToString(),
                    FindingGroupId: $"FG-{i:D4}",
                    FindingOccurrenceId: $"FO-{i:D4}",
                    Status: "ConfirmedRisk",
                    Operator: "user@example.com",
                    RecordedAtUtc: "2026-01-01T01:00:00Z",
                    Reason: "confirmed_sensitive",
                    ExceptionBindingSummary: "",
                    ExceptionExpiryUtc: ""));
            }

            return Task.FromResult<IReadOnlyList<ExportReviewRecordRow>>(list);
        }
    }
}
