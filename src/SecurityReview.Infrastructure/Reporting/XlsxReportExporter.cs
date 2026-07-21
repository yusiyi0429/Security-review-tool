using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Reporting;
using SecurityReview.Domain;

namespace SecurityReview.Infrastructure.Reporting;

/// <summary>
/// Exports a validated six-sheet XLSX report using <see cref="OpenXmlWriter"/>
/// streaming. The export is atomic: a randomized temp file is written,
/// verified, hashed, and atomically moved to the target. Any failure deletes
/// the temp file best-effort.
/// </summary>
public sealed class XlsxReportExporter : IXlsxReportExporter
{
    private readonly IDiagnosticSink _diagnostics;

    public XlsxReportExporter(IDiagnosticSink? diagnostics = null)
    {
        _diagnostics = diagnostics ?? new NullDiagnosticSink();
    }

    public async Task<ReportExportResult> ExportAsync(
        ExportXlsxCommand command,
        IReportDataReader reader,
        CancellationToken ct = default)
    {
        // --- 1. Validate preconditions ---
        ValidateExtension(command.TargetPath);

        if (!command.ContainsCompleteSensitiveValues)
            throw new ArgumentException(
                "Export requires ContainsCompleteSensitiveValues=true to acknowledge raw values in output.");

        // --- 2. Preflight row counts ---
        var rowCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        var summary = await reader.GetScanSummaryAsync(command.ScanId, ct).ConfigureAwait(false);
        rowCounts["扫描摘要"] = 1;

        var sensitive = await reader.GetSensitiveFindingsAsync(command.ScanId, ct).ConfigureAwait(false);
        rowCounts["敏感内容发现"] = sensitive.Count;

        var compliance = await reader.GetComplianceFindingsAsync(command.ScanId, ct).ConfigureAwait(false);
        rowCounts["资产合规发现"] = compliance.Count;

        var gaps = await reader.GetCoverageGapsAsync(command.ScanId, ct).ConfigureAwait(false);
        rowCounts["未覆盖内容"] = gaps.Count;

        var files = await reader.GetFileRecordsAsync(command.ScanId, ct).ConfigureAwait(false);
        rowCounts["文件清单"] = files.Count;

        var reviews = await reader.GetReviewRecordsAsync(command.ScanId, ct).ConfigureAwait(false);
        rowCounts["复核记录"] = reviews.Count;

        // Row limit enforcement
        foreach (var (sheetName, _) in XlsxSheetSchemas.Sheets)
        {
            if (rowCounts.TryGetValue(sheetName, out int count) && count > XlsxSheetSchemas.MaxDataRows)
            {
                return ReportExportResult.RowLimitExceeded(command.ScanId, sheetName, count);
            }
        }

        // --- 3. Create temp file ---
        string targetDir = Path.GetDirectoryName(command.TargetPath)
            ?? throw new ArgumentException("Target path has no directory component.");
        string tempPath = Path.Combine(targetDir,
            Path.GetFileNameWithoutExtension(command.TargetPath) +
            $".{GenerateRandomHex(128)}.tmp");

        int escapedCellCount = 0;

        _diagnostics.Publish(new DiagnosticEvent(
            DiagnosticCode.ExportStarted, DateTimeOffset.UtcNow,
            command.ScanId, null,
            new DiagnosticFields
            {
                Stage = "report.export",
                ReasonCode = "started",
                Module = "Infrastructure.Reporting",
                Method = "ExportAsync",
            }));

        try
        {
            // --- 4. Write package ---
            using (var doc = SpreadsheetDocument.Create(tempPath, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = doc.AddWorkbookPart();
                var stylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                WriteStylesheet(stylesPart);

                var sheetParts = new WorksheetPart[6];
                for (int i = 0; i < 6; i++)
                {
                    sheetParts[i] = workbookPart.AddNewPart<WorksheetPart>();
                }

                // Write each sheet
                escapedCellCount += WriteSheet(sheetParts[0], XlsxSheetSchemas.Sheets[0],
                    new[] { WriteScanSummaryRow(summary) });

                escapedCellCount += WriteSheet(sheetParts[1], XlsxSheetSchemas.Sheets[1],
                    sensitive.Select(f => WriteSensitiveFindingRow(f)));

                escapedCellCount += WriteSheet(sheetParts[2], XlsxSheetSchemas.Sheets[2],
                    compliance.Select(f => WriteComplianceFindingRow(f)));

                escapedCellCount += WriteSheet(sheetParts[3], XlsxSheetSchemas.Sheets[3],
                    gaps.Select(g => WriteCoverageGapRow(g)));

                escapedCellCount += WriteSheet(sheetParts[4], XlsxSheetSchemas.Sheets[4],
                    files.Select(f => WriteFileRecordRow(f)));

                escapedCellCount += WriteSheet(sheetParts[5], XlsxSheetSchemas.Sheets[5],
                    reviews.Select(r => WriteReviewRecordRow(r)));

                // Write workbook (sheets element)
                workbookPart.Workbook = new Workbook();
                var sheets = new Sheets();
                for (int i = 0; i < 6; i++)
                {
                    string id = workbookPart.GetIdOfPart(sheetParts[i]);
                    sheets.Append(new Sheet
                    {
                        Name = XlsxSheetSchemas.Sheets[i].Name,
                        SheetId = (uint)(i + 1),
                        Id = id,
                    });
                }

                workbookPart.Workbook.Append(sheets);
                workbookPart.Workbook.Save();
            }

            // --- 5. Validate ---
            XlsxPackageSecurityValidator.Validate(tempPath, rowCounts);

            // --- 6. Hash ---
            string sha256 = ComputeSha256(tempPath);

            // --- 7. Atomic move ---
            try
            {
                File.Move(tempPath, command.TargetPath, overwrite: false);
            }
            catch (IOException) when (File.Exists(command.TargetPath))
            {
                DeleteTempBestEffort(tempPath);
                return ReportExportResult.TargetExists(command.ScanId);
            }

            // --- 8. Audit record ---
            long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            AuditExport(command.ScanId, sha256, nowUnix, rowCounts);

            _diagnostics.Publish(new DiagnosticEvent(
                DiagnosticCode.ExportCompleted, DateTimeOffset.UtcNow,
                command.ScanId, null,
                new DiagnosticFields
                {
                    Stage = "report.export",
                    ReasonCode = "exported",
                    Module = "Infrastructure.Reporting",
                    Method = "ExportAsync",
                }));

            return new ReportExportResult(
                command.ScanId, "exported", sha256, nowUnix, rowCounts);
        }
        catch (XlsxCellLimitExceededException)
        {
            DeleteTempBestEffort(tempPath);
            return ReportExportResult.CellLimitExceeded(command.ScanId);
        }
        catch (Exception) when (!(new FileInfo(tempPath)).Exists == false)
        {
            DeleteTempBestEffort(tempPath);
            throw;
        }
    }

    // ---------------------------------------------------------------
    // Sheet writing
    // ---------------------------------------------------------------

    private static int WriteSheet(
        WorksheetPart part,
        (string Name, string[] Headers) schema,
        IEnumerable<Func<OpenXmlWriter, bool>> rowWriters)
    {
        int escaped = 0;
        using var writer = OpenXmlWriter.Create(part);

        writer.WriteStartElement(new Worksheet());
        writer.WriteStartElement(new SheetData());

        // Header row — style 1 (bold)
        WriteRow(writer, schema.Headers, 1, ref escaped);

        // Data rows — style 0 (default)
        foreach (var rowWriter in rowWriters)
        {
            bool hadEscape = rowWriter(writer);
            if (hadEscape) escaped++;
        }

        writer.WriteEndElement(); // SheetData
        writer.WriteEndElement(); // Worksheet
        writer.Close();

        return escaped;
    }

    private static void WriteRow(
        OpenXmlWriter writer, string[] values, uint styleIndex, ref int escapedCount)
    {
        writer.WriteStartElement(new Row());
        foreach (string value in values)
        {
            bool wasEscaped;
            XlsxCellWriter.WriteTextCellOrThrow(writer, value, out wasEscaped);
            if (wasEscaped) escapedCount++;
        }

        writer.WriteEndElement();
    }

    // ---------------------------------------------------------------
    // Row writers — each returns true if any cell was escaped
    // ---------------------------------------------------------------

    private static Func<OpenXmlWriter, bool> WriteScanSummaryRow(ExportScanSummary s)
    {
        return writer =>
        {
            bool anyEscaped = false;
            WriteValue(writer, s.ScanId, ref anyEscaped);
            WriteValue(writer, s.TaskStatus, ref anyEscaped);
            WriteValue(writer, s.BoundedConclusion, ref anyEscaped);
            WriteValue(writer, s.StartTimeUtc, ref anyEscaped);
            WriteValue(writer, s.EndTimeUtc, ref anyEscaped);
            WriteValue(writer, s.AssetId, ref anyEscaped);
            WriteValue(writer, s.AssetVersion, ref anyEscaped);
            WriteValue(writer, s.InputSummary, ref anyEscaped);
            WriteValue(writer, s.RulePackId, ref anyEscaped);
            WriteValue(writer, s.RulePackVersion, ref anyEscaped);
            WriteValue(writer, s.RulePackSha256, ref anyEscaped);
            WriteValue(writer, s.LocalSupplementSha256, ref anyEscaped);
            WriteValue(writer, s.EffectivePolicySha256, ref anyEscaped);
            WriteValue(writer, s.ClientVersion, ref anyEscaped);
            WriteValue(writer, s.ParserFingerprint, ref anyEscaped);
            WriteValue(writer, s.DetectorFingerprint, ref anyEscaped);
            WriteValue(writer, s.PromptTemplateVersion, ref anyEscaped);
            WriteValue(writer, s.LlmModel, ref anyEscaped);
            WriteValue(writer, s.TotalFiles.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.TotalBytes.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.SensitiveFindingsCount.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.ComplianceFindingsCount.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.UncoveredCount.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.CacheReuseCount.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.ContentEscapedCellCount.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, s.IsLegacyRule ? "true" : "false", ref anyEscaped);
            WriteValue(writer, s.IsLocalSupplement ? "true" : "false", ref anyEscaped);
            return anyEscaped;
        };
    }

    private static Func<OpenXmlWriter, bool> WriteSensitiveFindingRow(ExportSensitiveFinding f)
    {
        return writer =>
        {
            bool anyEscaped = false;
            WriteValue(writer, f.ScanId, ref anyEscaped);
            WriteValue(writer, f.AssetId, ref anyEscaped);
            WriteValue(writer, f.AssetVersion, ref anyEscaped);
            WriteValue(writer, f.FindingGroupId, ref anyEscaped);
            WriteValue(writer, f.FindingOccurrenceId, ref anyEscaped);
            WriteValue(writer, f.DifferenceStatus, ref anyEscaped);
            WriteValue(writer, f.CategoryId, ref anyEscaped);
            WriteValue(writer, f.Category, ref anyEscaped);
            WriteValue(writer, f.Severity, ref anyEscaped);
            WriteValue(writer, f.Confidence, ref anyEscaped);
            WriteValue(writer, f.FullHitValue, ref anyEscaped);
            WriteValue(writer, f.Context, ref anyEscaped);
            WriteValue(writer, f.AssetType, ref anyEscaped);
            WriteValue(writer, f.VirtualPath, ref anyEscaped);
            WriteValue(writer, f.LocatorType, ref anyEscaped);
            WriteValue(writer, f.PreciseLocation, ref anyEscaped);
            WriteValue(writer, f.RuleId, ref anyEscaped);
            WriteValue(writer, f.DetectorId, ref anyEscaped);
            WriteValue(writer, f.RuleVersion, ref anyEscaped);
            WriteValue(writer, f.LlmStatus, ref anyEscaped);
            WriteValue(writer, f.LlmClassification, ref anyEscaped);
            WriteValue(writer, f.LlmConfidence, ref anyEscaped);
            WriteValue(writer, f.LlmReason, ref anyEscaped);
            WriteValue(writer, f.HumanReviewStatus, ref anyEscaped);
            WriteValue(writer, f.ExceptionExpiryUtc, ref anyEscaped);
            return anyEscaped;
        };
    }

    private static Func<OpenXmlWriter, bool> WriteComplianceFindingRow(ExportComplianceFinding f)
    {
        return writer =>
        {
            bool anyEscaped = false;
            WriteValue(writer, f.ScanId, ref anyEscaped);
            WriteValue(writer, f.AssetId, ref anyEscaped);
            WriteValue(writer, f.AssetVersion, ref anyEscaped);
            WriteValue(writer, f.FindingGroupId, ref anyEscaped);
            WriteValue(writer, f.FindingOccurrenceId, ref anyEscaped);
            WriteValue(writer, f.DifferenceStatus, ref anyEscaped);
            WriteValue(writer, f.AssetType, ref anyEscaped);
            WriteValue(writer, f.ComplianceRuleId, ref anyEscaped);
            WriteValue(writer, f.Conclusion, ref anyEscaped);
            WriteValue(writer, f.Severity, ref anyEscaped);
            WriteValue(writer, f.EvidenceStatus, ref anyEscaped);
            WriteValue(writer, f.EvidenceReference, ref anyEscaped);
            WriteValue(writer, f.VirtualPath, ref anyEscaped);
            WriteValue(writer, f.PreciseLocation, ref anyEscaped);
            WriteValue(writer, f.HumanReviewStatus, ref anyEscaped);
            WriteValue(writer, f.HumanReviewReason, ref anyEscaped);
            return anyEscaped;
        };
    }

    private static Func<OpenXmlWriter, bool> WriteCoverageGapRow(ExportCoverageGapRow g)
    {
        return writer =>
        {
            bool anyEscaped = false;
            WriteValue(writer, g.GapId, ref anyEscaped);
            WriteValue(writer, g.Stage, ref anyEscaped);
            WriteValue(writer, g.ReasonCode, ref anyEscaped);
            WriteValue(writer, g.DetailCode, ref anyEscaped);
            WriteValue(writer, g.Format, ref anyEscaped);
            WriteValue(writer, g.VirtualPath, ref anyEscaped);
            WriteValue(writer, g.PlannedBytes.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, g.ProcessedBytes.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, g.ParserId, ref anyEscaped);
            WriteValue(writer, g.ParserVersion, ref anyEscaped);
            WriteValue(writer, g.RecordedAtUtc, ref anyEscaped);
            return anyEscaped;
        };
    }

    private static Func<OpenXmlWriter, bool> WriteFileRecordRow(ExportFileRecordRow f)
    {
        return writer =>
        {
            bool anyEscaped = false;
            WriteValue(writer, f.FileId, ref anyEscaped);
            WriteValue(writer, f.VirtualPath, ref anyEscaped);
            WriteValue(writer, f.DataStream, ref anyEscaped);
            WriteValue(writer, f.AssetType, ref anyEscaped);
            WriteValue(writer, f.Format, ref anyEscaped);
            WriteValue(writer, f.Size.ToString(CultureInfo.InvariantCulture), ref anyEscaped);
            WriteValue(writer, f.ContentSha256, ref anyEscaped);
            WriteValue(writer, f.ParserId, ref anyEscaped);
            WriteValue(writer, f.ParserVersion, ref anyEscaped);
            WriteValue(writer, f.CoverageStatus, ref anyEscaped);
            WriteValue(writer, f.ExtensionMismatch ? "true" : "false", ref anyEscaped);
            WriteValue(writer, f.CacheReuse ? "true" : "false", ref anyEscaped);
            return anyEscaped;
        };
    }

    private static Func<OpenXmlWriter, bool> WriteReviewRecordRow(ExportReviewRecordRow r)
    {
        return writer =>
        {
            bool anyEscaped = false;
            WriteValue(writer, r.DecisionId, ref anyEscaped);
            WriteValue(writer, r.FindingGroupId, ref anyEscaped);
            WriteValue(writer, r.FindingOccurrenceId, ref anyEscaped);
            WriteValue(writer, r.Status, ref anyEscaped);
            WriteValue(writer, r.Operator, ref anyEscaped);
            WriteValue(writer, r.RecordedAtUtc, ref anyEscaped);
            WriteValue(writer, r.Reason, ref anyEscaped);
            WriteValue(writer, r.ExceptionBindingSummary, ref anyEscaped);
            WriteValue(writer, r.ExceptionExpiryUtc, ref anyEscaped);
            return anyEscaped;
        };
    }

    private static void WriteValue(OpenXmlWriter writer, string value, ref bool anyEscaped)
    {
        bool wasEscaped;
        XlsxCellWriter.WriteTextCellOrThrow(writer, value, out wasEscaped);
        if (wasEscaped) anyEscaped = true;
    }

    // ---------------------------------------------------------------
    // Stylesheet
    // ---------------------------------------------------------------

    private static void WriteStylesheet(WorkbookStylesPart stylesPart)
    {
        var stylesheet = new Stylesheet();

        // Fonts: 0=default, 1=bold header
        stylesheet.Fonts = new Fonts(
            new Font(),                                                      // 0: default
            new Font(new Bold())                                            // 1: header bold
        );
        stylesheet.Fonts.Count = 2;

        // Fills: 0=none, 1=gray125 (required by spec)
        stylesheet.Fills = new Fills(
            new Fill(new PatternFill { PatternType = PatternValues.None }),  // 0: none
            new Fill(new PatternFill { PatternType = PatternValues.Gray125 }) // 1: gray125
        );
        stylesheet.Fills.Count = 2;

        // Borders: 0=no border
        stylesheet.Borders = new Borders(new Border());
        stylesheet.Borders.Count = 1;

        // Number formats
        stylesheet.NumberingFormats = new NumberingFormats(
            new NumberingFormat { NumberFormatId = 164, FormatCode = "yyyy-MM-ddTHH:mm:ssZ" } // ISO 8601
        );
        stylesheet.NumberingFormats.Count = 1;

        // Cell formats: 0=default
        stylesheet.CellFormats = new CellFormats(
            new CellFormat(), // 0: default
            new CellFormat { FontId = 1, ApplyFont = true } // 1: header bold
        );
        stylesheet.CellFormats.Count = 2;

        stylesPart.Stylesheet = stylesheet;
        stylesPart.Stylesheet.Save();
    }

    // ---------------------------------------------------------------
    // File helpers
    // ---------------------------------------------------------------

    private static void ValidateExtension(string path)
    {
        if (!path.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Target path must end with .xlsx.", nameof(path));
    }

    private static string GenerateRandomHex(int bits)
    {
        byte[] bytes = new byte[bits / 8];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexStringLower(bytes);
    }

    private static string ComputeSha256(string path)
    {
        byte[] hash = SHA256.HashData(File.ReadAllBytes(path));
        return Convert.ToHexStringLower(hash);
    }

    private static void DeleteTempBestEffort(string path)
    {
        try { File.Delete(path); }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Record audit entry: scan ID, UTC, target SHA-256, row counts, status.
    /// Never logs full target path or cell values.
    /// </summary>
    private static void AuditExport(
        ScanId scanId, string sha256, long unixSeconds,
        Dictionary<string, int> rowCounts)
    {
        // Audit record only — log scan ID, SHA-256, UTC, and row counts.
        // Never log target path or actual values.
        System.Diagnostics.Debug.WriteLine(
            $"XLSX exported: scan={scanId.Value:N}, sha256={sha256}, rows={string.Join(',', rowCounts.Select(kv => $"{kv.Key}={kv.Value}"))}");
    }
}
