<#
.SYNOPSIS
Generates test xlsx workbooks for RuleWorkbookReader contract tests.
#>

param(
    [string]$OutputDir = "$PSScriptRoot"
)

$ErrorActionPreference = 'Stop'

# Ensure NuGet packages are available
$packagesDir = "$env:USERPROFILE\.nuget\packages\documentformat.openxml\3.5.1\lib\net10.0"
if (-not (Test-Path $packagesDir\DocumentFormat.OpenXml.dll)) {
    # Try to restore
    dotnet restore (Join-Path $PSScriptRoot "..\..\..\..\SecurityReviewTool.sln") | Out-Null
}

# Load OpenXml
Add-Type -Path "$packagesDir\DocumentFormat.OpenXml.dll"
Add-Type -Path "$packagesDir\DocumentFormat.OpenXml.Framework.dll"

function New-Workbook {
    param([string]$FileName, [scriptblock]$AddSheets)

    $path = Join-Path $OutputDir $FileName
    $doc = [DocumentFormat.OpenXml.Packaging.SpreadsheetDocument]::Create($path,
        [DocumentFormat.OpenXml.SpreadsheetDocumentType]::Workbook)
    $wbPart = $doc.AddWorkbookPart()
    $wbPart.Workbook = [DocumentFormat.OpenXml.Spreadsheet.Workbook]::new()
    $sheets = $wbPart.Workbook.AppendChild([DocumentFormat.OpenXml.Spreadsheet.Sheets]::new())

    & $AddSheets $doc $wbPart $sheets

    $wbPart.Workbook.Save()
    $doc.Dispose()

    Write-Host "Generated: $path"
}

function Add-Sheet {
    param($wbPart, $sheets, $name, $rows)

    $part = $wbPart.AddNewPart([DocumentFormat.OpenXml.Packaging.WorksheetPart])
    $sheetData = [DocumentFormat.OpenXml.Spreadsheet.SheetData]::new()
    for ($r = 0; $r -lt $rows.Count; $r++) {
        $row = [DocumentFormat.OpenXml.Spreadsheet.Row]::new()
        $row.RowIndex = $r + 1
        for ($c = 0; $c -lt $rows[$r].Count; $c++) {
            $cell = [DocumentFormat.OpenXml.Spreadsheet.Cell]::new()
            $cell.DataType = [DocumentFormat.OpenXml.Spreadsheet.CellValues]::InlineString
            $col = [char](65 + $c)
            $cell.CellReference = "$col$($r + 1)"
            $inlineStr = [DocumentFormat.OpenXml.Spreadsheet.InlineString]::new()
            $inlineStr.AppendChild([DocumentFormat.OpenXml.Spreadsheet.Text]::new($rows[$r][$c]))
            $cell.AppendChild($inlineStr)
            $row.AppendChild($cell)
        }
        $sheetData.AppendChild($row)
    }
    $part.Worksheet = [DocumentFormat.OpenXml.Spreadsheet.Worksheet]::new($sheetData)

    $sheet = [DocumentFormat.OpenXml.Spreadsheet.Sheet]::new()
    $sheet.Name = $name
    $sheet.SheetId = $sheets.Count() + 1
    $sheet.Id = $wbPart.GetIdOfPart($part)
    $sheets.AppendChild($sheet)
}

# ── valid_minimal.xlsx ──────────────────────────────────
New-Workbook "valid_minimal.xlsx" {
    param($doc, $wbPart, $sheets)

    Add-Sheet $wbPart $sheets "规则包信息" @(
        @("键", "值"),
        @("rulePackId", "test-pack"),
        @("version", "1.0.0"),
        @("schemaVersion", "1"),
        @("minClientVersion", "1.0.0"),
        @("createdAtUtc", "2025-01-01T00:00:00Z"),
        @("signerKeyId", "rules-team-prod-01"),
        @("changeSummary", "initial")
    )

    Add-Sheet $wbPart $sheets "敏感类别" @(
        @("类别ID", "名称", "说明", "默认严重度", "启用"),
        @("SENS-001", "凭据和密钥", "API密钥、密码、令牌", "Critical", "TRUE")
    )

    Add-Sheet $wbPart $sheets "资产专项规则" @(
        @("规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"),
        @("RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "测试规则")
    )

    Add-Sheet $wbPart $sheets "受限实体词典" @(
        @("词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束"),
        @("dict-1", "ent-1", "test", "tst", "SENS-001", "High", "ASSET-001", "2025-01-01", "2025-12-31")
    )

    Add-Sheet $wbPart $sheets "安全占位符" @(
        @("占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束"),
        @("ph-1", "regex", "test_pattern", "default", "SENS-001", "2025-01-01", "2025-12-31")
    )

    Add-Sheet $wbPart $sheets "检测器配置" @(
        @("检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"),
        @("DET-TEST-001", "KnownFormat", "default", '{ }', "100")
    )

    Add-Sheet $wbPart $sheets "第三方授权" @(
        @("授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束"),
        @("lic-1", "test-lib", "abc123", "MIT", "https://example.com", "2025-01-01", "2025-12-31")
    )

    Add-Sheet $wbPart $sheets "合规规则" @(
        @("规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明"),
        @("COMP-001", "ASSET-001", "evidence.json", "present", "High", "合规测试")
    )
}

# ── missing_sheet.xlsx: missing 敏感类别 sheet ─────────
New-Workbook "missing_sheet.xlsx" {
    param($doc, $wbPart, $sheets)

    Add-Sheet $wbPart $sheets "规则包信息" @(
        @("键", "值"),
        @("rulePackId", "test-pack")
    )

    Add-Sheet $wbPart $sheets "资产专项规则" @(
        @("规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"),
        @("RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "")
    )

    Add-Sheet $wbPart $sheets "受限实体词典" @(
        @("词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "安全占位符" @(
        @("占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "检测器配置" @(
        @("检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"),
        @("DET-TEST-001", "KnownFormat", "default", '{ }', "100")
    )

    Add-Sheet $wbPart $sheets "第三方授权" @(
        @("授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "合规规则" @(
        @("规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明")
    )
}

# ── formula.xlsx: formula in a cell ────────────────────
New-Workbook "formula.xlsx" {
    param($doc, $wbPart, $sheets)

    Add-Sheet $wbPart $sheets "规则包信息" @(
        @("键", "值"),
        @("rulePackId", "test-pack")
    )

    Add-Sheet $wbPart $sheets "敏感类别" @(
        @("类别ID", "名称", "说明", "默认严重度", "启用"),
        @("SENS-001", "凭据", "desc", "Critical", "TRUE")
    )

    Add-Sheet $wbPart $sheets "资产专项规则" @(
        @("规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"),
        @("RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "")
    )

    Add-Sheet $wbPart $sheets "受限实体词典" @(
        @("词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "安全占位符" @(
        @("占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束")
    )

    # Detection config with formula in JSON column
    $part = $wbPart.AddNewPart([DocumentFormat.OpenXml.Packaging.WorksheetPart])
    $sheetData = [DocumentFormat.OpenXml.Spreadsheet.SheetData]::new()

    # Header
    $headerRow = [DocumentFormat.OpenXml.Spreadsheet.Row]::new()
    $headerRow.RowIndex = 1
    $headers = @("检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数")
    for ($c = 0; $c -lt $headers.Count; $c++) {
        $cell = [DocumentFormat.OpenXml.Spreadsheet.Cell]::new()
        $cell.DataType = [DocumentFormat.OpenXml.Spreadsheet.CellValues]::InlineString
        $col = [char](65 + $c)
        $cell.CellReference = "$col`1"
        $inlineStr = [DocumentFormat.OpenXml.Spreadsheet.InlineString]::new()
        $inlineStr.AppendChild([DocumentFormat.OpenXml.Spreadsheet.Text]::new($headers[$c]))
        $cell.AppendChild($inlineStr)
        $headerRow.AppendChild($cell)
    }
    $sheetData.AppendChild($headerRow)

    # Data with formula
    $dataRow = [DocumentFormat.OpenXml.Spreadsheet.Row]::new()
    $dataRow.RowIndex = 2
    $values = @("DET-TEST-001", "KnownFormat", "default", "", "100")
    for ($c = 0; $c -lt $values.Count; $c++) {
        $cell = [DocumentFormat.OpenXml.Spreadsheet.Cell]::new()
        $col = [char](65 + $c)
        $cell.CellReference = "$col`2"
        if ($c -eq 3) {
            # Formula cell
            $cell.CellFormula = [DocumentFormat.OpenXml.Spreadsheet.CellFormula]::new("1+1")
        } else {
            $cell.DataType = [DocumentFormat.OpenXml.Spreadsheet.CellValues]::InlineString
            $inlineStr = [DocumentFormat.OpenXml.Spreadsheet.InlineString]::new()
            $inlineStr.AppendChild([DocumentFormat.OpenXml.Spreadsheet.Text]::new($values[$c]))
            $cell.AppendChild($inlineStr)
        }
        $dataRow.AppendChild($cell)
    }
    $sheetData.AppendChild($dataRow)

    $part.Worksheet = [DocumentFormat.OpenXml.Spreadsheet.Worksheet]::new($sheetData)
    $sheet = [DocumentFormat.OpenXml.Spreadsheet.Sheet]::new()
    $sheet.Name = "检测器配置"
    $sheet.SheetId = $sheets.Count() + 1
    $sheet.Id = $wbPart.GetIdOfPart($part)
    $sheets.AppendChild($sheet)

    Add-Sheet $wbPart $sheets "第三方授权" @(
        @("授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "合规规则" @(
        @("规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明")
    )
}

# ── invalid_json.xlsx: invalid JSON in parameters ──────
New-Workbook "invalid_json.xlsx" {
    param($doc, $wbPart, $sheets)

    Add-Sheet $wbPart $sheets "规则包信息" @(
        @("键", "值"),
        @("rulePackId", "test-pack"),
        @("version", "1.0.0"),
        @("minClientVersion", "1.0.0")
    )

    Add-Sheet $wbPart $sheets "敏感类别" @(
        @("类别ID", "名称", "说明", "默认严重度", "启用"),
        @("SENS-001", "凭据", "desc", "Critical", "TRUE")
    )

    Add-Sheet $wbPart $sheets "资产专项规则" @(
        @("规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"),
        @("RULE-TEST-001", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "")
    )

    Add-Sheet $wbPart $sheets "受限实体词典" @(
        @("词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "安全占位符" @(
        @("占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "检测器配置" @(
        @("检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"),
        @("DET-TEST-001", "KnownFormat", "default", "{this is not json}", "100")
    )

    Add-Sheet $wbPart $sheets "第三方授权" @(
        @("授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "合规规则" @(
        @("规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明")
    )
}

# ── duplicate_rule_id.xlsx: duplicate RuleId ───────────
New-Workbook "duplicate_rule_id.xlsx" {
    param($doc, $wbPart, $sheets)

    Add-Sheet $wbPart $sheets "规则包信息" @(
        @("键", "值"),
        @("rulePackId", "test-pack"),
        @("version", "1.0.0"),
        @("minClientVersion", "1.0.0")
    )

    Add-Sheet $wbPart $sheets "敏感类别" @(
        @("类别ID", "名称", "说明", "默认严重度", "启用"),
        @("SENS-001", "凭据", "desc", "Critical", "TRUE")
    )

    Add-Sheet $wbPart $sheets "资产专项规则" @(
        @("规则ID", "资产ID", "类别ID", "发现类型", "检测器ID", "配置ID", "严重度", "置信度", "需要语义复核", "启用", "说明"),
        @("RULE-DUP", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "first"),
        @("RULE-DUP", "ASSET-001", "SENS-001", "SensitiveContent", "DET-TEST-001", "default", "High", "High", "FALSE", "TRUE", "second")
    )

    Add-Sheet $wbPart $sheets "受限实体词典" @(
        @("词典ID", "实体ID", "标准名称", "变体", "类别ID", "严重度", "资产范围", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "安全占位符" @(
        @("占位符ID", "匹配类型", "值", "允许上下文", "类别ID", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "检测器配置" @(
        @("检测器ID", "类型", "配置ID", "参数JSON", "最大每块命中数"),
        @("DET-TEST-001", "KnownFormat", "default", '{ }', "100")
    )

    Add-Sheet $wbPart $sheets "第三方授权" @(
        @("授权ID", "来源名称", "标识或指纹", "许可说明", "证据引用", "有效起始", "有效结束")
    )

    Add-Sheet $wbPart $sheets "合规规则" @(
        @("规则ID", "资产ID", "证据字段", "缺失结论", "严重度", "说明")
    )
}

Write-Host "`nDone! Generated 5 test workbooks in $OutputDir"
