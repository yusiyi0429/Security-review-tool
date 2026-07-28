[CmdletBinding()]
param(
  [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$sourceRoots = @(
  (Join-Path $repositoryRoot "src"),
  (Join-Path $repositoryRoot "tools")
)
$projectFiles = @(
  Get-ChildItem -LiteralPath $sourceRoots -Filter "*.csproj" -File -Recurse |
    Sort-Object -Property FullName
)
if ($projectFiles.Count -eq 0) {
  throw "No project files were found under src or tools."
}

function Get-RepositoryRelativePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  return [System.IO.Path]::GetRelativePath($repositoryRoot, $Path).Replace("\", "/")
}

function Get-ProjectCategory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RelativePath
  )

  if ($RelativePath.StartsWith("src/", [System.StringComparison]::Ordinal)) {
    return "source"
  }

  if ($RelativePath.StartsWith("tools/", [System.StringComparison]::Ordinal)) {
    return "tool"
  }

  throw "Unsupported project location: $RelativePath"
}

function ConvertTo-Lf {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Content
  )

  return $Content.Replace("`r`n", "`n")
}

$projects = @(
  foreach ($projectFile in $projectFiles) {
    $relativePath = Get-RepositoryRelativePath -Path $projectFile.FullName
    [pscustomobject]@{
      Name = [System.IO.Path]::GetFileNameWithoutExtension($projectFile.Name)
      RelativePath = $relativePath
      FullPath = [System.IO.Path]::GetFullPath($projectFile.FullName)
      Category = Get-ProjectCategory -RelativePath $relativePath
      SourceFileCount = @(
        Get-ChildItem -LiteralPath $projectFile.DirectoryName -Filter "*.cs" -File -Recurse |
          Where-Object { $_.FullName -notmatch "[\\/](bin|obj)[\\/]" }
      ).Count
      References = [string[]]@()
    }
  }
)

$projectsByPath = @{}
foreach ($project in $projects) {
  if ($projectsByPath.ContainsKey($project.FullPath)) {
    throw "Duplicate project path in code graph: $($project.FullPath)"
  }
  $projectsByPath[$project.FullPath] = $project
}

foreach ($project in $projects) {
  [xml]$projectXml = Get-Content -LiteralPath $project.FullPath -Raw
  $references = [System.Collections.Generic.List[string]]::new()

  foreach ($referenceNode in $projectXml.SelectNodes("//*[local-name()='ProjectReference']")) {
    $includeAttribute = $referenceNode.Attributes.GetNamedItem("Include")
    if ($null -eq $includeAttribute) {
      throw "Project reference without Include in $($project.RelativePath)"
    }

    $referenceInclude = $includeAttribute.Value.Replace("\", [System.IO.Path]::DirectorySeparatorChar).Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $referencePath = [System.IO.Path]::GetFullPath(
      [System.IO.Path]::Combine(
        (Split-Path -Parent $project.FullPath),
        $referenceInclude
      )
    )
    if (-not $projectsByPath.ContainsKey($referencePath)) {
      throw "Project reference is outside the code graph scope: $($project.RelativePath) -> $($includeAttribute.Value)"
    }

    $references.Add($projectsByPath[$referencePath].Name)
  }

  $project.References = @($references | Sort-Object -Unique)
}

$nodeIds = @{}
for ($index = 0; $index -lt $projects.Count; $index++) {
  $nodeIds[$projects[$index].Name] = "P$index"
}

$categoryDefinitions = @(
  [pscustomobject]@{ Key = "source"; Id = "source"; Label = "应用与核心组件（src）"; ClassName = "sourceNode" },
  [pscustomobject]@{ Key = "tool"; Id = "tool"; Label = "开发工具（tools）"; ClassName = "toolNode" }
)
$mermaidLines = [System.Collections.Generic.List[string]]::new()
$mermaidLines.Add("flowchart LR")
foreach ($category in $categoryDefinitions) {
  $categoryProjects = @($projects | Where-Object { $_.Category -eq $category.Key })
  if ($categoryProjects.Count -eq 0) {
    continue
  }

  $mermaidLines.Add("  subgraph $($category.Id)[`"$($category.Label)`"]")
  foreach ($project in $categoryProjects) {
    $mermaidLines.Add(
      "    $($nodeIds[$project.Name])[`"$($project.Name)<br/>$($project.SourceFileCount) C# files`"]"
    )
  }
  $mermaidLines.Add("  end")
}

foreach ($project in $projects) {
  foreach ($reference in $project.References) {
    $mermaidLines.Add("  $($nodeIds[$project.Name]) --> $($nodeIds[$reference])")
  }
}

foreach ($category in $categoryDefinitions) {
  $categoryNodeIds = @(
    $projects |
      Where-Object { $_.Category -eq $category.Key } |
      ForEach-Object { $nodeIds[$_.Name] }
  )
  if ($categoryNodeIds.Count -gt 0) {
    $mermaidLines.Add("  class $($categoryNodeIds -join ',') $($category.ClassName)")
  }
}
$mermaidLines.Add("  classDef sourceNode fill:#dbeafe,stroke:#2563eb,color:#172554")
$mermaidLines.Add("  classDef toolNode fill:#dcfce7,stroke:#16a34a,color:#14532d")

$markdownLines = [System.Collections.Generic.List[string]]::new()
$markdownLines.Add("# Code Graph")
$markdownLines.Add("")
$markdownLines.Add('> 此文件由 `build/update-code-graph.ps1` 生成；请勿手工修改。')
$markdownLines.Add("")
$markdownLines.Add('本图覆盖 `src/` 与 `tools/` 中的项目。箭头 `A --> B` 表示项目 A 直接引用项目 B；测试项目未纳入，以保持运行时代码的依赖关系清晰。')
$markdownLines.Add("")
$markdownLines.Add('更新：`pwsh ./build/update-code-graph.ps1`。验证生成文件没有过期：`pwsh ./build/update-code-graph.ps1 -Check`。')
$markdownLines.Add("")
$markdownLines.Add('```mermaid')
foreach ($line in $mermaidLines) {
  $markdownLines.Add($line)
}
$markdownLines.Add('```')
$markdownLines.Add("")
$markdownLines.Add("## 项目清单")
$markdownLines.Add("")
$markdownLines.Add("| 项目 | 路径 | C# 文件 | 直接依赖 |")
$markdownLines.Add("| --- | --- | ---: | --- |")
foreach ($project in $projects) {
  $dependencies = if ($project.References.Count -eq 0) { "—" } else { $project.References -join ", " }
  $markdownLines.Add(
    "| $($project.Name) | ``$($project.RelativePath)`` | $($project.SourceFileCount) | $dependencies |"
  )
}

$nodes = @(
  foreach ($project in $projects) {
    [ordered]@{
      id = $project.Name
      category = $project.Category
      projectFile = $project.RelativePath
      sourceFileCount = $project.SourceFileCount
    }
  }
)
$edges = @(
  foreach ($project in $projects) {
    foreach ($reference in $project.References) {
      [ordered]@{
        from = $project.Name
        to = $reference
        kind = "ProjectReference"
      }
    }
  }
)
$graph = [ordered]@{
  schemaVersion = 1
  scope = @("src", "tools")
  nodes = $nodes
  edges = $edges
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$outputs = @(
  [pscustomobject]@{
    Path = Join-Path $repositoryRoot "docs/architecture/code-graph.md"
    Content = (($markdownLines -join "`n") + "`n")
  },
  [pscustomobject]@{
    Path = Join-Path $repositoryRoot "docs/architecture/code-graph.json"
    Content = ConvertTo-Lf -Content (($graph | ConvertTo-Json -Depth 4) + "`n")
  }
)

$outOfDateFiles = [System.Collections.Generic.List[string]]::new()
foreach ($output in $outputs) {
  if ($Check) {
    if (-not (Test-Path -LiteralPath $output.Path -PathType Leaf)) {
      $outOfDateFiles.Add((Get-RepositoryRelativePath -Path $output.Path))
      continue
    }

    $actualContent = ConvertTo-Lf -Content ([System.IO.File]::ReadAllText($output.Path))
    if ($actualContent -cne $output.Content) {
      $outOfDateFiles.Add((Get-RepositoryRelativePath -Path $output.Path))
    }
    continue
  }

  $outputDirectory = Split-Path -Parent $output.Path
  if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
  }
  [System.IO.File]::WriteAllText($output.Path, $output.Content, $utf8NoBom)
}

if ($outOfDateFiles.Count -gt 0) {
  throw "Code graph is out of date: $($outOfDateFiles -join ', '). Run 'pwsh ./build/update-code-graph.ps1' and commit the generated files."
}

if ($Check) {
  Write-Host "Code graph is current."
} else {
  Write-Host "Code graph updated."
}
