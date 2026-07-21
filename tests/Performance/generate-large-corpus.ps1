[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Output,

    [Parameter(Mandatory = $true)]
    [int]$Seed = 20260720,

    [int]$FileCountA = 100000,
    [int]$TotalSizeGiB_A = 10,
    [int]$FileCountD = 50
)

$ErrorActionPreference = "Stop"

# ── Deterministic seeded random ──────────────────────────────────────────
$rng = [System.Random]::new($Seed)

function New-RandomString([int]$Length) {
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    -join (1..$Length | ForEach-Object { $chars[$rng.Next($chars.Length)] })
}

function New-RandomBytes([long]$Count) {
    $buf = [byte[]]::new($Count)
    $rng.NextBytes($buf)
    return $buf
}

# ── Directory setup ──────────────────────────────────────────────────────
$corpusRoot = Resolve-Path $Output -ErrorAction SilentlyContinue
if (-not $corpusRoot) {
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
    $corpusRoot = Resolve-Path $Output
}

$manifestPath = Join-Path $corpusRoot "manifest.json"
$corpusA = Join-Path $corpusRoot "corpus-a"
$corpusD = Join-Path $corpusRoot "corpus-d"

New-Item -ItemType Directory -Path $corpusA -Force | Out-Null
New-Item -ItemType Directory -Path $corpusD -Force | Out-Null

# ── Corpus A: 100k mixed small files totaling ~10 GiB ───────────────────
Write-Host "Generating Corpus A: $FileCountA files, ~$TotalSizeGiB_A GiB ..."

$extensions = @(
    @{ Ext = ".txt";  Weight = 35 },
    @{ Ext = ".json"; Weight = 15 },
    @{ Ext = ".xml";  Weight = 10 },
    @{ Ext = ".yaml"; Weight = 5  },
    @{ Ext = ".csv";  Weight = 5  },
    @{ Ext = ".py";   Weight = 10 },
    @{ Ext = ".java"; Weight = 8  },
    @{ Ext = ".md";   Weight = 5  },
    @{ Ext = ".conf"; Weight = 4  },
    @{ Ext = ".ini";  Weight = 3  }
)

$totalWeight = ($extensions | Measure-Object -Property Weight -Sum).Sum
$avgFileSize = [long]($TotalSizeGiB_A * 1GB / $FileCountA)
$manifestFilesA = @()

# Pre-generate sparse synthetic candidates interspersed throughout
$candidateCount = 1000
$candidatePositions = @{}
for ($i = 0; $i -lt $candidateCount; $i++) {
    $pos = $rng.Next(0, $FileCountA)
    if (-not $candidatePositions.ContainsKey($pos)) {
        $candidatePositions[$pos] = @()
    }
    $candidatePositions[$pos] += @{
        Type = ("password", "api_key", "token", "connection_string", "private_key")[$rng.Next(5)]
        Value = "synth-$($rng.Next(100000, 999999))-candidate-$i"
    }
}

$depthDirs = 4
$filesPerLeaf = [math]::Max(1, [math]::Ceiling($FileCountA / [math]::Pow($depthDirs, 2)))
$leafCount = 0
$leafMax = [math]::Pow($depthDirs, 2)

function New-CorpusATree {
    param([string]$Base, [int]$Depth, [int]$MaxDepth, [ref]$LeafIdx)
    if ($Depth -ge $MaxDepth) { return }
    for ($d = 0; $d -lt $depthDirs; $d++) {
        $sub = Join-Path $Base "dir-$d"
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        if ($Depth -eq $MaxDepth - 1) {
            $globalIdx = $LeafIdx.Value * $filesPerLeaf
            for ($f = 0; $f -lt $filesPerLeaf -and $globalIdx + $f -lt $FileCountA; $f++) {
                $extIdx = $rng.Next(0, $totalWeight)
                $cum = 0
                $picked = $extensions[0]
                foreach ($ext in $extensions) {
                    $cum += $ext.Weight
                    if ($extIdx -lt $cum) { $picked = $ext; break }
                }
                $name = "file-$($globalIdx + $f)$($picked.Ext)"
                $path = Join-Path $sub $name
                $size = [long]($avgFileSize * (0.5 + $rng.NextDouble() * 1.0))
                if ($size -lt 1) { $size = 1 }
                $content = New-RandomBytes $size

                # Inject synthetic candidate if position matches
                if ($candidatePositions.ContainsKey($globalIdx + $f)) {
                    $candidates = $candidatePositions[$globalIdx + $f]
                    $text = [System.Text.Encoding]::UTF8.GetString($content)
                    foreach ($c in $candidates) {
                        $pos = $rng.Next(0, [math]::Max(1, $text.Length - 50))
                        $inject = "`n$($c.Type)=$($c.Value)`n"
                        $text = $text.Substring(0, $pos) + $inject + $text.Substring([math]::Min($pos, $text.Length))
                    }
                    $content = [System.Text.Encoding]::UTF8.GetBytes($text)
                }

                [System.IO.File]::WriteAllBytes($path, $content)
                $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
                $manifestFilesA += @{
                    RelativePath = $path.Substring($corpusRoot.Length + 1).Replace('\', '/')
                    SizeBytes    = $content.Length
                    Sha256       = $hash
                    Candidates   = if ($candidatePositions.ContainsKey($globalIdx + $f)) {
                        $candidatePositions[$globalIdx + $f]
                    } else { @() }
                }
            }
            $LeafIdx.Value++
        } else {
            New-CorpusATree -Base $sub -Depth ($Depth + 1) -MaxDepth $MaxDepth -LeafIdx $LeafIdx
        }
    }
}

$leafIdx = 0
New-CorpusATree -Base $corpusA -Depth 0 -MaxDepth 3 -LeafIdx ([ref]$leafIdx)

$actualFileCountA = (Get-ChildItem -Path $corpusA -File -Recurse).Count
$actualSizeA = (Get-ChildItem -Path $corpusA -File -Recurse | Measure-Object -Property Length -Sum).Sum
Write-Host "  Corpus A complete: $actualFileCountA files, $([math]::Round($actualSizeA / 1GB, 2)) GiB"

# ── Corpus B: 1/5/20 GB streaming files ─────────────────────────────────
Write-Host "Generating Corpus B: 1/5/20 GB streaming files ..."

$corpusB = Join-Path $corpusRoot "corpus-b"
New-Item -ItemType Directory -Path $corpusB -Force | Out-Null

$sizesB = @(1GB, 5GB, 20GB)
$manifestFilesB = @()

foreach ($size in $sizesB) {
    $name = "streaming-$([math]::Round($size / 1GB, 0))gb.bin"
    $path = Join-Path $corpusB $name
    Write-Host "  Writing $name ..."
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $buf = [byte[]]::new(64KB)
    $remaining = [long]$size
    while ($remaining -gt 0) {
        $chunk = [math]::Min($buf.Length, $remaining)
        $rng.NextBytes($buf)
        $fs.Write($buf, 0, $chunk)
        $remaining -= $chunk
    }
    $fs.Close()
    $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
    $manifestFilesB += @{
        RelativePath = $path.Substring($corpusRoot.Length + 1).Replace('\', '/')
        SizeBytes    = $size
        Sha256       = $hash
    }
}

Write-Host "  Corpus B complete: $($sizesB.Count) files"

# ── Corpus C: nested/over-limit/archive bomb metadata ───────────────────
# (Generator creates directory structure metadata only; actual archive bombs
#  are built by the test harness at runtime to avoid committing large files.)
Write-Host "Generating Corpus C: nested/over-limit metadata ..."

$corpusC = Join-Path $corpusRoot "corpus-c"
New-Item -ItemType Directory -Path $corpusC -Force | Out-Null

$nestedSpec = @{
    maxDepth            = 100
    overLimitDirCount   = 5
    archiveBombMetadata = @(
        @{ Name = "zip-bomb-1k";  Layers = 5;  ExpansionFactor = 1000 },
        @{ Name = "tar-bomb";     Layers = 3;  ExpansionFactor = 500  }
    )
    symlinkLoops        = 3
    invalidEncodings    = 2
}

$manifestFilesC = @()
$nestRoot = Join-Path $corpusC "deep-nest"
$current = $nestRoot
New-Item -ItemType Directory -Path $current -Force | Out-Null
for ($d = 0; $d -lt $nestedSpec.maxDepth; $d++) {
    $current = Join-Path $current "level-$d"
    New-Item -ItemType Directory -Path $current -Force | Out-Null
}
# Place a trigger file at max depth
$deepFile = Join-Path $current "deep-trigger.txt"
"max-depth-reached" | Out-File -FilePath $deepFile -Encoding utf8
$manifestFilesC += @{
    RelativePath = $deepFile.Substring($corpusRoot.Length + 1).Replace('\', '/')
    Metadata     = @{ type = "deep-nest-trigger"; depth = $nestedSpec.maxDepth }
}

# Over-limit directories
$overLimitRoot = Join-Path $corpusC "over-limit"
New-Item -ItemType Directory -Path $overLimitRoot -Force | Out-Null
for ($o = 0; $o -lt $nestedSpec.overLimitDirCount; $o++) {
    $odir = Join-Path $overLimitRoot "overlimit-dir-$o"
    New-Item -ItemType Directory -Path $odir -Force | Out-Null
    # Create many small files that would exceed typical scan limits
    for ($f = 0; $f -lt 5000; $f++) {
        "overlimit-data" | Out-File -FilePath (Join-Path $odir "file-$f.txt") -Encoding utf8
    }
}

$manifestFilesC += @{
    RelativePath = $overLimitRoot.Substring($corpusRoot.Length + 1).Replace('\', '/')
    Metadata     = @{ type = "over-limit-dirs"; dirCount = $nestedSpec.overLimitDirCount; filesPerDir = 5000 }
}

# Archive bomb metadata records
foreach ($bomb in $nestedSpec.archiveBombMetadata) {
    $bombDir = Join-Path $corpusC "bomb-$($bomb.Name)"
    New-Item -ItemType Directory -Path $bombDir -Force | Out-Null
    $specPath = Join-Path $bombDir "bomb-spec.json"
    $bomb | ConvertTo-Json -Depth 5 | Out-File -FilePath $specPath -Encoding utf8
    $manifestFilesC += @{
        RelativePath = $specPath.Substring($corpusRoot.Length + 1).Replace('\', '/')
        Metadata     = @{ type = "archive-bomb-spec"; name = $bomb.Name }
    }
}

Write-Host "  Corpus C complete: $($manifestFilesC.Count) metadata entries"

# ── Corpus D: worker crash/hang/OOM/corrupt cases ────────────────────────
Write-Host "Generating Corpus D: crash/hang/OOM/corrupt cases ..."

$faultTypes = @(
    @{ Name = "crash-null-ref";          Method = "crash";   Extension = ".txt"  },
    @{ Name = "crash-stack-overflow";     Method = "crash";   Extension = ".json" },
    @{ Name = "crash-access-violation";   Method = "crash";   Extension = ".xml"  },
    @{ Name = "hang-infinite-loop";       Method = "hang";    Extension = ".py"   },
    @{ Name = "hang-deadlock-trigger";    Method = "hang";    Extension = ".java" },
    @{ Name = "oom-large-allocation";     Method = "oom";     Extension = ".csv"  },
    @{ Name = "oom-memory-leak-pattern";  Method = "oom";     Extension = ".yaml" },
    @{ Name = "corrupt-invalid-utf8";     Method = "corrupt"; Extension = ".txt"  },
    @{ Name = "corrupt-truncated-zip";    Method = "corrupt"; Extension = ".zip"  },
    @{ Name = "corrupt-broken-xml";       Method = "corrupt"; Extension = ".xml"  }
)

$manifestFilesD = @()
for ($i = 0; $i -lt $FileCountD; $i++) {
    $ft = $faultTypes[$i % $faultTypes.Length]
    $name = "fault-$($i.ToString('D3'))-$($ft.Name)$($ft.Extension)"
    $path = Join-Path $corpusD $name

    switch ($ft.Method) {
        "crash" {
            # Mark file with magic bytes that the test harness recognizes
            $magic = [System.Text.Encoding]::UTF8.GetBytes("SRT-FAULT-CRASH`n")
            $payload = New-RandomBytes 1024
            [System.IO.File]::WriteAllBytes($path, $magic + $payload)
        }
        "hang" {
            $magic = [System.Text.Encoding]::UTF8.GetBytes("SRT-FAULT-HANG`n")
            $payload = New-RandomBytes 1024
            [System.IO.File]::WriteAllBytes($path, $magic + $payload)
        }
        "oom" {
            $magic = [System.Text.Encoding]::UTF8.GetBytes("SRT-FAULT-OOM`n")
            $payload = New-RandomBytes 1024
            [System.IO.File]::WriteAllBytes($path, $magic + $payload)
        }
        "corrupt" {
            if ($ft.Extension -eq ".zip") {
                # Truncated zip: valid local header but truncated data
                $header = [byte[]]@(0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
                [System.IO.File]::WriteAllBytes($path, $header)
            } elseif ($ft.Extension -eq ".xml") {
                "<broken><unclosed>" | Out-File -FilePath $path -Encoding utf8
            } else {
                # Invalid UTF-8 bytes
                $badBytes = [byte[]]@(0xFF, 0xFE, 0x00, 0x00, 0xC0, 0xC1, 0xF5, 0xF6)
                [System.IO.File]::WriteAllBytes($path, $badBytes)
            }
        }
    }

    $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
    $manifestFilesD += @{
        RelativePath = $path.Substring($corpusRoot.Length + 1).Replace('\', '/')
        SizeBytes    = (Get-Item $path).Length
        Sha256       = $hash
        FaultType    = $ft.Method
        FaultName    = $ft.Name
    }
}

Write-Host "  Corpus D complete: $FileCountD files"

# ── Manifest ────────────────────────────────────────────────────────────
$manifest = @{
    SchemaVersion = 1
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    Seed           = $Seed
    GeneratorVersion = "P6-T4-1.0"
    Corpora = @{
        A = @{
            Description    = "100k mixed small files, ~10 GiB total, sparse synthetic candidates"
            RootPath       = "corpus-a"
            ExpectedFiles  = $actualFileCountA
            ExpectedSizeBytes = $actualSizeA
            CandidateCount = $candidateCount
            Files          = $manifestFilesA
        }
        B = @{
            Description   = "1/5/20 GB streaming files for memory growth measurement"
            RootPath      = "corpus-b"
            Files         = $manifestFilesB
        }
        C = @{
            Description   = "Nested/over-limit/archive bomb metadata"
            RootPath      = "corpus-c"
            Spec          = $nestedSpec
            Files         = $manifestFilesC
        }
        D = @{
            Description   = "Worker crash/hang/OOM/corrupt fault injection corpus"
            RootPath      = "corpus-d"
            ExpectedFiles = $FileCountD
            Files         = $manifestFilesD
        }
    }
}

$manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestPath -Encoding utf8

# Compute overall manifest hash
$manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash

Write-Host ""
Write-Host "=== Corpus Generation Complete ==="
Write-Host "Output   : $corpusRoot"
Write-Host "Seed     : $Seed"
Write-Host "Manifest : $manifestPath"
Write-Host "Manifest SHA-256: $manifestHash"
Write-Host "Corpus A : $actualFileCountA files, $([math]::Round($actualSizeA / 1GB, 2)) GiB"
Write-Host "Corpus B : 3 files ($( ($sizesB | ForEach-Object { "$([math]::Round($_/1GB,0))GB" }) -join ', ' ))"
Write-Host "Corpus C : $($manifestFilesC.Count) metadata entries"
Write-Host "Corpus D : $FileCountD fault-injection files"
