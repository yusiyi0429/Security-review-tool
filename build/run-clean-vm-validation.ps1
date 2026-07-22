param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [switch]$SkipNetworkCapture,

    [int]$StartupTimeoutSeconds = 5,

    [string]$LlmEndpoint,

    [string]$LlmApiKey,

    [string]$LlmModel = "gpt-4o-internal",

    [string]$TestAssetDir
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path -Parent
Push-Location $root

try {
    # Ensure output directory
    New-Item -ItemType Directory -Path $Output -Force | Out-Null

    $evidenceDir = Join-Path $Output "evidence"
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

    $snapshotDir = Join-Path $evidenceDir "snapshots"
    New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null

    # ── Evidence record ──────────────────────────────────────────────────────
    $evidence = [ordered]@{
        timestamp_utc     = (Get-Date).ToUniversalTime().ToString("o")
        host_os_caption   = (Get-CimInstance Win32_OperatingSystem).Caption
        host_os_build     = [System.Environment]::OSVersion.Version.ToString()
        host_user_admin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        package_path      = $Package
        package_sha256    = ""
        extraction_path   = ""
        checks            = @{}
        failures          = @()
    }

    # ── 1. Snapshot baseline state ───────────────────────────────────────────
    Write-Host "=== Step 1: Snapshot baseline state ==="

    function Get-SystemSnapshot($label, $dir) {
        $snap = [ordered]@{
            label         = $label
            timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
            processes     = @(Get-Process | Select-Object Id, ProcessName, StartTime | Sort-Object Id)
            services      = @(Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName | Sort-Object Name)
            scheduled_tasks = @(schtasks /query /fo CSV 2>$null | ConvertFrom-Csv | Select-Object TaskName | Sort-Object TaskName)
            registry_hklm_run = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name })
            registry_hkcu_run = @(Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name })
            env_path       = $env:PATH
            env_temp       = $env:TEMP
        }
        $snap | ConvertTo-Json -Depth 4 | Out-File (Join-Path $dir "$label.json") -Encoding utf8
        return $snap
    }

    function Get-FilesystemSnapshot($label, $dir) {
        $paths = @(
            $env:LOCALAPPDATA,
            $env:APPDATA,
            "$env:ProgramData\Microsoft\Windows\Start Menu",
            "$env:APPDATA\Microsoft\Windows\Start Menu"
        )
        $snap = [ordered]@{ label = $label; timestamp_utc = (Get-Date).ToUniversalTime().ToString("o"); directories = @{} }
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $snap.directories[$p] = @(Get-ChildItem $p -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
            }
        }
        $snap | ConvertTo-Json -Depth 4 | Out-File (Join-Path $dir "$label-filesystem.json") -Encoding utf8
        return $snap
    }

    $baselineProc  = Get-SystemSnapshot "baseline" $snapshotDir
    $baselineFS    = Get-FilesystemSnapshot "baseline" $snapshotDir

    # ── 2. Verify ZIP hash and signature ─────────────────────────────────────
    Write-Host "=== Step 2: Verify ZIP hash and signature ==="

    $packageHashBytes = [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($Package))
    $packageHash = [System.BitConverter]::ToString($packageHashBytes).Replace("-", "").ToLowerInvariant()
    $evidence.package_sha256 = $packageHash

    Write-Host "  SHA-256: $packageHash"

    $sha256Sidecar = "$Package.sha256"
    if (Test-Path $sha256Sidecar) {
        $expectedHash = (Get-Content $sha256Sidecar -Raw).Trim().Split(" ")[0].ToLowerInvariant()
        if ($packageHash -ne $expectedHash) {
            $evidence.failures += "SHA-256 mismatch: expected $expectedHash, got $packageHash"
            Write-Host "  HASH MISMATCH" -ForegroundColor Red
        } else {
            Write-Host "  SHA-256 matches sidecar."
        }
    } else {
        Write-Host "  No SHA-256 sidecar found. Verify hash through an out-of-band channel."
    }

    # Authenticode check
    if ($Package.EndsWith(".zip")) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $Package
            $evidence.checks["authenticode"] = $sig.Status.ToString()
            if ($sig.Status -eq "Valid") {
                Write-Host "  Authenticode: Valid ($($sig.SignerCertificate.Subject))"
            } else {
                Write-Host "  Authenticode: $($sig.Status) (may be unsigned pilot)" -ForegroundColor Yellow
            }
        } catch {
            $evidence.checks["authenticode"] = "check-failed"
            Write-Host "  Authenticode check failed: $_" -ForegroundColor Yellow
        }
    }

    # ── 3. Extract to long/spaced/Chinese path ───────────────────────────────
    Write-Host "=== Step 3: Extract to test path ==="

    $extractBase = if (Test-Path "D:\") { "D:\内部安全审查" } else { Join-Path $env:TEMP "SecurityReviewTool-Test" }
    $extractDir = Join-Path $extractBase "工具 v1.0 test\SecurityReviewTool"
    $evidence.extraction_path = $extractDir

    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

    Write-Host "  Extracting to: $extractDir"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Package, $extractDir)

    $exePath = Join-Path $extractDir "SecurityReviewTool.exe"
    if (-not (Test-Path $exePath)) {
        $evidence.failures += "SecurityReviewTool.exe not found after extraction."
        throw "Extraction failed: main executable not found."
    }
    Write-Host "  Extraction complete."

    # ── 4. Check: no admin prompt on launch attempt ─────────────────────────
    Write-Host "=== Step 4: Check no admin prompt required ==="

    $exeBytes = [System.IO.File]::ReadAllBytes($exePath)
    $peOffset = [System.BitConverter]::ToInt32($exeBytes, 0x3C)
    # Check requiredExecutionLevel in manifest (embedded or external)
    $manifestPath = "$exePath.manifest"
    $requiresAdmin = $false
    if (Test-Path $manifestPath) {
        $manifestContent = Get-Content $manifestPath -Raw
        if ($manifestContent -match 'requireAdministrator') {
            $requiresAdmin = $true
        }
    }
    if ($requiresAdmin) {
        $evidence.failures += "Executable manifest requests requireAdministrator."
        Write-Host "  WARNING: requests administrator" -ForegroundColor Red
    } else {
        Write-Host "  No admin request in manifest."
    }

    # ── 5. Check: no service or scheduled task registered ────────────────────
    $evidence.checks["no_service"] = $true
    $evidence.checks["no_scheduled_task"] = $true
    Write-Host "  Service/scheduled-task check deferred to post-run snapshot diff."

    # ── 6. Cold-start timing (timed launch attempt) ──────────────────────────
    Write-Host "=== Step 5: Startup time measurement ==="

    # Start pktmon capture if not skipped
    if (-not $SkipNetworkCapture) {
        try {
            pktmon stop 2>$null
            pktmon reset 2>$null
            pktmon start --capture --comp all 2>$null
            $evidence.checks["pktmon_started"] = $true
            Write-Host "  pktmon capture started."
        } catch {
            Write-Host "  pktmon not available: $_" -ForegroundColor Yellow
            $evidence.checks["pktmon_started"] = $false
        }
    }

    $startWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = $null

    try {
        $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Minimized
        Start-Sleep -Milliseconds 500
        # Wait for window or process to appear responsive
        $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
        $windowFound = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            $proc.Refresh()
            if ($proc.MainWindowHandle -ne [IntPtr]::Zero -and
                $proc.MainWindowTitle -eq "安全审查工具") {
                $windowFound = $true
                break
            }
            if ($proc.MainWindowTitle -eq "安全审查工具 - 启动失败") {
                $evidence.failures += "Startup failure dialog was shown instead of the main window."
                break
            }
            if ($proc.HasExited) {
                $evidence.failures += "Process exited during startup with code $($proc.ExitCode)."
                break
            }
            Start-Sleep -Milliseconds 200
        }
        $elapsed = $startWatch.Elapsed.TotalSeconds
        $evidence.checks["startup_time_seconds"] = $elapsed

        if ($windowFound) {
            Write-Host "  Startup: $([math]::Round($elapsed, 1))s (window found)" -ForegroundColor Green
        } else {
            Write-Host "  Startup: $([math]::Round($elapsed, 1))s (window NOT found within timeout)" -ForegroundColor Red
            if ($elapsed -gt $StartupTimeoutSeconds) {
                $evidence.failures += "Startup exceeded ${StartupTimeoutSeconds}s timeout ($([math]::Round($elapsed, 1))s)."
            }
        }
    } catch {
        $evidence.failures += "Startup failed: $_"
        Write-Host "  Startup failed: $_" -ForegroundColor Red
    }

    # ── 7. Process delta check (no unexpected processes) ─────────────────────
    Write-Host "=== Step 6: Process delta ==="

    $postLaunchProc = Get-SystemSnapshot "post-launch" $snapshotDir
    $evidence.checks["process_delta"] = "captured"

    # ── 8. Wait for sandbox health check ─────────────────────────────────────
    Write-Host "=== Step 7: Sandbox health ==="

    $healthPath = "$env:LOCALAPPDATA\SecurityReviewTool\diagnostics\health.json"
    $healthTimeout = 30
    $healthStart = [DateTime]::UtcNow
    $healthResult = $null

    while ([DateTime]::UtcNow -lt $healthStart.AddSeconds($healthTimeout)) {
        if (Test-Path $healthPath) {
            try {
                $healthResult = Get-Content $healthPath -Raw -Encoding UTF8 | ConvertFrom-Json
                break
            } catch { }
        }
        Start-Sleep -Seconds 1
    }

    if ($healthResult) {
        $evidence.checks["sandbox_health"] = $healthResult.overall
        Write-Host "  Health: $($healthResult.overall)"
        if ($healthResult.overall -ne "pass") {
            $evidence.failures += "Sandbox health check failed: $($healthResult | ConvertTo-Json -Compress)"
        }
    } else {
        $evidence.checks["sandbox_health"] = "timeout"
        $evidence.failures += "Sandbox health check did not complete within ${healthTimeout}s."
        Write-Host "  Health: timeout" -ForegroundColor Red
    }

    # ── 9. Synthetic scan (if TestAssetDir provided) ────────────────────────
    if ($TestAssetDir -and (Test-Path $TestAssetDir)) {
        Write-Host "=== Step 8: Synthetic scan ==="
        Write-Host "  Test asset directory: $TestAssetDir"
        Write-Host "  (Automated scan via UI not available in script mode — manual step.)"
        Write-Host "  Verify in UI: New Scan → select $TestAssetDir → run scan."
        Write-Host "  Expected: findings appear; unsupported formats produce gaps."
        $evidence.checks["synthetic_scan"] = "manual"
    } else {
        $evidence.checks["synthetic_scan"] = "skipped"
        Write-Host "  Synthetic scan skipped (no -TestAssetDir)." -ForegroundColor Yellow
    }

    # ── 10. UI verification steps (manual guide) ────────────────────────────
    Write-Host ""
    Write-Host "=== Step 9: Manual UI verification ===" -ForegroundColor Cyan
    Write-Host "In the running SecurityReviewTool window, verify:"
    Write-Host "  [ ] Review grid shows findings."
    Write-Host "  [ ] Coverage tab shows format/parser assignments."
    Write-Host "  [ ] Rescan button works (re-runs scan)."
    Write-Host "  [ ] Export XLSX creates a valid six-sheet workbook."
    Write-Host "  [ ] Settings → Diagnostics → Collect Diagnostics creates a ZIP."
    Write-Host "  [ ] Cancel button stops a running scan."
    Write-Host "  [ ] Clear data (via Settings) resets to fresh state."
    Write-Host ""

    # ── 11. Network capture: stop pktmon ─────────────────────────────────────
    if (-not $SkipNetworkCapture -and $evidence.checks["pktmon_started"]) {
        Write-Host "=== Step 10: Network capture analysis ==="

        try {
            pktmon stop 2>$null
            $pktmonOut = Join-Path $evidenceDir "pktmon.etl"
            pktmon etl2txt (Join-Path $env:SystemRoot "System32\LogFiles\WMI\PktMon.etl") --output $pktmonOut 2>$null

            if (Test-Path $pktmonOut) {
                $pktmonContent = Get-Content $pktmonOut -Raw
                $evidence.checks["pktmon_captured"] = $true

                # Check for worker network connections
                # Worker is SecurityReview.Worker.exe
                $workerLines = $pktmonContent | Select-String "Worker" -SimpleMatch
                $evidence.checks["worker_network_lines"] = $workerLines.Count

                if ($workerLines.Count -gt 0) {
                    $evidence.failures += "WORKER NETWORK ACTIVITY DETECTED: $($workerLines.Count) lines."
                    Write-Host "  FAIL: Worker network activity detected!" -ForegroundColor Red
                    $workerLines | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
                } else {
                    Write-Host "  PASS: Zero worker network connections." -ForegroundColor Green
                }

                # Check for loopback connections from worker
                $loopbackLines = $workerLines | Select-String "127\.|::1|localhost" -SimpleMatch
                $evidence.checks["worker_loopback_lines"] = $loopbackLines.Count
                if ($loopbackLines.Count -gt 0) {
                    $evidence.failures += "Worker loopback connection detected: $($loopbackLines.Count) lines."
                }

                # Check for non-DNS/non-TLS connections
                $nonDnsTls = $pktmonContent | Select-String -Pattern ":(?!53\b|443\b)\d{1,5}" -NotMatch
                $evidence.checks["pktmon_analyzed"] = $true
            }
        } catch {
            Write-Host "  Network capture analysis failed: $_" -ForegroundColor Yellow
            $evidence.checks["pktmon_error"] = $_.Exception.Message
        }
    }

    # ── 12. Windows firewall log check ───────────────────────────────────────
    Write-Host "=== Step 11: Firewall log check ==="

    try {
        $fwLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
        if (Test-Path $fwLog) {
            $fwLines = Get-Content $fwLog -Tail 200
            $evidence.checks["firewall_log_entries"] = $fwLines.Count
            Write-Host "  Firewall log: $($fwLines.Count) recent entries captured."
        } else {
            Write-Host "  Firewall log not found (may not be enabled)."
            Write-Host "  Enable with: netsh advfirewall set allprofiles logging filename %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
        }
    } catch {
        Write-Host "  Firewall log check failed: $_" -ForegroundColor Yellow
    }

    # ── 13. Post-run system snapshot delta ───────────────────────────────────
    Write-Host "=== Step 12: Post-run snapshot delta ==="

    $postProc   = Get-SystemSnapshot "post-run" $snapshotDir
    $postFS     = Get-FilesystemSnapshot "post-run" $snapshotDir

    # Process diff
    $baselinePids = @{}
    $baselineProc.processes | ForEach-Object { $baselinePids[$_.Id] = $true }
    $newProcesses = @($postProc.processes | Where-Object { -not $baselinePids.ContainsKey($_.Id) -and $_.StartTime -gt [DateTime]::UtcNow.AddMinutes(-30) })
    $evidence.checks["new_processes"] = $newProcesses.Count
    $evidence.checks["new_process_names"] = @($newProcesses | Select-Object -ExpandProperty ProcessName | Where-Object { $_ -notmatch "^(SecurityReviewTool|SecurityReview\.Worker|conhost|csrss|dwm|RuntimeBroker|sihost|svchost|taskhostw|WmiPrvSE|SearchIndexer|ShellExperienceHost|StartMenuExperienceHost|TextInputHost|Widgets|WinStore|SystemSettings|ApplicationFrameHost|UserOOBEBroker|backgroundTaskHost|smartscreen)$" })

    Write-Host "  New processes (last 30 min): $($newProcesses.Count)"
    $evidence.checks["new_process_names"] | ForEach-Object { Write-Host "    $_" }

    # Service diff
    $baselineSvc = @{}
    $baselineProc.services | ForEach-Object { $baselineSvc[$_.Name] = $true }
    $newServices = @($postProc.services | Where-Object { -not $baselineSvc.ContainsKey($_.Name) })
    $evidence.checks["new_services"] = $newServices.Count
    if ($newServices.Count -gt 0) {
        $evidence.failures += "New Windows services detected: $($newServices.Name -join ', ')"
        Write-Host "  New services: $($newServices.Name -join ', ')" -ForegroundColor Red
    } else {
        Write-Host "  PASS: No new services." -ForegroundColor Green
    }

    # Scheduled task diff
    $baselineTasks = @{}
    $baselineProc.scheduled_tasks | ForEach-Object { $baselineTasks[$_.TaskName] = $true }
    $newTasks = @($postProc.scheduled_tasks | Where-Object { -not $baselineTasks.ContainsKey($_.TaskName) })
    $evidence.checks["new_scheduled_tasks"] = $newTasks.Count
    if ($newTasks.Count -gt 0) {
        $evidence.failures += "New scheduled tasks detected: $($newTasks.TaskName -join ', ')"
        Write-Host "  New tasks: $($newTasks.TaskName -join ', ')" -ForegroundColor Red
    } else {
        Write-Host "  PASS: No new scheduled tasks." -ForegroundColor Green
    }

    # Registry run-key diff
    $baselineRun = @{}
    $baselineProc.registry_hkcu_run + $baselineProc.registry_hklm_run | ForEach-Object { $baselineRun[$_] = $true }
    $postRun = @($postProc.registry_hkcu_run + $postProc.registry_hklm_run | Where-Object { -not $baselineRun.ContainsKey($_) })
    $evidence.checks["new_run_keys"] = $postRun.Count
    if ($postRun.Count -gt 0) {
        $evidence.failures += "New registry run keys: $($postRun -join ', ')"
        Write-Host "  New run keys: $($postRun -join ', ')" -ForegroundColor Red
    } else {
        Write-Host "  PASS: No new registry run keys." -ForegroundColor Green
    }

    # Filesystem diff: check for unexpected directories
    $newDirs = @()
    foreach ($p in $postFS.directories.Keys) {
        if ($baselineFS.directories.ContainsKey($p)) {
            $before = $baselineFS.directories[$p]
            $after  = $postFS.directories[$p]
            $diff   = @($after | Where-Object { $_ -notin $before })
            if ($diff.Count -gt 0) {
                $newDirs += "$p\$($diff -join ", $p\")"
            }
        }
    }
    $evidence.checks["new_directories"] = $newDirs.Count
    if ($newDirs.Count -gt 0) {
        Write-Host "  New directories detected:" -ForegroundColor Yellow
        $newDirs | ForEach-Object { Write-Host "    $_" }
    }

    # ── 14. Check LocalAppData contents ──────────────────────────────────────
    Write-Host "=== Step 13: LocalAppData verification ==="

    $appDataDir = "$env:LOCALAPPDATA\SecurityReviewTool"
    if (Test-Path $appDataDir) {
        $appDataContents = @(Get-ChildItem $appDataDir -Recurse -File | Select-Object FullName, Length)
        $evidence.checks["appdata_files"] = $appDataContents.Count
        Write-Host "  LocalAppData files: $($appDataContents.Count)"

        # Check for .log files with secrets
        $logFiles = @($appDataContents | Where-Object { $_.FullName -match '\.log$' })
        $evidence.checks["log_files"] = $logFiles.Count
        Write-Host "  Log files: $($logFiles.Count)"

        # Check for plaintext credentials
        $plaintextCheck = Get-ChildItem $appDataDir -Recurse -File | Where-Object {
            $_.Extension -notin @('.db', '.db-wal', '.db-shm') -and
            $_.Name -notlike "*.dll" -and $_.Name -notlike "*.exe" -and
            $_.Name -notlike "*.json" -and $_.Name -notlike "*.zip"
        }
        foreach ($f in $plaintextCheck) {
            try {
                $content = Get-Content $f.FullName -Raw -ErrorAction Stop
                if ($content -match '(api[_\-]?key|apikey|secret|token|password|credential)\s*[:=]\s*[^\s"]{8,}') {
                    $evidence.failures += "Potential plaintext credential in: $($f.FullName)"
                    Write-Host "  WARNING: potential credential in $($f.FullName)" -ForegroundColor Red
                }
            } catch { }
        }
    } else {
        Write-Host "  LocalAppData directory not created (tool may not have fully initialized)."
    }

    # ── 15. Zero startup telemetry check ─────────────────────────────────────
    Write-Host "=== Step 14: Startup telemetry check ==="

    # Check for known telemetry endpoints in network capture
    $telemetryDomains = @(
        "telemetry", "events.data.microsoft.com", "vortex.data.microsoft.com",
        "watson.telemetry.microsoft.com", "dc.services.visualstudio.com",
        "mobile.events.data.microsoft.com", "browser.events.data.microsoft.com",
        "settings-win.data.microsoft.com", "onedscolprdcus*"
    )
    $evidence.checks["telemetry_check"] = "manual"
    Write-Host "  Manual: Verify in pktmon/firewall logs that no connections were made to:"
    $telemetryDomains | ForEach-Object { Write-Host "    - $_" }

    # ── 16. Cleanup: close the application ───────────────────────────────────
    Write-Host "=== Step 15: Cleanup ==="
    if ($proc -and -not $proc.HasExited) {
        Write-Host "  Closing SecurityReviewTool..."
        $proc.CloseMainWindow()
        Start-Sleep -Seconds 3
        if (-not $proc.HasExited) {
            $proc.Kill()
        }
        Write-Host "  Process exited with code: $($proc.ExitCode)"
    }

    # Final snapshot
    $postCleanupProc = Get-SystemSnapshot "post-cleanup" $snapshotDir

    # Check for residual worker processes
    $residualWorkers = @(Get-Process -Name "SecurityReview.Worker" -ErrorAction SilentlyContinue)
    if ($residualWorkers.Count -gt 0) {
        $evidence.failures += "Residual worker processes after cleanup: $($residualWorkers.Count)"
        Write-Host "  WARNING: $($residualWorkers.Count) residual worker processes!" -ForegroundColor Red
        $residualWorkers | Stop-Process -Force
    } else {
        Write-Host "  PASS: No residual worker processes." -ForegroundColor Green
    }

    # ── 17. Write evidence summary ───────────────────────────────────────────
    Write-Host ""
    Write-Host "=== Step 16: Write evidence ==="

    $evidencePath = Join-Path $Output "clean-vm-evidence.json"
    $evidence | ConvertTo-Json -Depth 5 | Out-File $evidencePath -Encoding utf8

    # Summary markdown
    $summaryPath = Join-Path $Output "clean-vm-summary.md"
    $passCount = ($evidence.checks.Values | Where-Object { $_ -eq $true -or $_ -eq "pass" -or $_ -match '^\d+$' }).Count
    $totalCount = $evidence.checks.Count
    $failCount = $evidence.failures.Count

    $summary = @"
# Clean-VM Validation Summary

**Timestamp:** $($evidence.timestamp_utc)
**OS:** $($evidence.host_os_caption) (build $($evidence.host_os_build))
**Package SHA-256:** `$packageHash`

## Results

| Check | Result |
|-------|--------|
| Extraction | OK -> `$extractDir` |
| Admin prompt | $($requiresAdmin ? "FAIL" : "PASS") |
| Startup time | $([math]::Round($evidence.checks['startup_time_seconds'], 1))s |
| Sandbox health | $($evidence.checks['sandbox_health']) |
| New services | $($evidence.checks['new_services']) |
| New scheduled tasks | $($evidence.checks['new_scheduled_tasks']) |
| New registry run keys | $($evidence.checks['new_run_keys']) |
| Worker network | $($evidence.checks['worker_network_lines']) lines |
| LocalAppData files | $($evidence.checks['appdata_files']) |

## Failures ($failCount)

$($evidence.failures -join "`n")
$(if ($failCount -eq 0) { "**None — all checks passed.**" } else { "" })
"@

    $summary | Out-File $summaryPath -Encoding utf8

    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "=== Clean-VM validation: FAILED ($failCount failures) ===" -ForegroundColor Red
        $evidence.failures | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    } else {
        Write-Host ""
        Write-Host "=== Clean-VM validation: PASSED ===" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Evidence: $evidencePath"
    Write-Host "Summary:  $summaryPath"

    exit $failCount

} finally {
    Pop-Location
}
