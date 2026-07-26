#!/usr/bin/env bash
# Windows security lane (WSL2 controller side).
#
# Publishes both the fault-injection probe worker and the standard production
# worker, plus the WindowsSecurityTests project self-contained. The production
# variant proves the runtime self-test path shipped to users.
#
# Usage: build/windows-lane.sh [windows-staging-dir]
#   default windows staging dir: C:\Users\yusiyi\AppData\Local\Temp\srt-winlane
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export DOTNET_ROOT="$PWD/.dotnet"
export PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1

LANE_DIR="artifacts/windows-lane"
EVIDENCE_DIR="artifacts/windows-security"
WIN_STAGING_WSL="${1:-/mnt/c/Users/yusiyi/AppData/Local/Temp/srt-winlane}"
WIN_STAGING_HOST='C:\Users\yusiyi\AppData\Local\Temp\srt-winlane'

mkdir -p "$LANE_DIR" "$EVIDENCE_DIR"
rm -rf "$LANE_DIR/WorkerProbe" "$LANE_DIR/WorkerProduction" \
  "$LANE_DIR/WindowsSecurityTests"

echo "== publish probe worker (self-contained) =="
dotnet publish src/SecurityReview.Worker/SecurityReview.Worker.csproj \
  -c Release -r win-x64 --self-contained true \
  -p:SecurityReviewSandboxProbe=true \
  -o "$LANE_DIR/WorkerProbe"

echo "== publish production worker (self-contained) =="
dotnet publish src/SecurityReview.Worker/SecurityReview.Worker.csproj \
  -c Release -r win-x64 --self-contained true \
  -o "$LANE_DIR/WorkerProduction"

echo "== publish WindowsSecurityTests (self-contained) =="
dotnet publish tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj \
  -c Release -r win-x64 --self-contained true \
  -o "$LANE_DIR/WindowsSecurityTests"

echo "== generate worker manifests (SHA-256) =="
for worker_dir in "$LANE_DIR/WorkerProbe" "$LANE_DIR/WorkerProduction"; do
python3 - "$worker_dir" <<'PY'
import hashlib, json, os, sys
root = sys.argv[1]
files = {}
for name in sorted(os.listdir(root)):
    path = os.path.join(root, name)
    if os.path.isfile(path) and name != "worker-manifest.json":
        with open(path, "rb") as handle:
            files[name] = hashlib.sha256(handle.read()).hexdigest()
with open(os.path.join(root, "worker-manifest.json"), "w", encoding="utf-8") as handle:
    json.dump({"algorithm": "SHA256", "files": files}, handle, indent=1)
print(f"manifest covers {len(files)} files")
PY
done

echo "== stage to Windows host =="
powershell.exe -NoProfile -Command "Get-Process -Name 'SecurityReview.Worker' -ErrorAction SilentlyContinue | Stop-Process -Force" || true
rm -rf "$WIN_STAGING_WSL"
mkdir -p "$WIN_STAGING_WSL"
cp -r "$LANE_DIR/WorkerProbe" "$LANE_DIR/WorkerProduction" \
  "$LANE_DIR/WindowsSecurityTests" "$WIN_STAGING_WSL/"

echo "== run lane on Windows =="
powershell.exe -NoProfile -Command "
[Console]::OutputEncoding = [Text.Encoding]::UTF8;
\$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = '1';
\$env:SECURITY_REVIEW_PROBE_WORKER_DIR = '$WIN_STAGING_HOST\WorkerProbe';
\$env:SECURITY_REVIEW_PRODUCTION_WORKER_DIR = '$WIN_STAGING_HOST\WorkerProduction';
Set-Location '$WIN_STAGING_HOST\WindowsSecurityTests';
.\SecurityReview.WindowsSecurityTests.exe;
exit \$LASTEXITCODE
" | tee "$EVIDENCE_DIR/windows-security-lane.log"
LANE_EXIT=${PIPESTATUS[0]}

echo "== collect evidence =="
powershell.exe -NoProfile -Command "
[Console]::OutputEncoding = [Text.Encoding]::UTF8;
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber | ConvertTo-Json;
" > "$EVIDENCE_DIR/os-build.json"
python3 - "$WIN_STAGING_WSL/WorkerProbe/SecurityReview.Worker.exe" > "$EVIDENCE_DIR/worker-hash.json" <<'PY'
import hashlib, json, sys
with open(sys.argv[1], "rb") as handle:
    digest = hashlib.sha256(handle.read()).hexdigest().upper()
print(json.dumps({"Algorithm": "SHA256", "Hash": digest}, indent=1))
PY

echo "lane exit code: $LANE_EXIT"
exit "$LANE_EXIT"
