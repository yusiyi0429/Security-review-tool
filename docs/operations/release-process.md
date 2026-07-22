# Windows Release Process

This document defines the release procedure for the portable Windows x64
package and per-user installer of SecurityReviewTool. Every release MUST follow these steps in
order. Any deviation requires documented approval.

## Preconditions

- The release is performed on a **clean machine** (fresh checkout, no cached
  build artifacts from previous builds).
- The repository is at a tagged commit (`vX.Y.Z`).
- The signing certificate is installed in the current user's certificate
  store if Authenticode signing is required.
- `pwsh` (PowerShell 7+) is installed.
- .NET SDK version in `global.json` is installed.
- Inno Setup 6 or 7 is installed when producing the installer.
- NuGet sources are configured and accessible.

## Release Checklist

### 1. Verify Traceability

```powershell
pwsh build/verify-traceability.ps1
```

Must exit 0. All requirement IDs, acceptance criteria, and verification
tests must be present and linked.

### 2. Build and Test

```powershell
pwsh build/build.ps1 -Configuration Release
pwsh build/test.ps1 -Lane Unit,Contract,Integration
```

Must exit 0. All lanes must pass.

### 3. Vulnerability Scan (Pre-release)

```powershell
dotnet list SecurityReviewTool.sln package --vulnerable --include-transitive
dotnet list SecurityReviewTool.sln package --deprecated
```

Any Critical or High vulnerability MUST have a reviewed exception document
containing: package name, version, CVE identifier, reachability analysis,
compensating controls, owner, and expiry date.

### 4. Package (Unsigned Pilot)

For development / pre-release / pilot builds:

```powershell
pwsh build/package.ps1 -Version 1.0.1 -AllowUnsignedPilot
```

This produces `artifacts/release/SecurityReviewTool-1.0.1-win-x64.zip`
and its `.sha256` sidecar.

### 5. Verify Package

```powershell
pwsh build/verify-package.ps1 `
  -Package artifacts/release/SecurityReviewTool-1.0.1-win-x64.zip `
  -RequireUnsignedPilotWarning
```

Must exit 0. The verifier checks:

1. **Extraction integrity** — no path traversal, no duplicate file names.
2. **Allowlist compliance** — every file matches `build/package-file-allowlist.txt`.
3. **Manifest validity** — `release-manifest.json` has all required fields.
4. **File cross-check** — manifest entries match extracted files (size, SHA-256).
5. **SBOM validity** — SPDX manifest is present and parseable JSON.
6. **Asset integrity** — `trusted-signers.json` exists and is valid JSON.
7. **Forbidden patterns** — no `.pdb`, `.xml` doc files, test/corpus/source artifacts.
8. **Signer mode** — matches expected mode (unsigned_pilot or authenticode).
9. **PE architecture** — main executable is x64 (AMD64).
10. **No stateful files** — no `.db`, `.sqlite`, `.wal`, `.shm`, `.log`, `.config` files.

### 6. Build Installer (Unsigned Pilot)

```powershell
pwsh build/package-installer.ps1 `
  -Version 1.0.1 `
  -PortablePackage artifacts/release/SecurityReviewTool-1.0.1-win-x64.zip `
  -AllowUnsignedPilot
```

This command verifies the portable ZIP again, builds a per-user installer, and
generates:

```text
artifacts/release/SecurityReviewTool-1.0.1-win-x64-setup.exe
artifacts/release/SecurityReviewTool-1.0.1-win-x64-setup.exe.sha256
```

The installer must be smoke-tested on a clean Windows 11 VM: install, launch,
upgrade in place, uninstall, and confirm that user data is retained.

### 7. Reproducibility Build

Build twice with the same source, version, SDK, and package lock:

```powershell
pwsh build/package.ps1 -Version 1.0.1-repro.1 -AllowUnsignedPilot
# Rename output
Move-Item artifacts/release/SecurityReviewTool-1.0.1-repro.1-win-x64.zip `
  artifacts/release/build-1.zip

pwsh build/package.ps1 -Version 1.0.1-repro.1 -AllowUnsignedPilot
Move-Item artifacts/release/SecurityReviewTool-1.0.1-repro.1-win-x64.zip `
  artifacts/release/build-2.zip
```

Compare the manifests:

```powershell
$m1 = (Expand-Archive -LiteralPath artifacts/release/build-1.zip -DestinationPath /tmp/b1 -Force;
       Get-Content /tmp/b1/release-manifest.json | ConvertFrom-Json)
$m2 = (Expand-Archive -LiteralPath artifacts/release/build-2.zip -DestinationPath /tmp/b2 -Force;
       Get-Content /tmp/b2/release-manifest.json | ConvertFrom-Json)

$diff = Compare-Object $m1.files $m2.files -Property path,size,sha256
if ($diff) { throw "Reproducibility check FAILED." }
```

Application assemblies, assets, rules, and resources MUST have identical
hashes. The following fields are explicitly allowed to vary between
builds:

- `created_utc` (manifest timestamp)
- SBOM document identity fields (SPDX namespace, creation timestamp)
- Authenticode signature and timestamp (when `signer_mode` is `authenticode`)
- SHA-256 of the signed ZIP (includes signature bytes)

No other file content difference is acceptable. Record both deterministic
and expected-volatile sets in release evidence.

### 8. Package and Installer (Authenticode Signed)

For production releases:

```powershell
pwsh build/package.ps1 -Version 1.0.1 -SigningCertificateThumbprint "A1B2C3D4E5F6..."
pwsh build/package-installer.ps1 `
  -Version 1.0.1 `
  -PortablePackage artifacts/release/SecurityReviewTool-1.0.1-win-x64.zip `
  -SigningCertificateThumbprint "A1B2C3D4E5F6..."
```

The signing certificate thumbprint must be obtained from a secure,
out-of-band source. **NEVER** store private keys in environment files
(`.env`, `.env.local`) under the repository.

### 9. Publish SHA-256

Publish the SHA-256 hash of the release ZIP through an authenticated,
out-of-band channel:

```powershell
Get-Content artifacts/release/SecurityReviewTool-1.0.1-win-x64.zip.sha256
```

Users verify with:

```powershell
Get-FileHash -Algorithm SHA256 SecurityReviewTool-1.0.1-win-x64.zip
```

### 10. Run Contract Tests

```powershell
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj `
  -c Release --filter "FullyQualifiedName~Package"
```

Must exit 0. Package manifest and content contract tests verify the
allowlist structure and schema conformance.

### 11. Commit

```powershell
git add build/package.ps1 build/package-installer.ps1 build/installer.iss `
  build/verify-package.ps1 build/generate-sbom.ps1 `
  build/package-file-allowlist.txt `
  src/SecurityReview.Desktop/Assets/release-manifest.schema.json `
  docs/operations/release-process.md `
  tests/SecurityReview.ContractTests/Release/
git commit -m "build: produce verified portable Windows release package"
```

## Rollback Procedure

If a released package is found to have issues:

1. Remove the problematic ZIP from the distribution channel.
2. Create a new release with the fix, bumping the patch version.
3. Publish the new SHA-256 sidecar.
4. Document the issue in the release notes.

## Security Prohibitions

| Prohibited Action | Rationale |
|---|---|
| Storing signing certificate private keys in `.env` files under the repo | `.env` files risk accidental commit. Use DPAPI (Windows) or a hardware token. |
| Committing `.env` or credential files | Git history retains secrets forever. |
| Releasing without allowlist/verification pass | A failing allowlist means unexpected files; blocking prevents supply-chain issues. |
| Releasing without vulnerability scan | Undisclosed vulnerabilities may compromise users. |
| Bypassing reproducibility check | Non-reproducible builds may contain hidden state or tampering. |
| Overwriting an existing release ZIP | Never replace a published artifact; always bump the version. |

## Artifacts

| File | Description |
|---|---|
| `SecurityReviewTool-<version>-win-x64.zip` | Portable Windows x64 release package |
| `SecurityReviewTool-<version>-win-x64.zip.sha256` | SHA-256 sidecar |
| `SecurityReviewTool-<version>-win-x64-setup.exe` | Per-user Windows x64 installer |
| `SecurityReviewTool-<version>-win-x64-setup.exe.sha256` | Installer SHA-256 sidecar |
| `artifacts/release/evidence/vulnerabilities.txt` | Dependency vulnerability report |
| `artifacts/release/evidence/deprecated.txt` | Deprecated dependency report |
| `artifacts/release/stage/sbom-out/_manifest/spdx_2.2/manifest.spdx.json` | SPDX SBOM |
