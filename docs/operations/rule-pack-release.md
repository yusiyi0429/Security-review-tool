# Rule Pack Release Procedure

This document defines the release checklist for security-review rule packs.
Every rule pack release MUST follow these steps in order. Any deviation requires
documented approval.

## Preconditions

- The release is performed on a **clean machine** (fresh checkout, no cached
  build artifacts).
- The repository is at a tagged commit (`vX.Y.Z`).
- Two authorized reviewers have signed off on the rule changes.

## Release Checklist

### 1. Two-Person Review

- [ ] At least two authorized reviewers have reviewed and approved all rule
  additions, modifications, and deletions.
- [ ] Reviewer 1: Technical correctness (detector logic, regex patterns,
  entity lists).
- [ ] Reviewer 2: Policy compliance (severity assignments, category mapping,
  false-positive analysis).
- [ ] Both reviewers documented their approval in the release tracking system.

### 2. Workbook Validation

- [ ] The rule workbook (`rules/workbook.xlsx`) passes schema validation.
- [ ] All formulas resolve without errors.
- [ ] Every rule has a non-empty `DetectorConfigId` and `AppliesToAssets`.
- [ ] Every detector has a non-empty `ConfigId` and valid `Kind`.
- [ ] No duplicate rule IDs, detector IDs, or entity IDs.
- [ ] All placeholder entries have valid, non-expired dates.
- [ ] Workbook hash matches the committed version.

```powershell
# Validate workbook schema
dotnet test tests/SecurityReview.ContractTests -c Release --filter "FullyQualifiedName~Workbook"
```

### 3. Package Build

- [ ] Build the rule pack from the signed-off workbook on a clean machine.
- [ ] The build is fully reproducible (same inputs → identical ZIP bytes).

```powershell
# Clean build
Remove-Item -Recurse -Force artifacts/rules -ErrorAction SilentlyContinue
dotnet build -c Release

# Build the signed rule pack
dotnet run --project tools/SecurityReview.RulePackBuilder -c Release -- build `
  --workbook rules/workbook.xlsx `
  --output artifacts/rules/security-review-rules-{VERSION}.zip `
  --signer-key-id {SIGNER_KEY_ID}
```

### 4. Signature Verification

- [ ] Verify the package signature against the trusted signer public key.
- [ ] The signer public key is obtained from a **secure, out-of-band channel**
  (hardware token, HSM, or air-gapped key server). **NEVER** email private keys.
- [ ] **NEVER** store private keys in environment files (`.env`, `.env.local`,
  `.env.production`) under the repository.

```powershell
# Verify the signature
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- verify-signature `
  --rules artifacts/rules/security-review-rules-{VERSION}.zip `
  --trusted-signers config/trusted-signers.json
```

### 5. Corpus Verification

- [ ] Run the deterministic rule corpus against the new package.
- [ ] **Exit code must be 0.** Any non-zero exit blocks the release.

```powershell
# Update manifest hashes and run verification
pwsh tests/Corpus/Rules/generate-rule-corpus.ps1 `
  -RulesPath "artifacts/rules/security-review-rules-{VERSION}.zip" `
  -ManifestPath "tests/Corpus/Rules/rule-corpus-manifest.json" `
  -OutputPath "artifacts/corpus/rule-results.json"
```

- [ ] 100% of expected Critical/High detections confirmed.
- [ ] No unauthorized placeholder suppression.
- [ ] No detector errors (coverage gaps).
- [ ] All provenance entries present and complete.
- [ ] All declared absence IDs confirmed absent.

### 6. Diff Summary

- [ ] Generate a human-readable diff between the previous active rule pack and
  the new version.
- [ ] Document every added, modified, and deleted rule.
- [ ] Document every added, modified, and deleted entity.
- [ ] Document every added, modified, and deleted placeholder.
- [ ] Document severity changes (upgrades and downgrades).

```powershell
# Generate diff summary
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- diff-rules `
  --old artifacts/rules/security-review-rules-{OLD_VERSION}.zip `
  --new artifacts/rules/security-review-rules-{NEW_VERSION}.zip `
  --output artifacts/corpus/rule-diff-{OLD_VERSION}-to-{NEW_VERSION}.md
```

### 7. Public Key and SHA-256 Publication

- [ ] Publish the SHA-256 hash of the new rule pack ZIP.
- [ ] Verify the signer's public key fingerprint against the published value.
- [ ] Publish the release metadata (version, SHA-256, signer key ID, timestamp).

```powershell
# Compute SHA-256
Get-FileHash -Algorithm SHA256 artifacts/rules/security-review-rules-{VERSION}.zip
```

### 8. Old-Version Retention

- [ ] Retain the previous active rule pack version for at least 90 days.
- [ ] Store old versions in a versioned, access-controlled archive.
- [ ] Do not delete old versions until the retention period expires.

### 9. Client Compatibility

- [ ] Verify the `min_client_version` in the manifest does not exceed the
  latest deployed client version.
- [ ] Verify that all detectors referenced by rules exist in the package.
- [ ] Verify that all category IDs referenced by rules exist in the package.
- [ ] Verify that all asset type IDs referenced by rules exist in the package.

### 10. Rollback Procedure

If the new rule pack causes false positives or detector issues in production:

1. **Immediate:** Deactivate the new active pointer and reactivate the previous
   active pointer.

   ```powershell
   dotnet run --project tools/SecurityReview.CorpusTool -c Release -- rollback `
     --version {PREVIOUS_VERSION}
   ```

2. **Investigation:** Run the corpus verification against the problematic
   package to identify the regressing test case.

3. **Fix:** Create a new rule pack version with corrections.

4. **Re-release:** Re-run this checklist from step 1.

## Security Prohibitions

| Prohibited Action | Rationale |
|---|---|
| Emailing private keys | Email is not end-to-end encrypted. Keys sent via email are compromised. |
| Storing keys in `.env` files under the repo | `.env` files risk accidental commit. Use DPAPI (Windows) or a hardware token. |
| Committing `.env` or credential files | Git history retains secrets forever. |
| Releasing without corpus pass | A failing corpus means a regression; blocking prevents silent breakage. |
| Bypassing two-person review | No single individual may unilaterally release a rule pack. |

## Release Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| Technical Reviewer | | | |
| Policy Reviewer | | | |
| Release Engineer | | | |
