# Security Review P3 Rule Packs and Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the approved Excel policy into a signed, versioned offline rule package; enforce an undeletable eight-category baseline; run deterministic detectors; and produce grouped findings with complete rule/detector/location provenance.

**Architecture:** Rule maintenance is separate from scanning. `SecurityReview.RulePackBuilder` reads a fixed Excel template, validates references/detector safety/corpus expectations, emits canonical JSON and an ECDSA-signed ZIP. The client validates and atomically activates packages, builds an effective additive policy, then streams parser chunks through small deterministic detectors. LLM review is a later, non-destructive stage.

**Tech Stack:** Open XML SDK 3.5.1, `System.Text.Json`, ECDSA P-256/SHA-256, .NET `RegexOptions.NonBacktracking`, custom checksum/network/entropy/Aho-Corasick detectors, xUnit.net v3.

## Global Constraints

- `SENS-001` through `SENS-008` are mandatory and enabled for every asset, including unknown assets.
- Asset-specific and local policies can only add rules or raise review requirements; they cannot disable baseline rules, lower minimum severity, broaden safe placeholders, or replace detector definitions.
- Client imports signed rule ZIPs, not raw maintenance Excel. Signing private keys never enter the repository or client.
- Rule ZIP paths are normalized, unique, root-relative, and hash-covered; manifest bytes are canonical and signed exactly.
- Deterministic findings never depend on LLM availability and keep detector/rule provenance.
- Approved placeholders are exact signed policy entries. LLM or local UI cannot invent a placeholder exemption.
- Third-party results use bounded wording (“suspected restricted third-party content; manual verification required”), never an automatic infringement claim.
- A rule package release is blocked if any expected deterministic high-risk corpus sample is missed.

---

## Task P3-T1: Define rule schemas and the built-in policy baseline

**Files:**
- Create: `src/SecurityReview.Domain/Rules/RulePackId.cs`
- Create: `src/SecurityReview.Domain/Rules/RuleDefinition.cs`
- Create: `src/SecurityReview.Domain/Rules/DetectorDefinition.cs`
- Create: `src/SecurityReview.Domain/Rules/AssetPolicy.cs`
- Create: `src/SecurityReview.Domain/Rules/ComplianceRule.cs`
- Create: `src/SecurityReview.Domain/Findings/FindingKind.cs`
- Create: `src/SecurityReview.Domain/Findings/Severity.cs`
- Create: `src/SecurityReview.Domain/Findings/DetectionConfidence.cs`
- Create: `src/SecurityReview.RulePack/Schema/RulePackDocument.cs`
- Create: `src/SecurityReview.RulePack/Schema/RulePackJsonContext.cs`
- Create: `src/SecurityReview.RulePack/Validation/RuleGraphValidator.cs`
- Create: `rules/schemas/rule-pack-manifest-v1.schema.json`
- Create: `rules/schemas/categories-v1.schema.json`
- Create: `rules/schemas/assets-v1.schema.json`
- Create: `rules/schemas/detectors-v1.schema.json`
- Create: `rules/baseline/categories.json`
- Create: `rules/baseline/assets.json`
- Create: `rules/baseline/compliance.json`
- Create: `tests/SecurityReview.UnitTests/Rules/BaselinePolicyTests.cs`
- Create: `tests/SecurityReview.ContractTests/Rules/RuleSchemaTests.cs`

**Interfaces:**
- Consumes: stable `AssetTypeId`, `CategoryId`, `Severity`, and `DetectionConfidence` domain values.
- Produces: canonical rule documents and `RuleGraphValidator.Validate`, consumed by builder, importer, effective policy, and detectors.

- [ ] **Step 1: Write baseline completeness and non-weakening tests**

```csharp
public sealed class BaselinePolicyTests
{
    [Fact]
    public void Contains_exactly_eight_enabled_categories()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.Equal(Enumerable.Range(1, 8).Select(i => $"SENS-{i:000}"),
            baseline.Categories.Select(x => x.Id.Value).Order(StringComparer.Ordinal));
        Assert.All(baseline.Categories, x => Assert.True(x.Enabled));
    }

    [Fact]
    public void Contains_exactly_eleven_registered_asset_policies()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.Equal(11, baseline.Assets.Select(x => x.AssetTypeId).Distinct().Count());
    }

    [Fact]
    public void Every_asset_includes_all_baseline_categories()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.All(baseline.Assets, asset =>
            Assert.Equal(8, asset.EffectiveCategoryIds(baseline.Categories).Count));
    }
}
```

- [ ] **Step 2: Run tests and observe missing schema/domain types**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~BaselinePolicyTests
```

Expected: FAIL because rule types and baseline fixture do not exist.

- [ ] **Step 3: Define closed rule records**

```csharp
public enum FindingKind { SensitiveContent, AssetCompliance }
public enum Severity { Critical, High, Medium, Low, Info }
public enum DetectionConfidence { High, Medium, Low }

public sealed record RuleDefinition(
    RuleId Id,
    CategoryId CategoryId,
    FindingKind FindingKind,
    Severity Severity,
    DetectionConfidence Confidence,
    DetectorId DetectorId,
    string DetectorConfigId,
    IReadOnlySet<AssetTypeId> AppliesToAssets,
    bool RequiresSemanticReview,
    bool Enabled);

public sealed record DetectorDefinition(
    DetectorId Id,
    DetectorKind Kind,
    string ConfigId,
    IReadOnlyDictionary<string, string> Parameters,
    int MaxMatchesPerChunk);

public enum DetectorKind
{
    KnownFormat, Checksum, StructuredField, NetworkAddress, Dictionary,
    EntropyWithContext, LicenseFingerprint, ContentFingerprint, SemanticCandidate
}
```

Validate ID formats (`RULE-[A-Z0-9-]{3,64}`, `DET-[A-Z0-9-]{3,64}`), max 100,000 rules, max 10,000 detectors, max 1,000 parameters/detector, no dangling category/detector/asset references, and no duplicate IDs under ordinal comparison.

- [ ] **Step 4: Normalize the source Excel semantics into baseline JSON**

Create the eight category labels and eleven asset policies exactly as the SRS registry. Every asset policy includes the implicit baseline and only adds focus weights/compliance rules. Encode:

- `ASSET-007`: knowledge-base transformation evidence; missing evidence = `Unverifiable` compliance finding;
- `ASSET-008`: base-model/fine-tune evidence; missing evidence = `Unverifiable`, never infer weights;
- `ASSET-011`: Docker/OCI config/history/all-layer focus and restricted-entity weight;
- other assets: SRS-specific focus areas without baseline suppression.

Do not put real restricted bank/customer/person/internal-product entries in repository baseline. Those live in signed internal rule packages. Repository fixtures use labels such as `RESTRICTED_ENTITY_ALPHA`.

- [ ] **Step 5: Add JSON contract tests**

Tests load all schemas/documents with strict `System.Text.Json` options, reject unknown/duplicate properties, oversized strings/arrays, invalid IDs, disabled/missing category, missing detector, conflicting severity, local weakening, and non-deterministic order. Serialize→deserialize→serialize must produce identical UTF-8 bytes after canonical normalization.

- [ ] **Step 6: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Rules
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter FullyQualifiedName~RuleSchema
git add src/SecurityReview.Domain/Rules src/SecurityReview.RulePack/Schema src/SecurityReview.RulePack/Validation rules tests/SecurityReview.UnitTests/Rules tests/SecurityReview.ContractTests/Rules
git commit -m "feat: define mandatory rule and asset policy baseline"
```

## Task P3-T2: Build the Excel-to-signed-rule-package CLI

**Files:**
- Create: `rules/templates/security-review-rules-template.xlsx`
- Create: `tools/SecurityReview.RulePackBuilder/Program.cs`
- Create: `tools/SecurityReview.RulePackBuilder/Commands/BuildRulePackCommand.cs`
- Create: `tools/SecurityReview.RulePackBuilder/Excel/RuleWorkbookReader.cs`
- Create: `tools/SecurityReview.RulePackBuilder/Excel/WorkbookCellReader.cs`
- Create: `src/SecurityReview.RulePack/Normalization/RulePackNormalizer.cs`
- Create: `src/SecurityReview.RulePack/Packaging/RulePackManifest.cs`
- Create: `src/SecurityReview.RulePack/Packaging/RulePackWriter.cs`
- Create: `src/SecurityReview.RulePack/Signing/EcdsaRulePackSigner.cs`
- Create: `tests/SecurityReview.ContractTests/Rules/RuleWorkbookContractTests.cs`
- Create: `tests/SecurityReview.ContractTests/Rules/RulePackageSignatureTests.cs`
- Create: `tests/SecurityReview.ContractTests/Rules/Fixtures/generate-rule-workbooks.ps1`

**Interfaces:**
- Consumes: P3-T1 schemas and validators.
- Produces: `security-review-rules-<version>.zip`, `RulePackManifest`, signature contract, and CLI exit codes used by rule release.

- [ ] **Step 1: Freeze workbook sheets and columns**

The template contains these sheets and exact headers:

```text
规则包信息: 键,值
敏感类别: 类别ID,名称,说明,默认严重度,启用
资产专项规则: 规则ID,资产ID,类别ID,发现类型,检测器ID,配置ID,严重度,置信度,需要语义复核,启用,说明
受限实体词典: 词典ID,实体ID,标准名称,变体,类别ID,严重度,资产范围,有效起始,有效结束
安全占位符: 占位符ID,匹配类型,值,允许上下文,类别ID,有效起始,有效结束
检测器配置: 检测器ID,类型,配置ID,参数JSON,最大每块命中数
第三方授权: 授权ID,来源名称,标识或指纹,许可说明,证据引用,有效起始,有效结束
合规规则: 规则ID,资产ID,证据字段,缺失结论,严重度,说明
```

`规则包信息` requires `rulePackId`, `version`, `schemaVersion=1`, `minClientVersion`, `createdAtUtc`, `signerKeyId`, and `changeSummary`. Formula cells, external links, macros, hidden sheets, unexpected sheets/headers, merged data cells, and duplicate headers cause validation failure. Text cells remain literal.

- [ ] **Step 2: Write valid/invalid workbook tests**

Generate in-memory/workbook fixtures for valid minimal, missing sheet/header, formula, external link, macro part, invalid JSON parameter, duplicate ID, dangling reference, category disabled, semantic version invalid, time range invalid, unsafe regex config, and version rollback. Assertions include sheet/row/column error location without cell value.

- [ ] **Step 3: Implement bounded workbook reading**

Open read-only with Open XML SDK, preflight ZIP/package size/part count, read shared/inline strings only, require ≤100,000 data rows/sheet and ≤4,096 characters/cell, parse booleans/enums/timestamps with invariant culture, reject formulas even when cached values exist, and never resolve external relationships.

Return `WorkbookValidationError(code,sheet,row,column)`; never include restricted entity or credential values in errors/logs.

- [ ] **Step 4: Canonicalize package files and manifest**

`RulePackNormalizer` sorts objects by ordinal stable ID and dictionary keys by ordinal, writes UTF-8 without BOM or indentation, and normalizes timestamps to UTC `O`. `RulePackWriter` creates only:

```text
manifest.json
signature.json
categories.json
assets.json
detectors.json
dictionaries/entities.json
placeholders.json
licenses.json
compliance.json
```

Manifest fields are schemaVersion, rulePackId, version, minClientVersion, createdAtUtc, signerKeyId, and sorted `files[{path,sha256,size}]`. ZIP entries use optimal compression, fixed UTC timestamp `1980-01-01T00:00:00Z`, normalized names, no duplicate or extra entry.

- [ ] **Step 5: Sign exact manifest bytes with an external key**

CLI syntax:

```powershell
dotnet run --project tools/SecurityReview.RulePackBuilder -c Release -- build `
  --input rules/templates/security-review-rules-template.xlsx `
  --output artifacts/rules/security-review-rules-1.0.0.zip `
  --private-key-path $env:SECURITY_REVIEW_RULE_SIGNING_KEY `
  --expected-signer rules-team-prod-01
```

Require the private-key path from an explicit argument/environment, verify ACL/readability, import ECDSA P-256 PEM, sign SHA-256 over the exact `manifest.json` UTF-8 bytes using `DSASignatureFormat.IeeeP1363FixedFieldConcatenation`, and write algorithm `ECDSA_P256_SHA256_P1363`, signer key ID, and the fixed 64-byte signature as base64. Do not copy the key, print its path, log key errors beyond stable codes, or keep it after process exit. Test keys are generated at test runtime.

- [ ] **Step 6: Add signature and tamper tests**

Verify a valid package; then independently mutate each normalized JSON byte, manifest byte, signature byte, entry size, entry name/case, duplicate entry, signer ID, and package extra file. Every mutation must fail with a stable validation code. Building twice from the same normalized workbook/time must produce byte-identical canonical JSON and `manifest.json`; both packages must verify. Do **not** require the final signed ZIP bytes to match because standard ECDSA signing may use a fresh nonce and .NET does not promise deterministic signatures.

- [ ] **Step 7: Run and commit**

```powershell
pwsh tests/SecurityReview.ContractTests/Rules/Fixtures/generate-rule-workbooks.ps1
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter "FullyQualifiedName~RuleWorkbook|FullyQualifiedName~RulePackageSignature"
git add rules/templates tools/SecurityReview.RulePackBuilder src/SecurityReview.RulePack/Normalization src/SecurityReview.RulePack/Packaging src/SecurityReview.RulePack/Signing tests/SecurityReview.ContractTests/Rules
git commit -m "feat: build canonical ECDSA-signed rule packages"
```

## Task P3-T3: Validate, import, activate, and merge effective policy

**Files:**
- Create: `src/SecurityReview.Application/Rules/ImportRulePackCommand.cs`
- Create: `src/SecurityReview.Application/Rules/IRulePackStore.cs`
- Create: `src/SecurityReview.Application/Rules/IRulePackValidator.cs`
- Create: `src/SecurityReview.Application/Rules/IEffectivePolicyProvider.cs`
- Create: `src/SecurityReview.Application/Rules/RulePackImportService.cs`
- Create: `src/SecurityReview.RulePack/Validation/RulePackageValidator.cs`
- Create: `src/SecurityReview.RulePack/Signing/TrustedSignerStore.cs`
- Create: `src/SecurityReview.RulePack/Policy/EffectivePolicy.cs`
- Create: `src/SecurityReview.RulePack/Policy/EffectivePolicyBuilder.cs`
- Create: `src/SecurityReview.Infrastructure/Rules/FileRulePackStore.cs`
- Create: `src/SecurityReview.Desktop/Assets/rules/trusted-signers.json`
- Create: `tests/SecurityReview.UnitTests/Rules/EffectivePolicyBuilderTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Rules/RulePackImportTests.cs`

**Interfaces:**
- Consumes: signed packages and trusted public keys.
- Produces: atomic active package, immutable historical packages, `IEffectivePolicyProvider.BuildAsync`, policy SHA-256 and import validation summary.

- [ ] **Step 1: Write package import transaction tests**

Cases: valid new package activates; invalid signature/hash/schema/reference leaves previous active unchanged; incompatible `minClientVersion` rejected; newer activates; lower version requires explicit `AllowDowngrade=true` and remains visibly old; package with same ID/version but different hash rejected; interrupted temp copy recovers; local additive file cannot weaken baseline.

- [ ] **Step 2: Implement validation order and trusted signer store**

Validation order is ZIP path/limits → manifest schema → exact entry allowlist → size/hash → signer key allowlist → ECDSA signature → client/schema/version → graph/baseline/detector safety → package summary. Before materialization require compressed package ≤256 MiB, exactly the allowlisted entries, total declared uncompressed bytes ≤1 GiB, each declared size equal to manifest size, and all reads bounded by those values. Embed only public JWK/PEM and signer ID in `trusted-signers.json`; validate its release hash at startup.

- [ ] **Step 3: Implement atomic file store**

Stage under `%LOCALAPPDATA%\SecurityReviewTool\rules\staging\<random>`, after creating/revalidating every parent as an ordinary non-reparse directory with current-user-only ACL. Validate, flush, move to `packages/<rulePackId>/<version>/<sha256>.zip`, mark historical packages read-only, then atomically replace an `active.json` pointer containing ID/version/hash. On failure delete staging and retain the previous pointer. Rule/entity/placeholder values never enter logs/diagnostics. P4 later records metadata in SQLite but does not change this file-level atomicity.

- [ ] **Step 4: Write non-weakening merge tests**

For each asset and unknown asset, assert all 8 categories and baseline rules remain. Attempt local changes that disable rule/category, lower severity, change detector, broaden placeholder, change compliance result, or remove entity; reject the entire local supplement. Additive new entity/rule with equal-or-higher severity succeeds and changes policy SHA-256.

- [ ] **Step 5: Implement deterministic effective policy**

`EffectivePolicyBuilder` merges signed baseline + selected asset additions + compliance rules + local additive entries. It normalizes/sorts all entries and computes SHA-256 over canonical JSON containing package hash, local supplement hash, asset IDs, detector versions, parser-policy limits and conclusion policy. Return warnings for non-latest signed package and presence of local additions.

- [ ] **Step 6: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~EffectivePolicy
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~RulePackImport
git add src/SecurityReview.Application/Rules src/SecurityReview.RulePack/Validation src/SecurityReview.RulePack/Signing src/SecurityReview.RulePack/Policy src/SecurityReview.Infrastructure/Rules src/SecurityReview.Desktop/Assets tests/SecurityReview.UnitTests/Rules/EffectivePolicyBuilderTests.cs tests/SecurityReview.IntegrationTests/Rules/RulePackImportTests.cs
git commit -m "feat: atomically activate non-weakening rule policy"
```

## Task P3-T4: Implement detector pipeline, safe regex, checksums, fields, and entropy

**Files:**
- Create: `src/SecurityReview.Domain/Findings/DetectionCandidate.cs`
- Create: `src/SecurityReview.RulePack/Detection/IDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/DetectorPipeline.cs`
- Create: `src/SecurityReview.RulePack/Detection/KnownFormatDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/SafeRegexFactory.cs`
- Create: `src/SecurityReview.RulePack/Detection/ChecksumDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/StructuredFieldDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/EntropyContextDetector.cs`
- Create: `tests/SecurityReview.UnitTests/Detection/SafeRegexFactoryTests.cs`
- Create: `tests/SecurityReview.UnitTests/Detection/ChecksumDetectorTests.cs`
- Create: `tests/SecurityReview.UnitTests/Detection/DetectorPipelineTests.cs`

**Interfaces:**
- Consumes: `ContentChunk` and `EffectivePolicy`.
- Produces: ordered `DetectionCandidate` stream with value/context/locator/rule/detector/severity/confidence and semantic-review flag.

- [ ] **Step 1: Write detector-order and failure tests**

Use synthetic chunks/rules to assert fixed stage order: structured field → known format → checksum → network → dictionary → entropy/context → license/fingerprint → placeholder evaluation → semantic candidate. A detector exception creates a detector coverage gap and does not treat candidates as safe. Cancellation stops after the current bounded detector operation.

Test the shared candidate factory at exact boundaries: value 1–5,000 UTF-16 code units, context 0–5,000, valid locator inside the chunk, and no unpaired surrogate. An oversized logical detector match is not silently truncated; emit `candidate_match_over_limit` with the original source range and keyed value HMAC (never a raw isolated-value hash), then mark that region partially covered. The 5,000-code-unit cap also guarantees that worst-case six-character JSON escaping remains below Excel's 32,767-character cell limit, so every stored “完整命中值” is complete for the supported candidate.

- [ ] **Step 2: Implement safe regex compilation and import rejection**

`SafeRegexFactory` accepts a pattern only when it compiles with `RegexOptions.CultureInvariant | RegexOptions.NonBacktracking`, timeout 100 ms, maximum length 4,096, and no unsupported backreference/lookaround/conditional/balancing construct. Reject invalid patterns during package import. Built-in audited exceptions must live in code, use a 25 ms timeout, and have a dedicated worst-case complexity test; signed packages cannot create exceptions.

- [ ] **Step 3: Implement known formats and checksum validators**

Implement detector interfaces for generic token prefixes/private-key header structure, Chinese ID checksum/date/region shape using synthetic region codes, Luhn account/card candidates, phone format, and signed policy-provided patterns. Format hits without checksum/context remain lower confidence; valid checksum elevates confidence but severity comes from policy. Never log rejected values.

- [ ] **Step 4: Implement structured fields and entropy-with-context**

`StructuredFieldDetector` uses parser-provided property/header/metadata path, not text regex alone, and matches normalized signed key dictionaries (`password`, `token`, `secret`, equivalents). `EntropyContextDetector` considers only bounded token-like sequences 16–512 characters, computes Shannon entropy, and requires a signed nearby credential context unless policy explicitly defines a strong format. Ignore binary chunks already covered by known format to avoid duplicate raw entropy noise.

- [ ] **Step 5: Preserve locator across chunk overlap**

Map match character ranges through `LocationMapEntry`; reject out-of-range worker locators; normalize overlap candidates to the original source range. Pipeline dedup key is file ID + virtual path + source locator + rule ID + detector ID, so one boundary hit appears once.

- [ ] **Step 6: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Detection
git add src/SecurityReview.Domain/Findings src/SecurityReview.RulePack/Detection tests/SecurityReview.UnitTests/Detection
git commit -m "feat: run deterministic bounded detector pipeline"
```

## Task P3-T5: Implement IP/domain, entity dictionaries, placeholders, and third-party detectors

**Files:**
- Create: `src/SecurityReview.RulePack/Detection/NetworkAddressDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/AhoCorasickMatcher.cs`
- Create: `src/SecurityReview.RulePack/Detection/RestrictedEntityDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/ApprovedPlaceholderMatcher.cs`
- Create: `src/SecurityReview.RulePack/Detection/LicenseFingerprintDetector.cs`
- Create: `src/SecurityReview.RulePack/Detection/ContentFingerprintDetector.cs`
- Create: `tests/SecurityReview.UnitTests/Detection/NetworkAddressDetectorTests.cs`
- Create: `tests/SecurityReview.UnitTests/Detection/DictionaryAndPlaceholderTests.cs`
- Create: `tests/SecurityReview.UnitTests/Detection/ThirdPartyDetectorTests.cs`

**Interfaces:**
- Consumes: signed dictionaries/placeholders/licenses and chunks.
- Produces: SENS-002/003/004/008 and restricted-entity candidates with exact match provenance and bounded wording.

- [ ] **Step 1: Write comprehensive network classification tests**

Cover IPv4/IPv6, CIDR, bracketed host, URL/host/port, RFC1918, loopback, link-local, multicast, documentation ranges, public addresses, invalid octets/prefixes, version-like numbers, approved example addresses, and surrounding punctuation. Assert private/public/example classification and that all non-approved private/public addresses are candidates with policy-specific category/severity.

- [ ] **Step 2: Implement parsed network detection**

Use `IPAddress.TryParse`, explicit CIDR parsing, `Uri.TryCreate` only after bounded tokenization, and signed domain suffix/context policy. Do not perform DNS, WHOIS, HTTP, reachability, reverse lookup, or network classification by live environment. Approved examples are exact IP/CIDR/domain entries in the signed placeholder set.

- [ ] **Step 3: Write dictionary/placeholder precedence tests**

Test standard name, abbreviation, former name, case/width variant, overlapping entities, Chinese/Latin boundary, 1 MiB chunk boundary, expired entity, asset scope, exact placeholder context, expired placeholder, and “looks fake” but unapproved value. Approved placeholder can annotate only the exact rule/category/context scope; it cannot suppress a restricted-entity hit unless the signed entry explicitly covers that rule.

- [ ] **Step 4: Implement linear multi-pattern matching**

Build immutable Aho-Corasick automatons per normalized matching mode at policy load. Normalize a comparison copy using Unicode NFKC and policy-controlled case folding while retaining an index map to original characters. Bound one effective policy to 100,000 normalized terms, 32 MiB total normalized UTF-8 term bytes, 512 characters per term, and a validated estimated automaton footprint of 128 MiB; reject the package before allocation when any bound is exceeded. Bound output matches per chunk to detector policy max. Resolve overlap by preserving all distinct entity/rule IDs, then group later.

- [ ] **Step 5: Implement placeholder annotation, not deletion**

`ApprovedPlaceholderMatcher` returns `PlaceholderDisposition.ApprovedExample` with placeholder ID, rule/category/context, version and expiry. `DetectorPipeline` retains the underlying candidate/provenance but marks it approved-example for policy conclusion. Unapproved values remain candidates. Expired placeholders are ignored and surfaced in rule diagnostics.

- [ ] **Step 6: Implement third-party license/fingerprint wording**

Match bounded license/copyright/SPDX/vendor markers and signed content fingerprints. Compare authorization IDs/time/asset scope from Manifest and rule package. Without a matching authorization, emit SENS-008 with `RequiresManualVerification=true` and conclusion key `suspected_restricted_third_party_content`; never set a legal/infringement boolean.

- [ ] **Step 7: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter "FullyQualifiedName~NetworkAddress|FullyQualifiedName~Dictionary|FullyQualifiedName~ThirdParty"
git add src/SecurityReview.RulePack/Detection tests/SecurityReview.UnitTests/Detection
git commit -m "feat: detect network entities placeholders and third-party markers"
```

## Task P3-T6: Merge candidates, preserve provenance, and calculate bounded conclusions

**Files:**
- Create: `src/SecurityReview.Domain/Findings/FindingGroup.cs`
- Create: `src/SecurityReview.Domain/Findings/FindingOccurrence.cs`
- Create: `src/SecurityReview.Domain/Findings/FindingProvenance.cs`
- Create: `src/SecurityReview.Application/Abstractions/IValueFingerprintService.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/EphemeralValueFingerprintService.cs`
- Create: `src/SecurityReview.Application/Findings/CandidateMerger.cs`
- Create: `src/SecurityReview.Application/Findings/ConclusionCalculator.cs`
- Create: `tests/SecurityReview.UnitTests/Findings/CandidateMergerTests.cs`
- Create: `tests/SecurityReview.UnitTests/Findings/ConclusionCalculatorTests.cs`

**Interfaces:**
- Consumes: candidates, coverage summary, policy fingerprint, and keyed value-fingerprint port.
- Produces: UI/report-ready groups/occurrences, independent severity/confidence, detector trail, and bounded scan conclusion.

- [ ] **Step 1: Write grouping and provenance tests**

Same value at three locations becomes one group with three occurrences; different normalized values never merge; same location/rule from chunk overlap becomes one occurrence; two detectors/rules at one location preserve both provenance entries; severity takes policy maximum while confidence remains independently derived; approved-example disposition remains visible.

- [ ] **Step 2: Define keyed fingerprint service and ephemeral implementation**

```csharp
public interface IValueFingerprintService
{
    ValueFingerprint Compute(ReadOnlySpan<char> normalizedValue);
}
```

`EphemeralValueFingerprintService` generates a random 32-byte HMAC key per process, normalizes only detector-approved whitespace/case rules, computes HMAC-SHA256 over UTF-8, clears temporary bytes, and disposes/zeros the key. P4 replaces it with the DPAPI-backed per-user key for persistent grouping; no code stores raw SHA-256 of a value.

- [ ] **Step 3: Implement occurrence/group identifiers**

Occurrence key is scan ID + file SHA-256 + virtual path + canonical locator + rule ID + value HMAC. Group key is scan ID + category + value HMAC. IDs are UUIDv5 of those keys. Preserve complete raw value/context only in the occurrence object for immediate encryption/display; `ToDiagnosticRecord` exposes IDs/category/severity/count only.

- [ ] **Step 4: Write bounded conclusion tests**

Cases: zero findings/all covered → `NoRiskFoundWithinSuccessfulCoverage`; findings/all covered → `RisksFound`; any gap/exclusion/encryption/unstable/unresolved semantic/cancel → `Incomplete`; task-level integrity failure → `Failed`. No enum/text contains `Safe`, `Guaranteed`, or `ApprovedForRelease`.

- [ ] **Step 5: Implement calculator and localization keys**

`ConclusionCalculator` accepts scan status, coverage summary, unresolved semantic count and finding counts. It returns enum plus Chinese resource key. Desktop/report later render exactly “在本次成功覆盖范围内未发现风险” for the zero/all-covered case and an explicit coverage-gap count for incomplete.

- [ ] **Step 6: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Findings
git add src/SecurityReview.Domain/Findings src/SecurityReview.Application/Abstractions/IValueFingerprintService.cs src/SecurityReview.Infrastructure/Cryptography/EphemeralValueFingerprintService.cs src/SecurityReview.Application/Findings tests/SecurityReview.UnitTests/Findings
git commit -m "feat: group findings with complete provenance and bounded conclusions"
```

## Task P3-T7: Establish deterministic rule-release corpus gates

**Files:**
- Create: `tests/Corpus/Rules/rule-corpus-manifest.schema.json`
- Create: `tests/Corpus/Rules/rule-corpus-manifest.json`
- Create: `tests/Corpus/Rules/generate-rule-corpus.ps1`
- Create: `tools/SecurityReview.CorpusTool/Commands/VerifyRuleCorpusCommand.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Rules/RuleCorpusTests.cs`
- Create: `docs/operations/rule-pack-release.md`

**Interfaces:**
- Consumes: signed package builder, parser corpus chunks, detector pipeline, candidate merger.
- Produces: 100% deterministic high-risk positive gate, negative/false-positive metrics, and package release evidence.

- [ ] **Step 1: Define rule expectation manifest**

Each case records synthetic input generator/seed, asset types, format/locator, rule package hash, expected rule/detector/category/severity/confidence, approved-example disposition, minimum/maximum occurrence count, and expected absence IDs. Include every enabled baseline detector/rule plus asset compliance, network, restricted entity, placeholder, third-party and cross-chunk cases.

- [ ] **Step 2: Add corpus integrity and coverage tests**

Tests require every enabled deterministic rule to have at least one positive and one negative case; every Critical/High rule has a positive exact-location expectation; every placeholder has approved and near-miss cases; all eight categories and eleven assets appear. No case contains real secrets/entities.

- [ ] **Step 3: Implement verification command**

```powershell
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- verify-rule-corpus `
  --rules artifacts/rules/security-review-rules-1.0.0.zip `
  --manifest tests/Corpus/Rules/rule-corpus-manifest.json `
  --output artifacts/corpus/rule-results.json
```

The command runs real parsers/detectors, compares candidate IDs/provenance/locations, and outputs aggregate counts only. Exit 1 on any missing Critical/High expected hit, unexpected placeholder suppression, detector error, missing provenance, or coverage gap not declared by the case.

- [ ] **Step 4: Document the release procedure**

`rule-pack-release.md` specifies two-person review, workbook validation, package build, signature verification on a clean machine, corpus command, diff summary, public-key/signer check, SHA-256 publication, old-version retention, client compatibility and rollback procedure. It forbids emailing private keys or placing them in environment files under the repo.

- [ ] **Step 5: Run P3 gate and commit**

```powershell
pwsh tests/Corpus/Rules/generate-rule-corpus.ps1
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~RuleCorpus
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- verify-rule-corpus --rules artifacts/rules/security-review-rules-1.0.0.zip --manifest tests/Corpus/Rules/rule-corpus-manifest.json --output artifacts/corpus/rule-results.json
git add tests/Corpus/Rules tools/SecurityReview.CorpusTool tests/SecurityReview.ParserCorpusTests/Rules docs/operations/rule-pack-release.md
git commit -m "test: block rule releases on deterministic corpus regressions"
```

P3 completes only when the enabled signed package passes the full deterministic corpus with 100% expected Critical/High detections and no unauthorized placeholder suppression.
