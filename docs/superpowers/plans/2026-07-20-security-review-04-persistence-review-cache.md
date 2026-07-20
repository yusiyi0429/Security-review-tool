# Security Review P4 Encrypted Persistence Review and Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist scans, complete findings, coverage, reviews, exceptions, and strict caches locally without plaintext leakage; recover safely from interruption; enforce retention; and calculate trustworthy rescan differences.

**Architecture:** Infrastructure uses explicit SQL over Microsoft.Data.Sqlite and forward-only embedded migrations. Sensitive payloads are encrypted before repository calls with AES-256-GCM; the data key is DPAPI CurrentUser-protected and a separate derived HMAC key produces non-reversible matching fingerprints. Review and exception history is append-only, while cache reuse requires complete stage fingerprints.

**Tech Stack:** Microsoft.Data.Sqlite 10.0.10, System.Security.Cryptography.ProtectedData 10.0.10, AES-GCM, HMAC-SHA256/HKDF-SHA256, Windows ACLs, xUnit.net v3.

## Global Constraints

- Store data under `%LOCALAPPDATA%\SecurityReviewTool`; never beside the executable or input assets.
- Encrypt complete values, context, paths, Manifest business fields, review reasons, LLM rationale/response details, and cache payloads before SQLite.
- A fresh 12-byte nonce is mandatory for every AES-GCM payload; AAD binds schema/table/record/field; 16-byte tag failure rejects data.
- DPAPI scope is CurrentUser. The design does not claim protection from the current user, administrator, debugger, or machine compromise.
- SQLite enables foreign keys, WAL, and busy timeout. Migrations are forward-only, transactional, and backed up before upgrade.
- Default retention is 90 days; allowed settings are 30, 90, 180 days, or permanent; one-click clear is irreversible and explicit.
- Historical scans are never overwritten. Review/exception events are append-only.
- A file/parser/rule/detector/prompt/model/endpoint change invalidates the corresponding cache stage and all downstream stages.

---

## Task P4-T1: Create application paths, SQLite connection, and migrations

**Files:**
- Create: `src/SecurityReview.Infrastructure/Persistence/AppDataPaths.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/SqliteConnectionFactory.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Migrations/IMigration.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Migrations/MigrationRunner.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Migrations/Migration001Initial.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/DatabaseHealthCheck.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/MigrationTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/DatabasePragmaTests.cs`

**Interfaces:**
- Consumes: domain IDs/status/enums from P0–P3.
- Produces: `AppDataPaths`, `ISqliteConnectionFactory.OpenAsync`, schema version 1, migration/health results, and tables used by all repositories.

- [ ] **Step 1: Write migration-from-empty and idempotence tests**

```csharp
[Fact]
public async Task Migration_creates_schema_once_and_is_idempotent()
{
    await _runner.MigrateAsync(_databasePath, CancellationToken.None);
    await _runner.MigrateAsync(_databasePath, CancellationToken.None);
    Assert.Equal(1, await _fixture.ReadSchemaVersionAsync());
    Assert.Equal(ExpectedTables.All, await _fixture.ReadUserTablesAsync());
}

[Fact]
public async Task Connection_enables_required_pragmas()
{
    await using var connection = await _factory.OpenAsync(CancellationToken.None);
    Assert.Equal(1L, await ScalarAsync<long>(connection, "PRAGMA foreign_keys;"));
    Assert.Equal("wal", (await ScalarAsync<string>(connection, "PRAGMA journal_mode;")).ToLowerInvariant());
    Assert.True(await ScalarAsync<long>(connection, "PRAGMA busy_timeout;") >= 5000);
}
```

- [ ] **Step 2: Run tests and observe missing persistence types**

```powershell
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter "FullyQualifiedName~Migration|FullyQualifiedName~DatabasePragma"
```

Expected: FAIL because database classes do not exist.

- [ ] **Step 3: Implement deterministic application paths**

`AppDataPaths.CreateDefault()` resolves `Environment.SpecialFolder.LocalApplicationData`, appends `SecurityReviewTool`, and exposes `Config`, `Data`, `Rules`, `Temp`, `Diagnostics`, `Backups`, `DatabaseFile`, and `KeyRingFile`. `EnsureCreated` creates directories with current-user-only ACL and rejects reparse points in any parent/created directory. Tests inject a temporary base path; no test writes real user app data.

- [ ] **Step 4: Implement connection factory**

Use connection string `Data Source=<db>;Mode=ReadWriteCreate;Cache=Shared;Pooling=True;Default Timeout=5`. Every opened connection executes:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA temp_store = MEMORY;
```

Do not place secrets in connection strings or enable SQL tracing with parameter values.

- [ ] **Step 5: Implement schema version 1 in one transaction**

Create these tables with `TEXT` UUIDs, UTC timestamps, `INTEGER` enums/version counters, foreign keys, and checks:

```text
schema_versions(version PK, applied_at_utc, client_build)
scan_runs(scan_id PK, status, created_at_utc, updated_at_utc, rule_pack_hash, client_version,
          pipeline_fingerprint, planned_units, version, encrypted_summary)
assets(asset_row_id PK, scan_id FK, manifest_hash, asset_id_hmac, encrypted_payload)
file_records(file_id PK, scan_id FK, path_hmac, content_sha256, size, format_id, coverage_status,
             parser_fingerprint, encrypted_payload)
finding_groups(group_id PK, scan_id FK, value_hmac, category_id, severity, confidence, difference_status)
finding_occurrences(occurrence_id PK, group_id FK, file_id FK, rule_id, detector_id,
                    requires_semantic_review, encrypted_payload)
coverage_gaps(gap_id PK, scan_id FK, file_id nullable FK, stage, reason, detail_code,
              planned_bytes, processed_bytes, encrypted_payload)
llm_reviews(review_id PK, scan_id FK, candidate_id, cache_key, status, endpoint_fingerprint,
            model_id, prompt_version, attempted_at_utc, encrypted_payload)
review_decisions(decision_id PK, scan_id FK, group_id nullable FK, occurrence_id nullable FK,
                 status, user_sid_hmac, decided_at_utc, encrypted_payload)
exception_grants(exception_id PK, asset_binding_hmac, occurrence_binding_hmac, rule_pack_hash,
                 valid_until_utc, created_at_utc, user_sid_hmac, encrypted_payload)
rule_packs(rule_pack_hash PK, rule_pack_id, version, signer_id, imported_at_utc, status, package_path_hmac)
cache_entries(cache_key PK, stage, created_at_utc, last_used_at_utc, source_scan_id, encrypted_payload)
diagnostic_events(event_id PK, scan_id nullable FK, event_code, occurred_at_utc, count_value,
                  duration_ms, redacted_fields_json)
```

Indexes: scan status/time, files by scan/path HMAC and content hash, groups by scan/value HMAC/category, occurrences by group/file, gaps by scan/reason, reviews by candidate/cache key, decisions by group/occurrence/time, exceptions by binding/expiry, cache by stage/last-used. No index contains plaintext path/value/context/reason.

- [ ] **Step 6: Implement migration runner and health check**

Acquire a named mutex per database path, checkpoint WAL, copy DB/keyring metadata to `backups/<timestamp>` before any version increase, run each migration transaction, insert schema version after successful DDL, and delete backup only after health checks. On failure roll back, leave original intact, and return read-only-history mode.

Health check runs `PRAGMA quick_check`, schema version compatibility, foreign key check, and a write/delete canary transaction. It returns stable codes only.

- [ ] **Step 7: Run and commit**

```powershell
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter "FullyQualifiedName~Migration|FullyQualifiedName~Database"
git add src/SecurityReview.Infrastructure/Persistence tests/SecurityReview.IntegrationTests/Persistence
git commit -m "feat: establish local SQLite schema and safe migrations"
```

## Task P4-T2: Implement DPAPI keyring, AES-GCM payloads, and HMAC fingerprints

**Files:**
- Create: `src/SecurityReview.Application/Abstractions/IPayloadProtector.cs`
- Create: `src/SecurityReview.Application/Abstractions/ISecretStore.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/KeyRingDocument.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/WindowsDpapiKeyRing.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/HkdfSha256.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/AesGcmPayloadProtector.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/PersistentValueFingerprintService.cs`
- Create: `src/SecurityReview.Infrastructure/Cryptography/WindowsDpapiSecretStore.cs`
- Create: `tests/SecurityReview.UnitTests/Cryptography/HkdfSha256Tests.cs`
- Create: `tests/SecurityReview.UnitTests/Cryptography/AesGcmPayloadProtectorTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Cryptography/DpapiKeyRingTests.cs`

**Interfaces:**
- Consumes: `AppDataPaths` and `IValueFingerprintService` from P3.
- Produces: `IPayloadProtector.Protect/Unprotect`, persistent keyed HMAC fingerprinting, and named DPAPI secrets for LLM credentials.

- [ ] **Step 1: Write crypto round-trip, uniqueness, AAD, and tamper tests**

```csharp
[Fact]
public void Same_plaintext_has_different_ciphertext_and_round_trips()
{
    byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
    EncryptedPayload first = _protector.Protect("finding_occurrences", "id-1", "payload", plaintext);
    EncryptedPayload second = _protector.Protect("finding_occurrences", "id-1", "payload", plaintext);
    Assert.NotEqual(first.NonceBase64, second.NonceBase64);
    Assert.NotEqual(first.CiphertextBase64, second.CiphertextBase64);
    Assert.Equal(plaintext, _protector.Unprotect("finding_occurrences", "id-1", "payload", first));
}

[Fact]
public void Wrong_record_or_mutated_tag_is_rejected()
{
    EncryptedPayload payload = _protector.Protect("t", "a", "f", "x"u8);
    Assert.Throws<CryptographicException>(() => _protector.Unprotect("t", "b", "f", payload));
    Assert.Throws<CryptographicException>(() => _protector.Unprotect("t", "a", "f", payload with { TagBase64 = Convert.ToBase64String(new byte[16]) }));
}
```

- [ ] **Step 2: Run tests and observe missing protector**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Cryptography
```

Expected: FAIL because keyring/protector types do not exist.

- [ ] **Step 3: Implement DPAPI CurrentUser keyring**

On first use generate 32 random bytes and an 8-byte random key ID. Protect with `ProtectedData.Protect(data, optionalEntropy: null, DataProtectionScope.CurrentUser)`. Write JSON `{schema_version:1,key_id,protected_data_base64,created_at_utc}` to a random sibling file, flush to disk, atomically move to `keyring.json`, and set current-user-only ACL. On load reject reparse points, wrong owner/ACL, invalid schema/base64/DPAPI, duplicate file, or key length not 32.

Never regenerate automatically when an existing keyring cannot decrypt; doing so would make history silently unreadable. Return `keyring_unavailable` and open history read-only/unavailable.

- [ ] **Step 4: Derive independent encryption/HMAC keys**

Implement RFC 5869 HKDF-SHA256 with empty salt and fixed info strings `SecurityReviewTool/v1/encryption` and `SecurityReviewTool/v1/fingerprint`, output 32 bytes each. Validate with published RFC 5869 SHA-256 vectors. Keep master/derived keys in owned byte arrays, zero on disposal, and never expose via properties/logging.

- [ ] **Step 5: Implement versioned AES-GCM envelope**

```csharp
public sealed record EncryptedPayload(int Version, string KeyId, string NonceBase64,
    string CiphertextBase64, string TagBase64);
```

AAD UTF-8 is `v1|<table>|<record-id>|<field-name>`. Generate 12 random nonce bytes and 16-byte tag; use `AesGcm(key, 16)`. Bound plaintext to 16 MiB per payload; larger result collections are split into records, not a giant blob. Clear plaintext staging buffers and key material in `finally`.

- [ ] **Step 6: Implement keyed fingerprints and DPAPI named secrets**

`PersistentValueFingerprintService` uses the derived fingerprint key and HMAC-SHA256 over detector-approved normalized UTF-8. `WindowsDpapiSecretStore` protects each named credential independently with DPAPI CurrentUser and AAD-like optional entropy derived from the secret name; filenames are SHA-256 of the logical name, not endpoint/model/token text.

- [ ] **Step 7: Run Windows/offline plaintext checks and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Cryptography
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~Dpapi
rg -a "SYNTHETIC_CANARY" artifacts/crypto-test -g "*"; if ($LASTEXITCODE -eq 0) { throw "Plaintext canary leaked." }
git add src/SecurityReview.Application/Abstractions src/SecurityReview.Infrastructure/Cryptography tests/SecurityReview.UnitTests/Cryptography tests/SecurityReview.WindowsSecurityTests/Cryptography
git commit -m "security: encrypt local payloads with DPAPI-backed keys"
```

Expected: no plaintext canary in DB/WAL/keyring/cache fixture files; wrong user copy on a second Windows test account cannot DPAPI-unprotect.

## Task P4-T3: Implement encrypted scan, file, finding, coverage, and rule repositories

**Files:**
- Create: `src/SecurityReview.Application/Abstractions/IScanRepository.cs`
- Create: `src/SecurityReview.Application/Abstractions/IFileRepository.cs`
- Create: `src/SecurityReview.Application/Abstractions/IFindingRepository.cs`
- Create: `src/SecurityReview.Application/Abstractions/ICoverageRepository.cs`
- Create: `src/SecurityReview.Application/Abstractions/IRulePackMetadataRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteScanRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteFileRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteFindingRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteCoverageRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteRulePackMetadataRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/RepositoryTransaction.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/RepositoryRoundTripTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/RepositoryConcurrencyTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/PlaintextLeakTests.cs`

**Interfaces:**
- Consumes: P4-T1 connection/migrations, P4-T2 crypto, P0/P1/P3 domain objects.
- Produces: transactional encrypted storage and query projections consumed by orchestration/UI/reporting.

- [ ] **Step 1: Write round-trip and optimistic transition tests**

Persist a complete synthetic scan with asset, path, finding value/context/locator, gap detail and rule metadata; read it and assert semantic equality. Assert stored SQL text/blob columns do not contain canaries. Two concurrent `TryTransitionAsync(expectedVersion)` calls yield exactly one success. Foreign-key/delete violations fail transactionally.

- [ ] **Step 2: Define repository transaction boundary**

`RepositoryTransaction` owns one open connection/SQLite transaction. Stage commits are: scan created, inventory committed, each batch of ≤500 chunks/findings/gaps committed, semantic reviews committed, final status committed. A transaction never spans worker/HTTP/UI waits. On batch failure roll back the batch and transition task Failed if trusted evidence cannot be reconciled.

- [ ] **Step 3: Implement encrypted mapping**

Before SQL, serialize sensitive payload records with source-generated JSON, encrypt with table/record/field AAD, and store envelope JSON. Keep searchable fields to IDs/enums/counts/hashes/HMACs only. `path_hmac` and `value_hmac` come from keyed fingerprint services; `content_sha256` is acceptable because it hashes the whole file for integrity, not the isolated sensitive value.

Query projections decrypt only requested rows. List views return group counts/IDs/category/severity/confidence/status without complete values; details/export explicitly request occurrence payloads.

- [ ] **Step 4: Implement batched inserts and cancellation semantics**

Use prepared commands and parameters; never string-concatenate values. At cancellation, finish/rollback current batch, stop new batches, persist Cancelled with existing committed results. Mark all remaining planned units with cancellation gaps before terminal reconciliation when possible.

- [ ] **Step 5: Add WAL/DB offline canary scan**

After realistic inserts and updates, checkpoint WAL, close pools with `SqliteConnection.ClearAllPools`, recursively scan DB/WAL/SHM/backups/temp for complete value, context, path, review-reason and LLM-like canaries. Expect zero. Also mutate one encrypted payload byte directly and assert the repository returns `encrypted_payload_tampered`, never partial plaintext.

- [ ] **Step 6: Run and commit**

```powershell
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter "FullyQualifiedName~Repository|FullyQualifiedName~PlaintextLeak"
git add src/SecurityReview.Application/Abstractions src/SecurityReview.Infrastructure/Persistence/Repositories tests/SecurityReview.IntegrationTests/Persistence
git commit -m "feat: persist encrypted scan and finding history"
```

## Task P4-T4: Implement recovery, retention, cleanup, and clear-local-data

**Files:**
- Create: `src/SecurityReview.Application/History/RetentionPolicy.cs`
- Create: `src/SecurityReview.Application/History/RetentionService.cs`
- Create: `src/SecurityReview.Application/History/ClearLocalDataService.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/StartupRecoveryService.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/DatabaseBackupService.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/SqliteMaintenanceService.cs`
- Create: `tests/SecurityReview.UnitTests/History/RetentionPolicyTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/StartupRecoveryTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Persistence/ClearLocalDataTests.cs`

**Interfaces:**
- Consumes: repositories, app paths, keyring, scan state machine.
- Produces: startup recovery report, scheduled/user retention cleanup, and irreversible clear result consumed by Desktop settings/startup.

- [ ] **Step 1: Write fixed-clock retention tests**

Test 30/90/180/permanent at exact boundary instants, related findings/gaps/reviews/cache removal, newer history retention, package retention when referenced, manual one-scan delete, and cache last-used vs source history behavior. Permanent deletes nothing automatically.

- [ ] **Step 2: Implement startup recovery**

At startup, before new scan: acquire app mutex; run DB health; map Preflight/Running/Cancelling scans to Interrupted in one transaction; close/delete orphan task temp directories older than the current process start after verifying they are ordinary directories below app temp; checkpoint WAL; validate active rule pointer/keyring; return counts/codes. Never auto-resume an interrupted scan or mark it Completed.

- [ ] **Step 3: Implement retention and maintenance**

Delete expired scans and dependent rows transactionally in batches of 100; delete cache rows no longer referenced/within policy; preserve rule packages referenced by remaining scans; then WAL checkpoint. Run `VACUUM` only when no active scan/export, database free-page ratio exceeds 25%, and enough disk space exists for a copy; VACUUM failure is diagnostic, not data-loss recovery.

- [ ] **Step 4: Implement explicit clear-local-data order**

Require exact confirmation command carrying `Confirmed=true` and current scan count. Stop/deny when an active scan/export exists. Close pools; delete DB/WAL/SHM/backups/cache/temp/diagnostics/rules/credentials/keyring; remove AppContainer profile only after worker termination; recreate empty base directories only. Return each path category status without the path. A failure leaves a list of categories requiring manual retry.

Deleting the DPAPI-protected data key provides cryptographic erasure for encrypted payloads, but the UI/documentation must not claim forensic secure erase of SSD/filesystem remnants. Report “本工具本地数据已清除” only when every category deletion/key removal succeeds; otherwise show the failed categories and retry guidance.

- [ ] **Step 5: Test process-kill and migration restore**

Integration harness kills a child app during a committed batch, uncommitted batch, migration and temp parse. Next startup must preserve committed rows, discard uncommitted rows, mark scan Interrupted, restore pre-migration DB when migration failed, and clean only safe task temp.

- [ ] **Step 6: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Retention
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter "FullyQualifiedName~Recovery|FullyQualifiedName~ClearLocalData"
git add src/SecurityReview.Application/History src/SecurityReview.Infrastructure/Persistence tests/SecurityReview.UnitTests/History tests/SecurityReview.IntegrationTests/Persistence
git commit -m "feat: recover and retain encrypted local history safely"
```

## Task P4-T5: Implement review decisions and exact expiring exceptions

**Files:**
- Create: `src/SecurityReview.Domain/Reviews/ReviewStatus.cs`
- Create: `src/SecurityReview.Domain/Reviews/ReviewDecision.cs`
- Create: `src/SecurityReview.Domain/Reviews/ExceptionBinding.cs`
- Create: `src/SecurityReview.Domain/Reviews/ExceptionGrant.cs`
- Create: `src/SecurityReview.Application/Reviews/RecordReviewCommand.cs`
- Create: `src/SecurityReview.Application/Reviews/GrantExceptionCommand.cs`
- Create: `src/SecurityReview.Application/Reviews/IReviewService.cs`
- Create: `src/SecurityReview.Application/Reviews/ReviewService.cs`
- Create: `src/SecurityReview.Application/Abstractions/IReviewRepository.cs`
- Create: `src/SecurityReview.Application/Abstractions/IWindowsIdentityProvider.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteReviewRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Identity/WindowsIdentityProvider.cs`
- Create: `tests/SecurityReview.UnitTests/Reviews/ExceptionBindingTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Reviews/ReviewPersistenceTests.cs`

**Interfaces:**
- Consumes: encrypted repositories, finding/file/asset/rule fingerprints, current Windows identity.
- Produces: append-only decisions, exact exception grants, and effective review state consumed by UI/report/diff.

- [ ] **Step 1: Write review transition and validation tests**

Allowed recorded statuses are Pending, ConfirmedRisk, FalsePositive, ApprovedException, RemediatedAwaitingRescan. Reason is required for all non-Pending states, 1–2,000 characters, encrypted, and never logged. Every update appends a decision; it never mutates/deletes prior history. Current effective state is latest by `(decidedAtUtc,decisionId)`.

- [ ] **Step 2: Write exact exception invalidation tests**

Binding includes asset ID/version HMAC, file relative-path HMAC, canonical locator HMAC, value HMAC, rule pack hash/rule ID, and expiry UTC. Changing any one value, location, asset version, rule package/rule ID, or crossing expiry invalidates. A changed severity without rule/hash change does not broaden scope. No wildcard/global exception API exists.

- [ ] **Step 3: Implement identity and review service**

`WindowsIdentityProvider` returns user SID plus display name. Store SID HMAC in searchable column and SID/display encrypted in payload. `ReviewService` loads occurrence, validates command optimistic version, captures current identity/time from injected clock, appends decision, and for ApprovedException creates a separate `ExceptionGrant` in the same transaction.

- [ ] **Step 4: Implement effective exception matching**

On scan, compute all binding fingerprints and query active non-expired grants by asset/occurrence binding. Exact match marks the new finding `ApprovedException`; any mismatch leaves Pending and records a non-sensitive `exception_not_applicable` reason code for diff/report. Rules cannot create global UI exceptions; only signed placeholder/rule changes affect global behavior.

- [ ] **Step 5: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter "FullyQualifiedName~Review|FullyQualifiedName~Exception"
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~Review
git add src/SecurityReview.Domain/Reviews src/SecurityReview.Application/Reviews src/SecurityReview.Application/Abstractions/IReviewRepository.cs src/SecurityReview.Application/Abstractions/IWindowsIdentityProvider.cs src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteReviewRepository.cs src/SecurityReview.Infrastructure/Windows/Identity tests/SecurityReview.UnitTests/Reviews/ExceptionBindingTests.cs tests/SecurityReview.IntegrationTests/Reviews/ReviewPersistenceTests.cs
git commit -m "feat: record reviews and exact expiring exceptions"
```

## Task P4-T6: Implement strict stage caches and trustworthy rescan differences

**Files:**
- Create: `src/SecurityReview.Domain/Reviews/DifferenceStatus.cs`
- Create: `src/SecurityReview.Application/Caching/ParseCacheKey.cs`
- Create: `src/SecurityReview.Application/Caching/DetectionCacheKey.cs`
- Create: `src/SecurityReview.Application/Caching/SemanticCacheKey.cs`
- Create: `src/SecurityReview.Application/Caching/CacheCoordinator.cs`
- Create: `src/SecurityReview.Application/Diff/ScanDiffService.cs`
- Create: `src/SecurityReview.Application/Abstractions/ICacheRepository.cs`
- Create: `src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteCacheRepository.cs`
- Create: `tests/SecurityReview.UnitTests/Caching/CacheKeyTests.cs`
- Create: `tests/SecurityReview.UnitTests/Diff/ScanDiffServiceTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Caching/CacheInvalidationMatrixTests.cs`

**Interfaces:**
- Consumes: encrypted cache repository, file/parser/policy/model/prompt/endpoint fingerprints, findings and coverage.
- Produces: exact parse/detect/semantic reuse decisions and `New/Persistent/Resolved/ReappearedAfterRuleChange/UnreviewableThisRun` results.

- [ ] **Step 1: Write complete cache key mutation tests**

```text
ParseKey = file SHA-256 + stream identity + parser ID/version + limits profile + parser contract/client version
DetectKey = ParseKey + effective policy SHA-256 + detector bundle version
SemanticKey = candidate HMAC + masked-context SHA-256 + endpoint origin fingerprint + model + response-format mode + temperature mode + prompt + rule-pack hash + adapter version
```

For every component, clone a valid key, change only that component, and assert inequality/cache miss. Identical values yield stable lowercase SHA-256 cache key. No raw path/value/context/API key enters a key.

- [ ] **Step 2: Implement encrypted cache entries and stage dependency**

Cache repository stores stage enum, key, encrypted result, source scan, created/last-used. `CacheCoordinator` may reuse parse→detect→semantic only independently in dependency order. A detect miss can reuse parse chunks; semantic miss can reuse deterministic candidates. Auth credential changes do not invalidate semantic content cache if exact endpoint/model/prompt remain, but endpoint origin/model/prompt/adapter changes do.

AEAD/hash/schema failure deletes the entry and reruns; it never fails open to the corrupt result.

Apply a default physical cache budget of `min(2 GiB, 10% of free space measured at scan start)` and preserve an additional 2 GiB free-space reserve for database/export/temp work. Evict least-recently-used, non-active entries transactionally before writes. If the budget/reserve cannot be met, skip caching that result without changing coverage or scan correctness; never truncate an encrypted cache entry. Tests use an injected disk-capacity provider and assert deterministic eviction/order.

- [ ] **Step 3: Write diff behavior tests**

Test new, persistent same binding, resolved only when corresponding location was covered this run, reappeared after rule change, moved location as new+resolved, content changed as new, exact exception carried, exception invalidated, and previous finding at current gap as `UnreviewableThisRun` rather than resolved.

- [ ] **Step 4: Implement stable matching and diff**

Primary key is asset lineage + path HMAC + canonical locator kind/value + rule ID + value HMAC. Secondary matching may annotate moved/similar but cannot change primary status. Rule package change with same location/value and newly enabled rule is `ReappearedAfterRuleChange`. Persist diff on the new scan only; do not rewrite old scan rows.

- [ ] **Step 5: Run matrix and plaintext checks**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter "FullyQualifiedName~Cache|FullyQualifiedName~Diff"
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~CacheInvalidationMatrix
rg -a "SYNTHETIC_CACHE_CANARY" artifacts/cache-test -g "*"; if ($LASTEXITCODE -eq 0) { throw "Cache plaintext leaked." }
```

- [ ] **Step 6: Commit and run P4 gate**

```powershell
git add src/SecurityReview.Domain/Reviews/DifferenceStatus.cs src/SecurityReview.Application/Caching src/SecurityReview.Application/Diff src/SecurityReview.Application/Abstractions/ICacheRepository.cs src/SecurityReview.Infrastructure/Persistence/Repositories/SqliteCacheRepository.cs tests/SecurityReview.UnitTests/Caching tests/SecurityReview.UnitTests/Diff tests/SecurityReview.IntegrationTests/Caching
git commit -m "feat: reuse strict encrypted caches and compute scan differences"
pwsh ./build/test.ps1 -Lane Unit,Integration
```

P4 is complete when encrypted round-trips, tamper rejection, offline canary scans, process-kill recovery, retention, exception invalidation, cache mutation matrix and unreviewable diff semantics all pass.
