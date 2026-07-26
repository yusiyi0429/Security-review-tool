# Rule Import

SecurityReviewTool ships with a built-in baseline rule set. This document
explains how to import updated or supplemental rule packs.

On first launch, the client verifies and activates the bundled baseline
automatically. Import is only required when replacing it with an approved
newer rule pack.

## Rule Pack Format

Rule packs are distributed as **signed ZIP archives** with the extension
`.zip`. Each pack contains:

- `manifest.json` — pack metadata (version, min client version, signer key ID).
- `signature.bin` — Ed25519 signature over the manifest and rule files.
- `rules/` — one or more rule definition files.
- `detectors/` — detector configuration files referenced by rules.
- `entities/` — entity lists (keywords, patterns, domain-specific terms).

## Importing a Rule Pack

1. Obtain the signed rule pack ZIP from an authorized distribution channel.
2. Open SecurityReviewTool and go to **Settings → Rules**.
3. Click **Import Rule Pack**.
4. Select the `.zip` file.
5. The tool:

   - Verifies the Ed25519 signature against the built-in trusted signers
     (`Assets/rules/trusted-signers.json`).
   - Validates the manifest schema and version compatibility.
   - Rejects the pack if the signature is invalid, the signer is not trusted,
     or the pack requires a newer client version than the current one.

6. If validation passes, the pack is installed into:
   ```
   %LOCALAPPDATA%\SecurityReviewTool\rules\
   ```
   The previous active pack is retained for rollback.

## Signed ZIP Only

The tool **only** accepts signed rule packs. Unsigned ZIP files, raw rule
files, or manually placed configuration files are rejected. The signature
check uses ECDSA P-256 with public keys from `trusted-signers.json`.

The built-in trusted signers file is part of the application distribution and
is verified as part of the release package integrity check. It cannot be
modified without invalidating the release manifest.

## Trusted Signers

The `trusted-signers.json` file in `Assets/rules/` defines the public keys
the client trusts. Each entry contains:

```json
{
  "id": "<key-id>",
  "public_key": "<base64-encoded-ed25519-public-key>",
  "description": "<organizational context>",
  "active": true
}
```

A signer can be deactivated by setting `"active": false`, which blocks all
packs signed by that key. This is the rollback mechanism for a compromised
signer — deploy an updated `trusted-signers.json` through the release process.

## Version Compatibility

Each rule pack declares `min_client_version`. The tool rejects any pack
whose `min_client_version` is greater than the current client version. This
prevents loading rules that reference detectors or categories unknown to the
current client.

## Verification Before Use

After import, the tool runs a **preflight check** on the new rule pack:

- Every rule references a known detector.
- Every detector has a valid configuration.
- Every entity list is parseable.
- No duplicate IDs exist (rules, detectors, entities).
- No rule references a category not in the pack.

If preflight fails, the previous rule set remains active and the imported
pack is quarantined for inspection.

## Rollback

To revert to the previous rule pack:

1. Go to **Settings → Rules**.
2. Select the previously active version from the history list.
3. Click **Activate**.

The tool retains the last two imported versions plus the baseline for
rollback. The baseline (shipped with the application) is always available.

## Manual Rule Inspection

Imported rules are stored under `%LOCALAPPDATA%\SecurityReviewTool\rules\`
but **must not be edited manually**. The signature covers the exact byte
content of rule files. Any modification will cause the next preflight check
to fail and the rule pack to be deactivated.

To propose rule changes, follow the rule pack release procedure documented
in the internal rule-authoring workflow.

## Troubleshooting

| Symptom | Cause | Action |
|---------|-------|--------|
| "Signature verification failed" | Pack is unsigned or tampered with | Obtain the original signed pack from the authorized channel. |
| "Signer not trusted" | The signing key is not in `trusted-signers.json` | Verify the pack source; if legitimate, request a trusted-signers update. |
| "Client version too old" | Pack requires a newer tool version | Upgrade SecurityReviewTool to the required version. |
| "Preflight check failed" | Pack is internally inconsistent | Report to the rule pack author; do not bypass. |
| "Pack already imported" | Duplicate import | No action needed; the tool skips duplicates. |
