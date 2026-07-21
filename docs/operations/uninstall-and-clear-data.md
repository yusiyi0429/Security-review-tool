# Uninstall and Clear Data

SecurityReviewTool is a portable application — there is no installer, no
Windows service, and no scheduled task. Uninstallation is manual but must
follow the procedure below to remove all local data and the AppContainer
isolation profile.

## What the Tool Writes

| Location | Content | Created |
|----------|---------|---------|
| `<extract-dir>/` | Application files (ZIP contents) | At extract time |
| `%LOCALAPPDATA%\SecurityReviewTool\` | Configuration, history, rules, temp, diagnostics | On first launch |
| AppContainer profile (system-managed) | Worker sandbox isolation object | On first launch |

The tool writes **nothing** to:

- `Program Files` or `Program Files (x86)`.
- The Windows registry (except what the OS creates automatically for
  AppContainer profile tracking).
- ProgramData.
- Startup folder.
- Windows firewall rules (worker has no network; main process uses standard
  outbound HTTPS, no custom rules).

## Complete Uninstall Procedure

Perform these steps in order:

### 1. Export any data you want to keep

Before clearing, export scan history if needed:

1. Open SecurityReviewTool.
2. For each completed scan, export the XLSX report to a safe location.
3. Note any custom LLM configuration (endpoint, model, prompt) — you will
   need to re-enter it after reinstall.

### 2. Delete the application directory

Delete the entire extracted directory. For example:

```powershell
Remove-Item -Recurse -Force "C:\Tools\SecurityReviewTool"
```

The application does not register itself anywhere — deleting the directory
removes the executable and all shipped assets.

### 3. Clear LocalAppData

Delete the tool's writable data directory:

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\SecurityReviewTool"
```

This removes:

- Encrypted history database (all scan records, review decisions).
- LLM configuration and credentials (DPAPI-encrypted).
- Imported rule packs.
- Diagnostic logs.
- Temporary files.

> ⚠ **This is irreversible.** The encrypted database cannot be recovered
> without the DPAPI key material bound to the original Windows user profile.
> Export any XLSX reports before this step.

### 4. Remove the AppContainer profile

The AppContainer profile is a system-managed isolation object that persists
across application reinstalls. It is user-specific and must be removed
separately.

Open PowerShell **as the same user** (not as administrator) and run:

```powershell
Get-AppBackgroundTask | Where-Object { $_.TaskName -like "*SecurityReviewTool*" } |
    Unregister-AppBackgroundTask -Confirm:$false
```

If the above does not find the profile, locate it by SID pattern (the profile
name is `Company.SecurityReviewTool.Parser.V1`):

```powershell
# List all AppContainer profiles for the current user
icacls "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db" 2>$null
```

On a clean uninstall, the profile can be removed with:

```powershell
# Remove the AppContainer profile by name
$profileName = "Company.SecurityReviewTool.Parser.V1"
$profile = Get-AppxPackage -Name "*" 2>$null  # AppContainer is not an AppX package
```

> **Note:** As of Windows 11 x64 (supported builds only), there is no
> single-command PowerShell cmdlet to delete an arbitrary AppContainer
> profile. The OS **asynchronously reclaims** unused profiles. If the above
> steps are completed (application directory deleted, LocalAppData cleared),
> the orphaned profile will be reclaimed during normal system operation.
> The profile is harmless — it contains no application data and grants no
> capabilities.

### 5. Verify cleanup

Confirm the following directories no longer exist:

```powershell
Test-Path "$env:LOCALAPPDATA\SecurityReviewTool"   # Should be False
Test-Path "C:\Tools\SecurityReviewTool"             # Should be False
```

If you reinstalled to a different directory, verify that directory is
deleted.

## Partial Uninstall (Keep Data, Remove Application)

To remove only the application while keeping configuration and history:

1. Delete the extracted application directory.
2. **Do not** delete `%LOCALAPPDATA%\SecurityReviewTool\`.

When you re-extract a new version, it will use the existing data directory.
Ensure the new version is compatible with the existing database schema
(check the release notes for schema migration notices).

## Partial Uninstall (Clear Data, Keep Application)

To clear all local data while keeping the application:

1. Close SecurityReviewTool.
2. Delete `%LOCALAPPDATA%\SecurityReviewTool\`.
3. Restart SecurityReviewTool — it will recreate the data directory with
   fresh defaults.

This is equivalent to a factory reset.

## Enterprise Cleanup (IT Administrator)

For enterprise deployment where multiple user profiles may have run the tool:

1. For each user profile, run the uninstall procedure above.
2. Optionally, scan for orphaned `%LOCALAPPDATA%\SecurityReviewTool\`
   directories across user profiles.
3. AppContainer profiles are per-user and can be verified by enumerating
   SIDs with the pattern `S-1-15-2-*` that match the application's
   capability SID.

The application leaves **no machine-wide artifacts** — no `HKLM` registry
keys, no `ProgramData` files, no services, no scheduled tasks, no firewall
rules.

## Reinstallation

After a complete uninstall:

1. Extract the release ZIP to a fresh directory.
2. Double-click `SecurityReviewTool.exe`.
3. Reconfigure LLM settings (endpoint, model, API key).
4. Import any updated rule packs.

All previous scan history is gone — use the XLSX exports from step 1 of
the uninstall procedure as your record of past reviews.
