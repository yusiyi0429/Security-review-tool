# Uninstall and Clear Data

SecurityReviewTool is available as a per-user installation and as a portable
ZIP. Neither delivery mode installs a Windows service or scheduled task. The
application uninstall intentionally keeps local scan history and settings;
clearing that data is a separate, irreversible operation.

## What the Tool Writes

| Location | Content | Created |
|----------|---------|---------|
| `%LOCALAPPDATA%\Programs\SecurityReviewTool\` | Installed application files | At install time |
| Start Menu / optional desktop shortcut and current-user uninstall entry | Installed application registration | At install time |
| `<extract-dir>/` | Portable application files (ZIP contents) | At extract time |
| `%LOCALAPPDATA%\SecurityReviewTool\` | Configuration, history, rules, temp, diagnostics | On first launch |
| AppContainer profile (system-managed) | Worker sandbox isolation object | On first launch |

The tool writes **nothing** to these machine-wide locations:

- `Program Files` or `Program Files (x86)`.
- `HKEY_LOCAL_MACHINE` registry keys. The installer creates only the standard
  current-user uninstall registration under `HKEY_CURRENT_USER`.
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

### 2. Remove the application

For the installed version, open **Settings → Apps → Installed apps**, find
**安全审查工具**, and select **Uninstall**. This removes program files,
shortcuts, and the current-user uninstall entry without deleting scan data.

For the portable version, delete the entire extracted directory. For example:

Delete the entire extracted directory. For example:

```powershell
Remove-Item -Recurse -Force "C:\Tools\SecurityReviewTool"
```

Do not manually delete the installed directory before running the uninstaller,
or the uninstall registration and shortcuts may be left behind.

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
Test-Path "$env:LOCALAPPDATA\Programs\SecurityReviewTool" # Should be False
Test-Path "C:\Tools\SecurityReviewTool"             # Should be False
```

If you reinstalled to a different directory, verify that directory is
deleted.

## Partial Uninstall (Keep Data, Remove Application)

To remove only the application while keeping configuration and history:

1. Uninstall the installed version, or delete the portable application directory.
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
rules. Per-user shortcuts and uninstall registration are removed by the
installer's uninstaller.

## Reinstallation

After a complete uninstall:

1. Run the release installer, or extract the release ZIP to a fresh directory.
2. Launch from the Start Menu, or double-click the portable `SecurityReviewTool.exe`.
3. Reconfigure LLM settings (endpoint, model, API key).
4. Import any updated rule packs.

All previous scan history is gone — use the XLSX exports from step 1 of
the uninstall procedure as your record of past reviews.
