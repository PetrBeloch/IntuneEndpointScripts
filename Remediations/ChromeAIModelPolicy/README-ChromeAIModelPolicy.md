# ChromeAIModelPolicy — Intune Enforcement Package

**Purpose:** Detect and enforce Chrome Enterprise Policy to block on-device AI model downloads (Gemini Nano / Optimization Guide models) across managed Windows endpoints.

---

## Enforcement Method Comparison

Three methods are available. Use them in combination, not as alternatives.

| Method | What it does | When to use |
|---|---|---|
| **Settings Catalog** *(recommended)* | Enforces `OptimizationGuideModelDownloading = 0` as a native Intune configuration profile | Primary enforcement for all managed devices |
| **ADMX Import** *(fallback)* | Same result via imported Chrome ADMX templates | If the policy is not yet visible in Settings Catalog |
| **Proactive Remediation** *(complementary)* | Audits existing artifacts, writes Event Log, verifies policy is in place, generates HTML report | Audit trail, compliance monitoring, enforcement verification |

> **Recommended approach:** Deploy the Settings Catalog profile as your enforcement mechanism, then deploy the Proactive Remediation alongside it for audit and monitoring. The remediation script will detect non-compliant devices (policy missing) and report them in Intune — acting as a compliance sensor even when you rely on the profile for actual enforcement.

---

## Files Included

| File | Description |
|---|---|
| `Detect-ChromeAIModelPolicy.ps1` | Detection script — checks Chrome Enterprise Policy and audits existing AI model artifacts |
| `Remediate-ChromeAIModelPolicy.ps1` | Remediation script — audits, writes Event Log, applies policy, generates HTML report |
| `KQL-ChromeAIModelPolicy.kql` | Defender XDR Advanced Hunting queries for baseline, audit, and ongoing monitoring |
| `README-ChromeAIModelPolicy.md` | This document |

---

## Background

Chrome distributes on-device AI model files (Gemini Nano / Optimization Guide models) to endpoints for features including scam detection, "Help me write", and future on-device AI capabilities. These model folders can consume hundreds of MB to several GB per user profile.

**Detection paths (per user profile):**
```
%LOCALAPPDATA%\Google\Chrome\User Data\OptGuideOnDeviceModel
%LOCALAPPDATA%\Google\Chrome\User Data\OptimizationGuidePredictionModels
```

**Enterprise control:** The `OptimizationGuideModelDownloading` Chrome Enterprise Policy (DWORD = 0) in `HKLM\SOFTWARE\Policies\Google\Chrome` instructs Chrome to stop downloading these models. Existing artifacts are NOT deleted — they age out as Chrome cleans unused components.

---

## Detection Logic

**Primary check (compliance decision):**

The script checks whether `OptimizationGuideModelDownloading = 0` exists in `HKLM\SOFTWARE\Policies\Google\Chrome`.

- Policy = 0 → **Exit 0 (Compliant)** — remediation does not run
- Policy missing or ≠ 0 → **Exit 1 (Non-compliant)** — remediation runs

**Secondary (informational, always runs):**

The detection script also scans all user profiles under `C:\Users\` for existing model artifact folders and reports their size. This output is captured by Intune per-device and provides your audit trail of which machines had models present, even before remediation runs.

**On script error:** Exit 0 (safe default — prevents accidental remediation on detection failure).

---

## Remediation Actions

The remediation script executes five phases:

**Phase 1 — Audit**
Scans all local user profiles for Chrome AI model artifact folders. Records folder names, sizes per user, and total size across the device. This runs before any changes are made, preserving the pre-remediation state.

**Phase 2 — Event Log**
Writes a structured audit record to the **Windows Application Event Log**:
- Log: `Application`
- Source: `ChromeAIModelPolicy`
- EventID: `9001`

This provides a persistent on-device record that remains after the device becomes compliant, and is queryable via Defender XDR Advanced Hunting (Query 3 in the KQL file).

**Phase 3 — Apply Policy**
Creates `HKLM\SOFTWARE\Policies\Google\Chrome` if it does not exist, then sets:
```
OptimizationGuideModelDownloading = 0 (DWORD)
```
Chrome enforces this policy on next browser restart. Existing model artifacts are **not deleted**.

**Phase 4 — Verify**
Reads back the registry value to confirm it was written correctly. Exits 1 (failure) if verification fails, triggering Intune retry.

**Phase 5 — HTML Report**
Generates a self-contained HTML report saved to the Intune log directory, documenting pre-remediation artifacts and all actions taken.

---

## Audit Trail Strategy

The remediation is designed so that you never lose the "who had it" history:

| Mechanism | Location | Retention | Queryable via |
|---|---|---|---|
| Intune detection output (stdout) | Intune portal per-device | ~30 days | Intune Reports |
| Windows Application Event Log | On device | Until log rotation (~20 MB default) | Defender XDR / Event Viewer |
| HTML report file | `%ProgramData%\...\Logs\` | Until manually deleted | Defender XDR (Query 5) |
| Defender XDR file events | Cloud | Up to 30 days | KQL Queries 1–2 |

**Recommended before deployment:** Run KQL Query 1 and KQL Query 2 from the `.kql` file against your estate and export the results. This snapshot is your permanent pre-remediation baseline, independent of any script.

---

## Method 1 — Settings Catalog (Recommended)

The Intune Settings Catalog includes natively ingested Chrome Enterprise Policies. This is the cleanest enforcement path: no scripts, no ADMX import, managed as a standard configuration profile with full assignment targeting, conflict detection, and compliance reporting.

### Step 1 — Check if the policy is in Settings Catalog

1. Navigate to: **Intune Admin Center → Devices → Configuration → + Create → New Policy**
2. Platform: **Windows 10 and later**
3. Profile type: **Settings catalog**
4. Click **+ Add settings**
5. In the settings picker, search for: `OptimizationGuideModelDownloading`
   - If found under **Google Chrome** → proceed with this method
   - If not found → use Method 2 (ADMX Import) below

> The Chrome policy catalog in Intune is updated periodically. `OptimizationGuideModelDownloading` may also appear under search terms like **"Optimization Guide"** or **"model download"**. The display name in the UI is typically **"Disable model downloading for the Optimization Guide"**.

### Step 2 — Configure the profile

| Setting | Value |
|---|---|
| **Name** | `Chrome - Disable AI Model Downloads` |
| **Description** | `Enforces OptimizationGuideModelDownloading = 0. Prevents Chrome from downloading on-device AI models (Gemini Nano / Optimization Guide). Applied via Intune Settings Catalog.` |
| **Platform** | Windows 10 and later |
| **Profile type** | Settings catalog |

Add the setting and set the value:

| Setting name | Value |
|---|---|
| `Disable model downloading for the Optimization Guide` (or `OptimizationGuideModelDownloading`) | **Disabled** (= 0) |

### Step 3 — Assign the profile

- Assign to your target device groups
- Use **Exclude** to create a pilot group for initial rollout

### Step 4 — Verify on endpoint

After assignment syncs (allow up to 8 hours, or trigger Sync from the Intune portal), open Chrome and navigate to:
```
chrome://policy
```
Look for `OptimizationGuideModelDownloading` with value `0` and source `Platform`.

The registry will show:
```
HKLM\SOFTWARE\Policies\Google\Chrome\OptimizationGuideModelDownloading = 0 (DWORD)
```

---

## Method 2 — ADMX Import (Fallback)

Use this method if `OptimizationGuideModelDownloading` is not yet available in the Settings Catalog.

### Step 1 — Download Chrome ADMX templates

Download the Chrome Enterprise bundle from:
```
https://chromeenterprise.google/intune/
```
Or via the Chrome Enterprise Bundle (contains `chrome.admx` and language files).

### Step 2 — Import ADMX into Intune

1. Navigate to: **Intune Admin Center → Devices → Configuration → + Create → New Policy**
2. Platform: **Windows 10 and later**
3. Profile type: **Administrative Templates** → click **Import ADMX**
4. Upload `chrome.admx` (and `google.admx` if required)
5. Wait for import to complete (status: Available)

### Step 3 — Create Administrative Templates profile

1. **Devices → Configuration → + Create → New Policy**
2. Platform: **Windows 10 and later**
3. Profile type: **Administrative Templates**
4. Search for: `OptimizationGuideModelDownloading`
5. Set to: **Disabled**
6. Assign to device groups

---

## Method 3 — Proactive Remediation (Audit + Enforcement Verification)

Deploy alongside Method 1 or 2. The remediation scripts serve a different purpose than the configuration profile: they provide audit data, Event Log records, and compliance verification — not just enforcement.

### What the remediation adds that Settings Catalog cannot provide

- Per-device stdout captured by Intune (artifact count, sizes, user profiles affected)
- Pre-remediation state written to Windows Application Event Log (persistent, queryable via Defender XDR)
- HTML report on device documenting what was found before policy was applied
- Detection script acts as a compliance sensor: if the Settings Catalog profile fails to apply for any reason, the detection script catches it and reports non-compliance in Intune

### Intune Deployment Instructions

### Step 1 — Run KQL baseline (before deploying)
Open Defender XDR → Advanced Hunting → run Query 1 and Query 2 from `KQL-ChromeAIModelPolicy.kql`. Export CSV. This is your "before" snapshot.

### Step 2 — Create Proactive Remediation package

1. Navigate to: **Intune Admin Center → Devices → Scripts and remediations → Proactive remediations**
2. Click **+ Create**
3. Configure:
   - **Name:** `Chrome AI Model Policy`
   - **Description:** `Enforces Chrome Enterprise Policy to disable on-device AI model downloading. Audits existing artifacts and writes Event Log before applying policy.`
   - **Publisher:** `Petr Beloch (CSGM DIW)`

### Step 3 — Upload scripts

- **Detection script:** `Detect-ChromeAIModelPolicy.ps1`
- **Remediation script:** `Remediate-ChromeAIModelPolicy.ps1`

### Step 4 — Configure script settings

| Setting | Value |
|---|---|
| Run this script using the logged-on credentials | **No** (System) |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell | **Yes** |

> **Why System context?** The Chrome Enterprise Policy must be written to `HKLM`, which requires local administrator / SYSTEM privileges. The artifact scan iterates `C:\Users\` directly (SYSTEM cannot use `%LOCALAPPDATA%` to find user profiles).

### Step 5 — Schedule and assign

- **Schedule:** Daily (or hourly for faster initial rollout)
- **Target:** Pilot device group first, then production

### Step 6 — Monitor results

After deployment, verify in Intune portal:
- **Reports → Endpoint Analytics → Proactive remediations → [your package]**
- Review per-device detection output (stdout captured by Intune)
- Check for remediation success/failure counts

Run KQL Query 3–5 in Defender XDR to confirm Event Log records and report files are appearing.

---

## Logging

All script output is written to the Intune Management Extension log directory:

| File | Description |
|---|---|
| `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\Detect-ChromeAIModelPolicy.log` | Detection run log |
| `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\Remediate-ChromeAIModelPolicy.log` | Remediation run log |
| `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\Remediate-ChromeAIModelPolicy-Report.html` | HTML remediation report |

Windows Application Event Log:
- **Log:** Application
- **Source:** ChromeAIModelPolicy
- **EventID:** 9001

---

## Verify Policy on Endpoint

After Chrome restarts, open the following URL in Chrome to confirm the policy is active:

```
chrome://policy
```

Look for `OptimizationGuideModelDownloading` with value `0` and source `Platform`.

---

## Testing

Before production rollout:

```powershell
# Test detection (run as SYSTEM using PsExec, or test manually as admin)
.\Detect-ChromeAIModelPolicy.ps1
echo "Exit code: $LASTEXITCODE"

# Test remediation
.\Remediate-ChromeAIModelPolicy.ps1
echo "Exit code: $LASTEXITCODE"

# Verify registry
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome" | Select OptimizationGuideModelDownloading

# Verify event log
Get-EventLog -LogName Application -Source ChromeAIModelPolicy -Newest 5

# Open HTML report
Start-Process "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-ChromeAIModelPolicy-Report.html"
```

---

## Requirements

- **PowerShell:** 5.1 or higher (Windows PowerShell — not PowerShell Core)
- **Run context:** SYSTEM (local administrator privileges)
- **Platform:** Windows 10 / Windows 11
- **Chrome:** Any version where Optimization Guide model downloads are active
- **MDE:** Microsoft Defender for Endpoint recommended (enables KQL Event Log queries)

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 1.0.0 | 2026-05-07 | Initial release |

---

## Authors

- **Author:** Petr Beloch (CSGM DIW)
- **Co-Author:** Claude
