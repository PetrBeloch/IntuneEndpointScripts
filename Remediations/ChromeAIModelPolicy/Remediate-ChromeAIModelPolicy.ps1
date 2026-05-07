<#
.SYNOPSIS
    Applies Chrome Enterprise Policy to disable on-device AI model downloading.

.DESCRIPTION
    Remediation process:

    Phase 1 - Audit
        Scans all local user profiles for existing Chrome AI model artifact folders
        (OptGuideOnDeviceModel, OptimizationGuidePredictionModels) and records
        their size per user. This preserves pre-remediation state for audit purposes.

    Phase 2 - Event Log
        Writes the full audit summary to the Windows Application Event Log
        (Source: ChromeAIModelPolicy, EventID: 9001) before any changes are made.
        This provides a persistent on-device record queryable via Defender XDR
        Advanced Hunting even after the device becomes compliant.

    Phase 3 - Apply Policy
        Creates the Chrome Enterprise Policy registry path if it does not exist
        and sets OptimizationGuideModelDownloading = 0 (DWORD) in HKLM.
        Chrome will enforce this policy on next browser restart.
        Existing model artifacts are NOT deleted - they will age out naturally
        as Chrome stops refreshing them.

    Phase 4 - Verify
        Reads back the registry value to confirm it was written correctly.

    Phase 5 - HTML Report
        Generates a self-contained HTML report saved to the Intune log directory,
        documenting pre-remediation artifacts and all actions taken.

    Exit Codes:
    - Exit 0: Remediation succeeded (policy applied and verified)
    - Exit 1: Remediation failed (see log for details)

.NOTES
    Author:   Petr Beloch (CSGM DIW)
    Co-Author: Claude
    Version:  1.0.0
    Intune Deployment: Proactive Remediation - Remediation Script
    Run as:   System
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes

.EXAMPLE
    .\Remediate-ChromeAIModelPolicy.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

#region Initialize
$ScriptName = "Remediate-ChromeAIModelPolicy"
$LogPath    = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\$ScriptName.log"

$LogDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path -Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-LogEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$Severity = "Information"
    )
    $TimeStamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$TimeStamp [$Severity] $Message"
    try {
        Add-Content -Path $LogPath -Value $LogMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log: $_"
    }
}

function New-RemediationReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        [Parameter(Mandatory = $true)]
        [array]$Actions,
        [Parameter(Mandatory = $false)]
        [array]$ArtifactData,
        [Parameter(Mandatory = $false)]
        [string]$TotalSizeGB = "0"
    )

    $ReportTime   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $ComputerName = $env:COMPUTERNAME

    # Build artifact table rows
    if ($ArtifactData -and $ArtifactData.Count -gt 0) {
        $ArtifactRows = ($ArtifactData | ForEach-Object {
            "<tr><td>$($_.User)</td><td>$($_.Folder)</td><td>$($_.SizeMB) MB</td>" +
            "<td style='word-break:break-all;font-size:0.82em;color:#444;'>$($_.Path)</td></tr>"
        }) -join "`n"
    }
    else {
        $ArtifactRows = "<tr><td colspan='4' style='text-align:center;color:#888;padding:16px;'>" +
            "No Chrome AI model artifacts detected in any user profile.</td></tr>"
    }

    # Build action table rows
    $ActionRows = ($Actions | ForEach-Object {
        $Color = switch ($_.Status) {
            "Success" { "#107c10" }
            "Warning" { "#c47900" }
            "Error"   { "#d13438" }
            default   { "#323130" }
        }
        "<tr><td style='white-space:nowrap;'>$($_.Timestamp)</td>" +
        "<td>$($_.Action)</td>" +
        "<td style='color:$Color;font-weight:600;white-space:nowrap;'>$($_.Status)</td>" +
        "<td>$($_.Details)</td></tr>"
    }) -join "`n"

    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Remediation Report - $ScriptName</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; background: #f3f2f1; color: #323130; font-size: 14px; }
    .header { background: #0078d4; color: #fff; padding: 20px 32px; }
    .header h1 { font-size: 1.3em; font-weight: 600; letter-spacing: -0.2px; }
    .header .sub { margin-top: 6px; opacity: 0.88; font-size: 0.88em; }
    .body { max-width: 980px; margin: 24px auto; padding: 0 16px 40px; }
    .card { background: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,.12); margin-bottom: 20px; overflow: hidden; }
    .card-title { background: #f9f8f7; border-bottom: 1px solid #edebe9; padding: 12px 20px; font-weight: 600; font-size: 0.95em; color: #0078d4; }
    .card-body { padding: 16px 20px; }
    .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 40px; }
    .meta-item { font-size: 0.9em; line-height: 1.5; }
    .meta-label { font-weight: 600; color: #605e5c; display: block; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.4px; }
    .note { font-size: 0.83em; color: #605e5c; margin-bottom: 12px; padding: 8px 12px; background: #f3f2f1; border-left: 3px solid #0078d4; border-radius: 2px; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #0078d4; color: #fff; padding: 9px 12px; text-align: left; font-weight: 600; font-size: 0.88em; }
    td { padding: 8px 12px; border-bottom: 1px solid #edebe9; vertical-align: top; font-size: 0.9em; }
    tr:last-child td { border-bottom: none; }
    tbody tr:hover td { background: #f9f8f7; }
    .footer { text-align: center; font-size: 0.8em; color: #a19f9d; padding-top: 8px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Chrome AI Model Policy - Remediation Report</h1>
    <div class="sub">$ComputerName &nbsp;|&nbsp; $ReportTime &nbsp;|&nbsp; $ScriptName</div>
  </div>
  <div class="body">

    <div class="card">
      <div class="card-title">Execution Summary</div>
      <div class="card-body">
        <div class="meta-grid">
          <div class="meta-item"><span class="meta-label">Computer</span>$ComputerName</div>
          <div class="meta-item"><span class="meta-label">Date / Time</span>$ReportTime</div>
          <div class="meta-item"><span class="meta-label">Policy Applied</span>OptimizationGuideModelDownloading = 0 (DWORD)</div>
          <div class="meta-item"><span class="meta-label">Registry Path</span>HKLM\SOFTWARE\Policies\Google\Chrome</div>
          <div class="meta-item"><span class="meta-label">Total Artifact Size (pre-remediation)</span>$TotalSizeGB GB</div>
          <div class="meta-item"><span class="meta-label">Artifact Folders Found</span>$(if ($ArtifactData) { $ArtifactData.Count } else { 0 })</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Pre-Remediation Chrome AI Model Artifacts</div>
      <div class="card-body">
        <p class="note">These folders were present <strong>before</strong> the policy was applied.
        Existing files are <strong>not deleted</strong> - Chrome will stop refreshing them once the policy is active.
        They will age out naturally on next Chrome cleanup cycle.</p>
        <table>
          <thead><tr><th>User Profile</th><th>Folder</th><th>Size</th><th>Full Path</th></tr></thead>
          <tbody>$ArtifactRows</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Remediation Actions</div>
      <div class="card-body">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Details</th></tr></thead>
          <tbody>$ActionRows</tbody>
        </table>
      </div>
    </div>

  </div>
  <div class="footer">
    Intune Proactive Remediation &nbsp;|&nbsp; Author: Petr Beloch (CSGM DIW) &nbsp;|&nbsp; Co-Author: Claude
  </div>
</body>
</html>
"@

    try {
        $HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
        Write-LogEntry -Message "HTML report generated: $ReportPath"
    }
    catch {
        Write-LogEntry -Message "Failed to generate HTML report: $_" -Severity Error
    }
}
#endregion

#region Main Remediation Logic
try {
    Write-LogEntry -Message "========== Remediation Started =========="
    Write-LogEntry -Message "Computer : $env:COMPUTERNAME"
    Write-LogEntry -Message "Script   : $ScriptName v1.0.0"

    $ReportActions = @()

    # -------------------------------------------------------------------
    # PHASE 1: Audit existing AI model artifacts across all user profiles
    # -------------------------------------------------------------------
    Write-LogEntry -Message "--- Phase 1: Auditing Chrome AI model artifacts ---"

    $ModelFolderNames      = @("OptGuideOnDeviceModel", "OptimizationGuidePredictionModels")
    $ChromeUserDataRelPath = "AppData\Local\Google\Chrome\User Data"

    $ArtifactData   = @()
    $TotalSizeBytes = 0

    $UserProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    Write-LogEntry -Message "Scanning $($UserProfiles.Count) user profile(s)..."

    foreach ($Profile in $UserProfiles) {
        foreach ($FolderName in $ModelFolderNames) {
            $ModelPath = Join-Path -Path $Profile.FullName -ChildPath "$ChromeUserDataRelPath\$FolderName"

            if (Test-Path -Path $ModelPath) {
                try {
                    $SizeBytes       = (Get-ChildItem -Path $ModelPath -Recurse -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum).Sum
                    $SizeMB          = [math]::Round($SizeBytes / 1MB, 2)
                    $TotalSizeBytes += $SizeBytes

                    $ArtifactData += [PSCustomObject]@{
                        User   = $Profile.Name
                        Folder = $FolderName
                        SizeMB = $SizeMB
                        Path   = $ModelPath
                    }

                    Write-LogEntry -Message "Found | User=$($Profile.Name) | Folder=$FolderName | Size=$SizeMB MB"
                }
                catch {
                    Write-LogEntry -Message "Error measuring $ModelPath : $_" -Severity Warning
                }
            }
        }
    }

    $TotalSizeGB = [math]::Round($TotalSizeBytes / 1GB, 2)
    Write-LogEntry -Message "Audit complete: $($ArtifactData.Count) artifact folder(s), $TotalSizeGB GB total"

    $ReportActions += [PSCustomObject]@{
        Timestamp = Get-Date -Format "HH:mm:ss"
        Action    = "Audit AI Model Artifacts"
        Status    = "Success"
        Details   = "$($ArtifactData.Count) folder(s) found across $($UserProfiles.Count) profile(s). Total size: $TotalSizeGB GB"
    }

    # -------------------------------------------------------------------
    # PHASE 2: Write pre-remediation audit to Windows Application Event Log
    # Provides persistent on-device record queryable via Defender XDR
    # Source: ChromeAIModelPolicy | EventID: 9001 | Log: Application
    # -------------------------------------------------------------------
    Write-LogEntry -Message "--- Phase 2: Writing audit record to Windows Application Event Log ---"

    try {
        $EventSource = "ChromeAIModelPolicy"

        # Register source if it does not exist (requires local admin / SYSTEM)
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName "Application" -Source $EventSource -ErrorAction Stop
            Write-LogEntry -Message "Registered new event source: $EventSource"
        }

        # Build artifact detail lines for the event message
        if ($ArtifactData.Count -gt 0) {
            $ArtifactLines = ($ArtifactData | ForEach-Object {
                "  Profile: $($_.User) | Folder: $($_.Folder) | Size: $($_.SizeMB) MB"
            }) -join "`r`n"
        }
        else {
            $ArtifactLines = "  No Chrome AI model artifacts detected on this device."
        }

        $EventMessage = @"
Chrome AI Model Policy - Pre-Remediation Audit
===============================================
Computer  : $env:COMPUTERNAME
Timestamp : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Action    : Applying OptimizationGuideModelDownloading = 0

Pre-remediation artifact scan:
$ArtifactLines

Summary   : $($ArtifactData.Count) folder(s) | Total: $TotalSizeGB GB

Policy details:
  Registry : HKLM\SOFTWARE\Policies\Google\Chrome
  Value    : OptimizationGuideModelDownloading (DWORD) = 0
  Effect   : Chrome will no longer download on-device AI models.
             Existing artifacts are not deleted; they age out naturally.

Source    : Intune Proactive Remediation
Script    : $ScriptName v1.0.0
"@

        Write-EventLog -LogName "Application" -Source $EventSource -EventId 9001 `
            -EntryType Information -Message $EventMessage -ErrorAction Stop

        Write-LogEntry -Message "Event written: Log=Application | Source=$EventSource | EventID=9001"

        $ReportActions += [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = "Write Audit Event Log"
            Status    = "Success"
            Details   = "Pre-remediation state recorded. Application Event Log | Source: $EventSource | EventID: 9001"
        }
    }
    catch {
        Write-LogEntry -Message "Failed to write Application Event Log: $_" -Severity Warning

        $ReportActions += [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = "Write Audit Event Log"
            Status    = "Warning"
            Details   = "Event log write failed (non-critical): $($_.Exception.Message)"
        }
    }

    # -------------------------------------------------------------------
    # PHASE 3: Apply Chrome Enterprise Policy via HKLM registry
    # -------------------------------------------------------------------
    Write-LogEntry -Message "--- Phase 3: Applying Chrome Enterprise Policy ---"

    $PolicyPath  = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    $PolicyName  = "OptimizationGuideModelDownloading"
    $PolicyValue = 0

    # Ensure the full registry path exists
    if (-not (Test-Path -Path $PolicyPath)) {
        Write-LogEntry -Message "Creating registry path: $PolicyPath"
        New-Item -Path $PolicyPath -Force -ErrorAction Stop | Out-Null

        $ReportActions += [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = "Create Registry Key"
            Status    = "Success"
            Details   = "Created: HKLM\SOFTWARE\Policies\Google\Chrome"
        }
    }
    else {
        Write-LogEntry -Message "Registry path already exists: $PolicyPath"
    }

    # Set the policy value
    Write-LogEntry -Message "Setting: $PolicyPath\$PolicyName = $PolicyValue (DWORD)"
    Set-ItemProperty -Path $PolicyPath -Name $PolicyName -Value $PolicyValue -Type DWord -Force -ErrorAction Stop
    Write-LogEntry -Message "Policy registry value set"

    $ReportActions += [PSCustomObject]@{
        Timestamp = Get-Date -Format "HH:mm:ss"
        Action    = "Set Chrome Policy Value"
        Status    = "Success"
        Details   = "HKLM\SOFTWARE\Policies\Google\Chrome\OptimizationGuideModelDownloading = 0 (DWORD)"
    }

    # -------------------------------------------------------------------
    # PHASE 4: Verify policy was written correctly
    # -------------------------------------------------------------------
    Write-LogEntry -Message "--- Phase 4: Verifying policy application ---"

    $VerifiedValue = Get-ItemPropertyValue -Path $PolicyPath -Name $PolicyName -ErrorAction Stop

    if ($VerifiedValue -eq 0) {
        Write-LogEntry -Message "Verification PASSED: $PolicyName = $VerifiedValue"

        $ReportActions += [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = "Verify Policy"
            Status    = "Success"
            Details   = "Confirmed: OptimizationGuideModelDownloading = 0. Policy active on next Chrome restart."
        }
    }
    else {
        Write-LogEntry -Message "Verification FAILED: $PolicyName = $VerifiedValue (expected 0)" -Severity Error

        $ReportActions += [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = "Verify Policy"
            Status    = "Error"
            Details   = "Unexpected value after write: $PolicyName = $VerifiedValue (expected 0)"
        }

        throw "Policy verification failed - expected 0, got: $VerifiedValue"
    }

    # -------------------------------------------------------------------
    # PHASE 5: Generate HTML report
    # -------------------------------------------------------------------
    Write-LogEntry -Message "--- Phase 5: Generating HTML report ---"

    $ReportPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\$ScriptName-Report.html"

    New-RemediationReport `
        -ReportPath   $ReportPath `
        -ScriptName   $ScriptName `
        -Actions      $ReportActions `
        -ArtifactData $ArtifactData `
        -TotalSizeGB  $TotalSizeGB

    # Final stdout captured by Intune
    $FinalOutput = "REMEDIATED | Policy=OptimizationGuideModelDownloading=0 applied and verified | " +
        "Pre-existing artifacts: $($ArtifactData.Count) folder(s), $TotalSizeGB GB (will age out) | " +
        "EventLog: Application/ChromeAIModelPolicy/9001 | Report: $ReportPath"

    Write-Output $FinalOutput
    Write-LogEntry -Message $FinalOutput
    Write-LogEntry -Message "========== Remediation Completed: EXIT 0 =========="
    exit 0
}
catch {
    $ErrorMsg = "Remediation failed: $($_.Exception.Message)"
    Write-LogEntry -Message $ErrorMsg -Severity Error
    Write-Output "REMEDIATION ERROR: $ErrorMsg"
    Write-LogEntry -Message "========== Remediation Failed: EXIT 1 =========="
    exit 1
}
#endregion
