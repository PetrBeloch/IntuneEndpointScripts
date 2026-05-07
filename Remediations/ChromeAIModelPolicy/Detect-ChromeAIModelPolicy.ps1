<#
.SYNOPSIS
    Detects whether Chrome on-device AI model downloading is blocked via Chrome Enterprise Policy.

.DESCRIPTION
    Primary compliance check: verifies that the Chrome Enterprise Policy value
    OptimizationGuideModelDownloading is set to 0 (disabled) in HKLM.

    Additionally scans all local user profiles for existing AI model artifact folders
    (OptGuideOnDeviceModel, OptimizationGuidePredictionModels) and reports their sizes.
    This artifact data is captured by Intune per-device and provides an audit trail
    of which machines had models present before policy enforcement.

    Exit Codes:
    - Exit 0 : Compliant   - policy is applied, model downloading is disabled
    - Exit 1 : Non-compliant - policy is missing or not set to 0
    - Exit 0 : Script error - safe default, prevents remediation on detection failure

.NOTES
    Author:   Petr Beloch (CSGM DIW)
    Co-Author: Claude
    Version:  1.0.0
    Intune Deployment: Proactive Remediation - Detection Script
    Run as:   System
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes

.EXAMPLE
    .\Detect-ChromeAIModelPolicy.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

#region Initialize
$ScriptName = "Detect-ChromeAIModelPolicy"
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
#endregion

#region Main Detection Logic
try {
    Write-LogEntry -Message "========== Detection Started =========="
    Write-LogEntry -Message "Computer : $env:COMPUTERNAME"
    Write-LogEntry -Message "Script   : $ScriptName v1.0.0"

    # -------------------------------------------------------------------
    # PRIMARY CHECK: Chrome Enterprise Policy in HKLM
    # -------------------------------------------------------------------
    $PolicyPath  = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    $PolicyName  = "OptimizationGuideModelDownloading"
    $PolicyCompliant = $false
    $PolicyCurrentValue = "NOT SET"

    Write-LogEntry -Message "Checking Chrome Enterprise Policy: $PolicyPath\$PolicyName"

    if (Test-Path -Path $PolicyPath) {
        try {
            $PolicyValue = Get-ItemPropertyValue -Path $PolicyPath -Name $PolicyName -ErrorAction Stop
            $PolicyCurrentValue = $PolicyValue

            Write-LogEntry -Message "Policy value found: $PolicyName = $PolicyValue"

            if ($PolicyValue -eq 0) {
                $PolicyCompliant = $true
                Write-LogEntry -Message "Policy COMPLIANT: $PolicyName = 0 (downloading disabled)"
            }
            else {
                Write-LogEntry -Message "Policy NON-COMPLIANT: $PolicyName = $PolicyValue (expected 0)" -Severity Warning
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            Write-LogEntry -Message "Policy value '$PolicyName' not found under $PolicyPath" -Severity Warning
        }
        catch {
            Write-LogEntry -Message "Error reading policy value: $_" -Severity Warning
        }
    }
    else {
        Write-LogEntry -Message "Chrome Enterprise Policy path does not exist: $PolicyPath" -Severity Warning
    }

    # -------------------------------------------------------------------
    # INFORMATIONAL: Scan all user profiles for existing model artifacts
    # Runs as SYSTEM - must iterate C:\Users\ directly (LOCALAPPDATA not valid)
    # This output is captured by Intune per-device for audit/reporting purposes
    # -------------------------------------------------------------------
    $ModelFolderNames      = @("OptGuideOnDeviceModel", "OptimizationGuidePredictionModels")
    $ChromeUserDataRelPath = "AppData\Local\Google\Chrome\User Data"

    $ArtifactSummary = @()
    $TotalSizeBytes  = 0

    $UserProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    Write-LogEntry -Message "Scanning $($UserProfiles.Count) user profile(s) for Chrome AI model artifacts..."

    foreach ($Profile in $UserProfiles) {
        foreach ($FolderName in $ModelFolderNames) {
            $ModelPath = Join-Path -Path $Profile.FullName -ChildPath "$ChromeUserDataRelPath\$FolderName"

            if (Test-Path -Path $ModelPath) {
                try {
                    $SizeBytes = (Get-ChildItem -Path $ModelPath -Recurse -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum).Sum

                    $SizeMB          = [math]::Round($SizeBytes / 1MB, 2)
                    $TotalSizeBytes += $SizeBytes

                    $ArtifactSummary += [PSCustomObject]@{
                        User    = $Profile.Name
                        Folder  = $FolderName
                        SizeMB  = $SizeMB
                        Path    = $ModelPath
                    }

                    Write-LogEntry -Message "ARTIFACT | User=$($Profile.Name) | Folder=$FolderName | Size=$SizeMB MB"
                }
                catch {
                    Write-LogEntry -Message "Error measuring size for $ModelPath : $_" -Severity Warning
                }
            }
        }
    }

    $TotalSizeGB = [math]::Round($TotalSizeBytes / 1GB, 2)
    Write-LogEntry -Message "Artifact scan complete: $($ArtifactSummary.Count) folder(s) found, $TotalSizeGB GB total"

    # -------------------------------------------------------------------
    # DECISION & OUTPUT
    # stdout is captured by Intune per-device - write rich, parseable output
    # -------------------------------------------------------------------
    $ArtifactCount = $ArtifactSummary.Count

    if ($ArtifactCount -gt 0) {
        $ArtifactDetail = ($ArtifactSummary | ForEach-Object {
            "$($_.User)\$($_.Folder)=$($_.SizeMB)MB"
        }) -join " | "
    }
    else {
        $ArtifactDetail = "none"
    }

    if ($PolicyCompliant) {
        $Output = "COMPLIANT | Policy=$PolicyName=0 | Artifacts=$ArtifactCount folders/$TotalSizeGB GB (will age out) | $ArtifactDetail"
        Write-Output $Output
        Write-LogEntry -Message $Output
        Write-LogEntry -Message "========== Detection Completed: EXIT 0 (COMPLIANT) =========="
        exit 0
    }
    else {
        $Output = "NON-COMPLIANT | Policy=$PolicyName=$PolicyCurrentValue | Artifacts=$ArtifactCount folders/$TotalSizeGB GB | $ArtifactDetail"
        Write-Output $Output
        Write-LogEntry -Message $Output
        Write-LogEntry -Message "========== Detection Completed: EXIT 1 (NON-COMPLIANT) =========="
        exit 1
    }
}
catch {
    $ErrorMsg = "Detection script failed: $($_.Exception.Message)"
    Write-LogEntry -Message $ErrorMsg -Severity Error
    Write-Output "DETECTION ERROR: $ErrorMsg"
    Write-LogEntry -Message "========== Detection Failed: EXIT 0 (safe default) =========="
    exit 0
}
#endregion
