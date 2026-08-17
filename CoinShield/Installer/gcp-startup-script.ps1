#Requires -Version 5.1
<#
.SYNOPSIS
    CoinShield GCP VM Startup Script

.DESCRIPTION
    Google Cloud Platform VM startup script for CoinShield Anti-Mining Service.

    This script is designed to be attached as a Windows startup-script-url or
    sysprep-specialize-script to a GCP VM instance. It runs as SYSTEM on every
    boot and is idempotent (safe to run multiple times).

    HOW TO ATTACH TO A GCP VM:
    ──────────────────────────

    Option A — Metadata startup script (runs on every boot):

        gcloud compute instances add-metadata <VM_NAME> \
            --metadata windows-startup-script-url=gs://your-bucket/coinshield/gcp-startup-script.ps1

    Option B — Instance template (new VMs in a group):

        gcloud compute instance-templates create coinshield-template \
            --metadata windows-startup-script-url=gs://your-bucket/coinshield/gcp-startup-script.ps1 \
            --metadata coinshield-mode=Enforcement

    Option C — Inline (small scripts only):

        gcloud compute instances add-metadata <VM_NAME> \
            --metadata windows-startup-script=<SCRIPT_CONTENT>

    CONFIGURATION VIA GCP METADATA:
    ────────────────────────────────
    Set these keys on the VM instance to control behavior without editing files:

        coinshield-mode          = Monitor | Enforcement | Emergency
        coinshield-gcs-source    = gs://bucket/path/  (GCS folder with binaries)
        coinshield-skip-if-running = true            (skip if service already running)

    PREREQUISITES ON THE GCS BUCKET:
    ─────────────────────────────────
    Upload the published binaries to GCS before creating VMs:

        gsutil -m cp -r .\publish\* gs://your-bucket/coinshield/binaries/

    SCRIPT BEHAVIOR:
    ────────────────
    1. Check if CoinShield is already running (idempotent guard)
    2. Read GCP metadata for configuration
    3. Download binaries from GCS bucket or local path
    4. Run install.ps1 -Silent with detected mode
    5. Verify service started
    6. Log result to GCP Cloud Logging via Event Log (GCP agent picks it up)

    TROUBLESHOOTING:
    ────────────────
    Startup script logs: C:\ProgramData\CoinShield\Logs\startup-script.log
    Windows Event Log:   Application > CoinShield (EventID 1000-1003)
    GCP Ops Agent logs:  Cloud Logging > Windows Event Log

.NOTES
    This script runs as SYSTEM. All file paths must be absolute.
    Network may not be fully available at the instant this script starts;
    the script retries GCS downloads up to 3 times with 10-second delays.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Logging setup (write to file AND Event Log) ───────────────────────────────
$ScriptLogDir  = 'C:\ProgramData\CoinShield\Logs'
$ScriptLogFile = Join-Path $ScriptLogDir 'startup-script.log'

function Write-Log {
    param([string]$msg, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line      = "[$timestamp] [$Level] $msg"

    if (-not (Test-Path $ScriptLogDir)) {
        New-Item -ItemType Directory -Path $ScriptLogDir -Force | Out-Null
    }

    Add-Content -Path $ScriptLogFile -Value $line -Encoding UTF8

    # Also write to Windows Event Log (GCP Ops Agent forwards to Cloud Logging)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('CoinShield-Startup')) {
            [System.Diagnostics.EventLog]::CreateEventSource('CoinShield-Startup', 'Application')
        }
        $entryType = switch ($Level) {
            'ERROR'   { [System.Diagnostics.EventLogEntryType]::Error }
            'WARNING' { [System.Diagnostics.EventLogEntryType]::Warning }
            default   { [System.Diagnostics.EventLogEntryType]::Information }
        }
        Write-EventLog -LogName Application -Source 'CoinShield-Startup' `
            -EventId 1001 -EntryType $entryType -Message $msg
    } catch { <# Event Log not available yet — continue #> }
}

Write-Log "=== CoinShield GCP Startup Script v1.1 ==="
Write-Log "Script started on host: $env:COMPUTERNAME"

# ── Helper: Read GCP instance metadata ────────────────────────────────────────
function Get-GcpMeta {
    param([string]$path, [string]$default = '')
    try {
        $response = Invoke-WebRequest `
            -Uri     "http://metadata.google.internal/computeMetadata/v1/$path" `
            -Headers @{ 'Metadata-Flavor' = 'Google' } `
            -TimeoutSec 3 `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        return $response.Content.Trim()
    } catch {
        return $default
    }
}

# ── Step 1: Read GCP metadata ─────────────────────────────────────────────────
Write-Log "Reading GCP instance metadata..."

$gcpProject     = Get-GcpMeta 'project/project-id'
$gcpZone        = (Get-GcpMeta 'instance/zone')  -split '/' | Select-Object -Last 1
$gcpMachineType = (Get-GcpMeta 'instance/machine-type') -split '/' | Select-Object -Last 1
$gcpInstanceName= Get-GcpMeta 'instance/name'

# Custom metadata keys
$csMode         = Get-GcpMeta 'instance/attributes/coinshield-mode'         -default 'Monitor'
$csGcsSource    = Get-GcpMeta 'instance/attributes/coinshield-gcs-source'   -default ''
$csSkipRunning  = Get-GcpMeta 'instance/attributes/coinshield-skip-if-running' -default 'true'

# Validate mode value
if ($csMode -notin @('Monitor', 'Enforcement', 'Emergency')) { $csMode = 'Monitor' }

Write-Log "Instance: $gcpInstanceName | Project: $gcpProject | Zone: $gcpZone | Type: $gcpMachineType"
Write-Log "CoinShield mode: $csMode | GCS source: $(if ($csGcsSource) { $csGcsSource } else { 'local' })"

# ── Step 2: Idempotent guard ──────────────────────────────────────────────────
$existingSvc = Get-Service -Name 'CoinShield' -ErrorAction SilentlyContinue

if ($existingSvc -and $existingSvc.Status -eq 'Running' -and $csSkipRunning -eq 'true') {
    Write-Log "CoinShield is already RUNNING. Startup script skipping (coinshield-skip-if-running=true)."
    Write-Log "To force reinstall: set metadata coinshield-skip-if-running=false"
    exit 0
}

if ($existingSvc) {
    Write-Log "CoinShield service exists but status=$($existingSvc.Status). Proceeding with install/update."
}

# ── Step 3: Download binaries ─────────────────────────────────────────────────
$DeployDir = 'C:\CoinShield-deploy'

if ($csGcsSource -and $csGcsSource.StartsWith('gs://')) {
    # Download from Google Cloud Storage
    Write-Log "Downloading binaries from GCS: $csGcsSource"

    if (-not (Test-Path $DeployDir)) {
        New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
    }

    $maxRetries = 3
    $success    = $false

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            Write-Log "GCS download attempt $attempt of $maxRetries..."

            # Use gsutil if available, otherwise gcloud storage
            $gsutil = Get-Command gsutil -ErrorAction SilentlyContinue
            if ($gsutil) {
                & gsutil -m cp "$csGcsSource*" $DeployDir 2>&1 | ForEach-Object { Write-Log $_ }
            } else {
                # Try gcloud storage (newer SDK)
                & gcloud storage cp "${csGcsSource}*" $DeployDir --recursive 2>&1 |
                    ForEach-Object { Write-Log $_ }
            }

            if (Test-Path (Join-Path $DeployDir 'CoinShield.Service.exe')) {
                $success = $true
                Write-Log "Binaries downloaded successfully to $DeployDir"
                break
            }
        } catch {
            Write-Log "GCS download attempt $attempt failed: $_" 'WARNING'
            if ($attempt -lt $maxRetries) { Start-Sleep -Seconds 10 }
        }
    }

    if (-not $success) {
        Write-Log "All GCS download attempts failed. Checking for local binaries." 'WARNING'
    }
} else {
    Write-Log "No GCS source specified — using local/pre-staged binaries."
}

# ── Step 4: Locate installer script ───────────────────────────────────────────
$installScript = $null

# Search order: deploy dir, script dir, common staging paths
$searchPaths = @(
    $DeployDir,
    $PSScriptRoot,
    'C:\CoinShield-stage\Installer',
    'C:\tools\CoinShield\Installer'
)

foreach ($sp in $searchPaths) {
    $candidate = Join-Path $sp 'install.ps1'
    if (Test-Path $candidate) {
        $installScript = $candidate
        Write-Log "Found installer: $installScript"
        break
    }
}

if (-not $installScript) {
    # Installer not found — try to use deploy dir as source dir
    $candidate = Join-Path $DeployDir 'install.ps1'
    if (-not (Test-Path $candidate)) {
        Write-Log "ERROR: install.ps1 not found. Cannot install CoinShield." 'ERROR'
        Write-Log "Upload install.ps1 to GCS source or include it in the staging directory."
        exit 1
    }
    $installScript = $candidate
}

# ── Step 5: Run installer ─────────────────────────────────────────────────────
Write-Log "Running installer: mode=$csMode silent=true autoInstallDotNet=true"

try {
    # Determine source dir: where binaries are
    $installSourceDir = Split-Path $installScript -Parent

    $installArgs = @(
        '-ExecutionPolicy', 'Bypass',
        '-File', $installScript,
        '-Silent',
        '-Mode', $csMode,
        '-AutoInstallDotNet',
        '-SourceDir', $installSourceDir
    )

    $proc = Start-Process powershell.exe `
        -ArgumentList $installArgs `
        -Wait -PassThru -NoNewWindow

    if ($proc.ExitCode -eq 0) {
        Write-Log "Installer completed successfully (exit code 0)."
    } else {
        Write-Log "Installer exited with code $($proc.ExitCode)." 'WARNING'
    }
} catch {
    Write-Log "Installer execution failed: $_" 'ERROR'
    exit 1
}

# ── Step 6: Verify service started ────────────────────────────────────────────
Write-Log "Verifying service status..."

Start-Sleep -Seconds 5

$svc = Get-Service -Name 'CoinShield' -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq 'Running') {
        Write-Log "SUCCESS: CoinShield service is RUNNING."
    } else {
        Write-Log "WARNING: CoinShield service status = $($svc.Status). Check Event Log." 'WARNING'
    }
} else {
    Write-Log "ERROR: CoinShield service not found after install." 'ERROR'
    exit 1
}

$wdSvc = Get-Service -Name 'CoinShieldWatchdog' -ErrorAction SilentlyContinue
if ($wdSvc) {
    Write-Log "Watchdog service status: $($wdSvc.Status)"
} else {
    Write-Log "Watchdog service not installed (may have been skipped)." 'WARNING'
}

# ── Step 7: Write success event ───────────────────────────────────────────────
try {
    Write-EventLog -LogName Application -Source 'CoinShield-Startup' `
        -EventId 1002 -EntryType Information `
        -Message "CoinShield startup script completed successfully.`nInstance: $gcpInstanceName`nProject: $gcpProject`nZone: $gcpZone`nMode: $csMode`nService status: $($svc?.Status)"
} catch { <# non-fatal #> }

Write-Log "=== Startup script completed successfully ==="
Write-Log "Log file: $ScriptLogFile"

exit 0
