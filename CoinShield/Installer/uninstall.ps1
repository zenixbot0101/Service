#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CoinShield Anti-Mining Service — Uninstaller

.DESCRIPTION
    Cleanly removes CoinShield from the system.

    Steps performed:
      1.  Verify administrator privileges
      2.  Stop CoinShield service
      3.  Stop CoinShield Watchdog service
      4.  Remove service registrations (sc delete)
      5.  Remove application binaries
      6.  Remove Event Log sources
      7.  Optionally remove log files and incident bundles
      8.  Never removes unrelated Windows files

.PARAMETER InstallDir
    Installation directory to remove.
    Default: C:\Program Files\CoinShield

.PARAMETER RemoveLogs
    Also delete log files and incident evidence bundles.
    Default: $false  (logs are preserved by default)

.PARAMETER RemoveEventLogSource
    Remove the Windows Event Log source registration.
    Default: $true

.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -RemoveLogs
    .\uninstall.ps1 -InstallDir "D:\Security\CoinShield" -RemoveLogs
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $InstallDir            = 'C:\Program Files\CoinShield',
    [switch] $RemoveLogs,
    [bool]   $RemoveEventLogSource  = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Colour helpers ────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "  [*] $msg" -ForegroundColor Cyan   }
function Write-Ok    { param($msg) Write-Host "  [+] $msg" -ForegroundColor Green  }
function Write-Warn  { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fatal { param($msg) Write-Host "  [X] $msg" -ForegroundColor Red; exit 1 }

$ServiceName  = 'CoinShield'
$WatchdogName = 'CoinShieldWatchdog'
$LogDir       = Join-Path $env:ProgramData 'CoinShield\Logs'

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '═══════════════════════════════════════════════════════' -ForegroundColor DarkCyan
Write-Host '  CoinShield Anti-Mining Service  —  Uninstaller v1.0'  -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════' -ForegroundColor DarkCyan
Write-Host ''

# ── Step 1: Administrator check ───────────────────────────────────────────────
Write-Step 'Verifying administrator privileges...'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fatal 'This uninstaller must be run as Administrator.'
}
Write-Ok 'Running as Administrator.'

# ── Helper: stop and remove a service ────────────────────────────────────────
function Remove-CoinShieldService {
    param([string]$name, [string]$displayName)

    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue

    if (-not $svc) {
        Write-Ok "$displayName is not installed — nothing to remove."
        return
    }

    # Step 2/3: Stop service
    Write-Step "Stopping service: $displayName ($name)..."
    if ($svc.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $name -Force
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            Write-Ok "Service stopped: $name"
        } catch {
            Write-Warn "Could not stop $name gracefully: $_ — forcing..."
            & sc.exe stop $name | Out-Null
            Start-Sleep -Seconds 5
        }
    } else {
        Write-Ok "Service already stopped: $name"
    }

    # Step 4: Remove service registration
    Write-Step "Removing service registration: $name..."
    $result = & sc.exe delete $name 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Service removed: $name"
    } else {
        Write-Warn "sc delete returned: $result"
    }
    Start-Sleep -Seconds 1
}

Remove-CoinShieldService $WatchdogName 'CoinShield Watchdog'
Remove-CoinShieldService $ServiceName  'CoinShield Anti-Mining Service'

# ── Step 5: Remove application binaries ──────────────────────────────────────
Write-Step "Removing installation directory: $InstallDir"

if (Test-Path $InstallDir) {
    # Safety check: only remove the CoinShield installation directory,
    # never anything outside it or unrelated Windows paths.
    $normalised = (Resolve-Path $InstallDir).Path
    $safeRoots  = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        (Join-Path $env:SystemDrive 'CoinShield')
    ) | Where-Object { $_ } | ForEach-Object { (Resolve-Path $_ -ErrorAction SilentlyContinue)?.Path }

    $isSafe = $safeRoots | Where-Object {
        $_ -and $normalised.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase)
    }

    if (-not $isSafe) {
        Write-Warn "InstallDir '$InstallDir' is outside expected locations — skipping removal."
        Write-Warn "Manually delete: $InstallDir"
    } else {
        # Only remove known CoinShield files, not arbitrary content
        $safeExtensions = @('.exe', '.dll', '.json', '.config', '.pdb', '.runtimeconfig.json')
        $removed = 0
        foreach ($f in Get-ChildItem -Path $InstallDir -File -ErrorAction SilentlyContinue) {
            if ($f.Extension -in $safeExtensions -or $f.Name -in @('config.json','allowlist.json')) {
                Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
                $removed++
            }
        }
        Write-Ok "Removed $removed files from $InstallDir"

        # Remove directory only if now empty
        $remaining = (Get-ChildItem -Path $InstallDir -ErrorAction SilentlyContinue).Count
        if ($remaining -eq 0) {
            Remove-Item -Path $InstallDir -Force -ErrorAction SilentlyContinue
            Write-Ok "Removed empty directory: $InstallDir"
        } else {
            Write-Ok "$remaining item(s) remain in $InstallDir (not removed)."
        }
    }
} else {
    Write-Ok "Installation directory not found: $InstallDir"
}

# ── Step 6: Remove Event Log sources ─────────────────────────────────────────
if ($RemoveEventLogSource) {
    Write-Step 'Removing Windows Event Log sources...'
    foreach ($src in @($ServiceName, $WatchdogName)) {
        try {
            if ([System.Diagnostics.EventLog]::SourceExists($src)) {
                [System.Diagnostics.EventLog]::DeleteEventSource($src)
                Write-Ok "Event Log source removed: $src"
            } else {
                Write-Ok "Event Log source not found: $src"
            }
        } catch {
            Write-Warn "Could not remove Event Log source '$src': $_"
        }
    }
}

# ── Step 7: Optionally remove logs ────────────────────────────────────────────
if ($RemoveLogs) {
    Write-Step "Removing log directory: $LogDir"
    if (Test-Path $LogDir) {
        # Safety: only remove files inside the CoinShield log folder
        $logNorm = (Resolve-Path $LogDir).Path
        $safeLogRoot = (Resolve-Path (Join-Path $env:ProgramData 'CoinShield') -ErrorAction SilentlyContinue)?.Path

        if ($safeLogRoot -and $logNorm.StartsWith($safeLogRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -Path $LogDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "Log directory removed: $LogDir"

            # Remove parent CoinShield data dir if empty
            $parent = Split-Path $LogDir -Parent
            if ((Get-ChildItem $parent -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item $parent -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Warn "Log directory is outside expected location — not removed."
        }
    } else {
        Write-Ok "Log directory not found: $LogDir"
    }
} else {
    Write-Ok "Log files preserved (use -RemoveLogs to delete): $LogDir"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '─── Uninstallation Summary ─────────────────────────────' -ForegroundColor DarkCyan
Write-Host "  CoinShield service:  $(if (Get-Service $ServiceName  -ErrorAction SilentlyContinue) { 'STILL PRESENT' } else { 'REMOVED' })"
Write-Host "  Watchdog service:    $(if (Get-Service $WatchdogName -ErrorAction SilentlyContinue) { 'STILL PRESENT' } else { 'REMOVED' })"
Write-Host "  Binaries:            $(if (Test-Path $InstallDir) { 'PARTIAL — see above' } else { 'REMOVED' })"
Write-Host "  Logs:                $(if ($RemoveLogs) { 'REMOVED' } else { "PRESERVED at $LogDir" })"
Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkCyan
Write-Host ''
Write-Ok 'CoinShield uninstallation complete.'
Write-Host ''
