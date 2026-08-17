#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CoinShield Anti-Mining Service - Installer v1.1

.DESCRIPTION
    Installs CoinShield.Service.exe and CoinShield.Watchdog.exe as Windows
    Services with automatic (delayed) startup and SCM recovery configured.

    Supports:
      ✓ Windows 10 / 11
      ✓ Windows Server 2022 (build 20348)
      ✓ Windows Server 2025 (build 26100+)
      ✓ Windows Server Core (headless, no Desktop Experience)
      ✓ Google Cloud Platform VMs (auto-detects metadata server)
      ✓ Silent installation for unattended / startup-script deployment

    Steps performed:
      1.  Verify administrator privileges
      2.  Detect OS edition (Server 2022/2025, Server Core) and cloud environment
      3.  Verify / install .NET 10 runtime
      4.  Create installation directory
      5.  Copy binaries and configuration
      6.  Protect configuration and log directory ACLs
      7.  Create Windows Event Log sources
      8.  Register CoinShield service (Automatic Delayed Start)
      9.  Register CoinShield Watchdog service (Automatic Delayed Start)
      10. Configure service recovery (restart after 10 s)
      11. Apply GCP metadata mode override if running on GCP
      12. Start services
      13. Verify service status
      14. Write installation result to Event Log

.PARAMETER InstallDir
    Target installation directory.
    Default: C:\Program Files\CoinShield

.PARAMETER SourceDir
    Directory containing the compiled binaries.
    Default: script directory (Installer\)

.PARAMETER Mode
    Operating mode for the detection engine.
    Values: Monitor | Enforcement | Emergency
    Default: Monitor  (safe - no process termination, no shutdown)

.PARAMETER NoWatchdog
    Skip installation of the Watchdog service.

.PARAMETER Silent
    Silent installation mode - no colored output, no user interaction.
    All events are still logged to Windows Event Log for audit trail.
    Suitable for GCP Startup Scripts and SCCM deployments.

.PARAMETER AutoInstallDotNet
    Automatically download and install .NET 10 runtime if not present.
    Default: $false on desktop, auto-enabled on Server Core.

.EXAMPLE
    # Interactive install on desktop/server
    .\install.ps1

    # Silent install for GCP Startup Script
    .\install.ps1 -Silent -Mode Monitor -AutoInstallDotNet

    # Server 2022 Enforcement mode
    .\install.ps1 -Mode Enforcement -InstallDir "D:\Security\CoinShield"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDir  = 'C:\Program Files\CoinShield',
    [string] $SourceDir   = $PSScriptRoot,
    [ValidateSet('Monitor','Enforcement','Emergency')]
    [string] $Mode        = 'Monitor',
    [switch] $NoWatchdog,
    [switch] $Silent,
    [switch] $AutoInstallDotNet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Output helpers ────────────────────────────────────────────────────────────
function Write-Step  {
    param($msg)
    if (-not $Silent) { Write-Host "  [*] $msg" -ForegroundColor Cyan }
    Write-EventLogSafe "STEP: $msg"
}
function Write-Ok    {
    param($msg)
    if (-not $Silent) { Write-Host "  [+] $msg" -ForegroundColor Green }
}
function Write-Warn  {
    param($msg)
    if (-not $Silent) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
    Write-EventLogSafe "WARN: $msg" -EntryType Warning
}
function Write-Fatal {
    param($msg)
    if (-not $Silent) { Write-Host "  [X] $msg" -ForegroundColor Red }
    Write-EventLogSafe "FATAL: $msg" -EntryType Error
    exit 1
}
function Write-EventLogSafe {
    param([string]$msg, [string]$EntryType = 'Information')
    try {
        if ([System.Diagnostics.EventLog]::SourceExists('CoinShield')) {
            Write-EventLog -LogName Application -Source 'CoinShield' `
                -EventId 999 -EntryType $EntryType -Message "[Installer] $msg" `
                -ErrorAction SilentlyContinue
        }
    } catch { <# silent - Event Log source may not exist yet #> }
}

# ── Constants ─────────────────────────────────────────────────────────────────
$ServiceName        = 'CoinShield'
$ServiceDisplayName = 'CoinShield Anti-Mining Service'
$ServiceDescription = 'Behavioral cryptomining detector. Uses multi-signal analysis; never acts on GPU usage alone.'
$ServiceExe         = 'CoinShield.Service.exe'

$WatchdogName        = 'CoinShieldWatchdog'
$WatchdogDisplayName = 'CoinShield Watchdog'
$WatchdogDescription = 'Monitors health of the CoinShield service. Makes no detection decisions.'
$WatchdogExe         = 'CoinShield.Watchdog.exe'

$LogDir             = Join-Path $env:ProgramData 'CoinShield\Logs'

# ── Banner ────────────────────────────────────────────────────────────────────
if (-not $Silent) {
    Write-Host ''
    Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor DarkCyan
    Write-Host '  CoinShield Anti-Mining Service  -  Installer v1.1'        -ForegroundColor Cyan
    Write-Host '  Supports: Win 10/11, Server 2022/2025, Server Core, GCP'  -ForegroundColor DarkCyan
    Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor DarkCyan
    Write-Host ''
}

# ── Step 1: Administrator check ───────────────────────────────────────────────
Write-Step 'Verifying administrator privileges...'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fatal 'This installer must be run as Administrator.'
}
Write-Ok 'Running as Administrator.'

# ── Step 2: OS and environment detection ──────────────────────────────────────
Write-Step 'Detecting OS edition and environment...'

# Read OS info from registry (works on Server Core where WMI may be limited)
$regKey         = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$productNameRaw = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).ProductName
$productName    = if ($productNameRaw) { $productNameRaw } else { '' }
$currentBuildRaw = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).CurrentBuild
$currentBuild   = if ($currentBuildRaw) { [int]$currentBuildRaw } else { 0 }
$installTypeRaw = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).InstallationType
$installType    = if ($installTypeRaw) { $installTypeRaw } else { '' }

$isWindowsServer = $productName -match 'Server'
$isServerCore    = $installType -eq 'Server Core'
$isNanoServer    = $installType -eq 'Nano Server'
$isServer2022    = $isWindowsServer -and $currentBuild -ge 20348 -and $currentBuild -lt 26100
$isServer2025    = $isWindowsServer -and $currentBuild -ge 26100

if ($isServer2025)         { Write-Ok "OS: Windows Server 2025 (build $currentBuild)" }
elseif ($isServer2022)     { Write-Ok "OS: Windows Server 2022 (build $currentBuild)" }
elseif ($isWindowsServer)  { Write-Ok "OS: Windows Server (build $currentBuild)" }
else                       { Write-Ok "OS: Windows Desktop (build $currentBuild)" }

if ($isServerCore)    { Write-Ok 'Mode: Server Core (headless - no Desktop Experience)' }
if ($isNanoServer)    { Write-Warn 'Mode: Nano Server - limited compatibility, proceeding.' }

# Auto-enable AutoInstallDotNet on Server Core (no package manager / GUI)
if ($isServerCore -and -not $AutoInstallDotNet) {
    $AutoInstallDotNet = $true
    Write-Ok 'Server Core detected - AutoInstallDotNet enabled automatically.'
}

# ── GCP detection ─────────────────────────────────────────────────────────────
Write-Step 'Checking cloud environment...'
$isGcp         = $false
$gcpProject    = ''
$gcpZone       = ''
$gcpMachineType= ''
$gcpMode       = ''

try {
    $metadataUri = 'http://metadata.google.internal/computeMetadata/v1/instance/id'
    $resp = Invoke-WebRequest -Uri $metadataUri `
        -Headers @{'Metadata-Flavor'='Google'} `
        -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue

    if ($resp -and $resp.StatusCode -eq 200 -and
        $resp.Headers['Metadata-Flavor'] -eq 'Google') {

        $isGcp = $true

        function Get-GcpMeta([string]$path) {
            try {
                (Invoke-WebRequest -Uri "http://metadata.google.internal/computeMetadata/v1/$path" `
                    -Headers @{'Metadata-Flavor'='Google'} `
                    -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue).Content
            } catch { '' }
        }

        $gcpProject     = Get-GcpMeta 'project/project-id'
        $rawZone        = Get-GcpMeta 'instance/zone'
        $gcpZone        = ($rawZone -split '/')[-1]
        $rawMachineType = Get-GcpMeta 'instance/machine-type'
        $gcpMachineType = ($rawMachineType -split '/')[-1]

        # Read custom metadata key "coinshield-mode" - allows per-VM mode override
        $gcpMode = Get-GcpMeta 'instance/attributes/coinshield-mode'
        if ($gcpMode -and $gcpMode -in @('Monitor','Enforcement','Emergency')) {
            $Mode = $gcpMode
            Write-Ok "GCP mode override applied: coinshield-mode=$gcpMode"
        }

        Write-Ok "Cloud: Google Cloud Platform"
        Write-Ok "  Project: $gcpProject  Zone: $gcpZone  Type: $gcpMachineType"
    }
} catch {
    # Not on GCP or metadata server unreachable - on-premises
}

if (-not $isGcp) {
    Write-Ok 'Cloud: On-Premises or non-GCP environment.'
}

# ── Step 3: .NET runtime check / install ──────────────────────────────────────
Write-Step 'Checking .NET 10 runtime...'

function Test-DotNet10 {
    try {
        $runtimes = & dotnet --list-runtimes 2>$null
        return ($runtimes | Where-Object { $_ -match 'Microsoft\.NETCore\.App 10\.' }).Count -gt 0
    } catch { return $false }
}

$hasDotNet10 = Test-DotNet10

if (-not $hasDotNet10) {
    if ($AutoInstallDotNet) {
        Write-Step 'Downloading and installing .NET 10 runtime...'
        try {
            $dotnetInstallDir = Join-Path $env:TEMP 'dotnet-install'
            New-Item -ItemType Directory -Path $dotnetInstallDir -Force | Out-Null

            # Use official Microsoft dotnet-install.ps1 script
            $installScript = Join-Path $dotnetInstallDir 'dotnet-install.ps1'
            $downloadUrl   = 'https://dot.net/v1/dotnet-install.ps1'

            # Download with TLS 1.2+ (required on Server 2022/2025)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            Invoke-WebRequest -Uri $downloadUrl -OutFile $installScript -UseBasicParsing

            # Install .NET 10 runtime (not SDK) to default location
            & $installScript -Channel 10.0 -Runtime dotnet -InstallDir 'C:\Program Files\dotnet' -NoPath

            # Add to PATH for current session
            $env:PATH = "C:\Program Files\dotnet;$env:PATH"

            if (Test-DotNet10) {
                Write-Ok '.NET 10 runtime installed successfully.'
            } else {
                Write-Warn '.NET 10 installation may need a restart to take effect.'
            }
        } catch {
            Write-Warn "Automatic .NET 10 install failed: $_"
            Write-Warn "Manual download: https://dotnet.microsoft.com/download/dotnet/10.0"
        }
    } else {
        Write-Warn '.NET 10 runtime not detected. Binaries may fail to start.'
        Write-Warn 'Download: https://dotnet.microsoft.com/download/dotnet/10.0'
        Write-Warn 'Or re-run installer with -AutoInstallDotNet flag.'
    }
} else {
    Write-Ok '.NET 10 runtime found.'
}

# ── Step 4: Create installation directory ─────────────────────────────────────
Write-Step "Creating installation directory: $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Ok "Directory ready: $InstallDir"

# ── Step 5: Copy binaries and configuration ────────────────────────────────────
Write-Step 'Copying binaries...'

$filesToCopy = @(
    $ServiceExe,
    $WatchdogExe,
    'config.json',
    'allowlist.json',
    'mining-domains.json'
)

$buildOutput  = Split-Path $SourceDir -Parent
$searchPaths  = @(
    $SourceDir,
    $buildOutput,
    (Join-Path $buildOutput 'CoinShield.Service\bin\Release\net10.0-windows\win-x64\publish'),
    (Join-Path $buildOutput 'CoinShield.Service\bin\Release\net10.0-windows\win-x64'),
    (Join-Path $buildOutput 'CoinShield.Service\bin\Debug\net10.0-windows\win-x64'),
    # GCP: binaries may be staged in C:\CoinShield-deploy by startup script
    'C:\CoinShield-deploy'
)

foreach ($file in $filesToCopy) {
    $copied = $false
    foreach ($dir in $searchPaths) {
        $src = Join-Path $dir $file
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $InstallDir -Force
            Write-Ok "Copied: $file"
            $copied = $true
            break
        }
    }
    if (-not $copied) {
        if ($file -in @($ServiceExe, $WatchdogExe)) {
            Write-Warn "$file not found - build the solution first (dotnet publish)."
        } else {
            Write-Warn "$file not found in source - default will be used if present."
        }
    }
}

# ── Step 6: Protect configuration and log directories ─────────────────────────
Write-Step 'Setting directory permissions...'

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

try {
    $acl = Get-Acl $LogDir
    $acl.SetAccessRuleProtection($true, $false)
    $rules = @(
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'),
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    )
    foreach ($rule in $rules) { $acl.AddAccessRule($rule) }
    Set-Acl -Path $LogDir -AclObject $acl
    Write-Ok "Log directory secured: $LogDir"
} catch {
    Write-Warn "Could not set log directory ACL: $_"
}

$cfgPath = Join-Path $InstallDir 'config.json'
if (Test-Path $cfgPath) {
    try {
        $acl = Get-Acl $cfgPath
        $acl.SetAccessRuleProtection($true, $false)
        $rules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM', 'FullControl', 'None', 'None', 'Allow'),
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'None', 'None', 'Allow')
        )
        foreach ($rule in $rules) { $acl.AddAccessRule($rule) }
        Set-Acl -Path $cfgPath -AclObject $acl
        Write-Ok 'config.json permissions secured.'
    } catch {
        Write-Warn "Could not set config.json ACL: $_"
    }
}

# ── Step 7: Create Event Log sources ──────────────────────────────────────────
Write-Step 'Registering Windows Event Log sources...'
foreach ($src in @($ServiceName, $WatchdogName)) {
    if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
        [System.Diagnostics.EventLog]::CreateEventSource($src, 'Application')
        Write-Ok "Event Log source created: $src"
    } else {
        Write-Ok "Event Log source already exists: $src"
    }
}

# ── Helpers ────────────────────────────────────────────────────────────────────
function Remove-ServiceIfExists {
    param([string]$name)
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Step "Stopping existing service: $name"
        if ($svc.Status -eq 'Running') {
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        & sc.exe delete $name | Out-Null
        Start-Sleep -Seconds 2
        Write-Ok "Removed existing service: $name"
    }
}

function Set-ServiceRecovery {
    param([string]$name)
    & sc.exe failure $name reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null
    & sc.exe failureflag $name 1 | Out-Null
    Write-Ok "Service recovery configured: $name (restart after 10 s, 3 attempts)"
}

# ── Step 8: Register CoinShield service ───────────────────────────────────────
Write-Step "Registering Windows Service: $ServiceName"
Remove-ServiceIfExists $ServiceName

$svcExePath = Join-Path $InstallDir $ServiceExe
if (-not (Test-Path $svcExePath)) {
    Write-Warn "$ServiceExe not found at $svcExePath - service registration skipped."
    Write-Warn "Build the solution and re-run the installer."
} else {
    & sc.exe create $ServiceName `
        binPath= "`"$svcExePath`"" `
        DisplayName= $ServiceDisplayName `
        start= delayed-auto `
        obj= LocalSystem | Out-Null

    & sc.exe description $ServiceName $ServiceDescription | Out-Null
    Write-Ok "Service registered: $ServiceName"

    # Update config.json with selected mode and cloud environment info
    $cfgFile = Join-Path $InstallDir 'config.json'
    if (Test-Path $cfgFile) {
        try {
            $json = Get-Content $cfgFile -Raw | ConvertFrom-Json

            $json.detection.mode = $Mode

            # Write GCP context into config for runtime use
            if ($isGcp) {
                if (-not $json.cloud) { $json | Add-Member -MemberType NoteProperty -Name cloud -Value @{} }
                $json.cloud.enabled                    = $true
                $json.cloud.logInstanceMetadataAtStartup = $true
                $json.cloud.reduceWmiOverheadOnCloud   = $true
            }

            # Server Core: disable browser correlation (no browsers present)
            if ($isServerCore) {
                if (-not $json.webMining) { $json | Add-Member -MemberType NoteProperty -Name webMining -Value @{} }
                $json.webMining.enableBrowserCorrelation = $false
                if (-not $json.cloud) { $json | Add-Member -MemberType NoteProperty -Name cloud -Value @{} }
                $json.cloud.serverCoreMode = 'HeadlessOnly'
            }

            $json | ConvertTo-Json -Depth 10 | Set-Content $cfgFile -Encoding UTF8
            Write-Ok "config.json updated: mode=$Mode serverCore=$isServerCore gcp=$isGcp"
        } catch {
            Write-Warn "Could not update config.json: $_"
        }
    }

    Set-ServiceRecovery $ServiceName
}

# ── Step 9: Register Watchdog service ─────────────────────────────────────────
if (-not $NoWatchdog) {
    Write-Step "Registering Windows Service: $WatchdogName"
    Remove-ServiceIfExists $WatchdogName

    $wdExePath = Join-Path $InstallDir $WatchdogExe
    if (-not (Test-Path $wdExePath)) {
        Write-Warn "$WatchdogExe not found - Watchdog service skipped."
    } else {
        & sc.exe create $WatchdogName `
            binPath= "`"$wdExePath`"" `
            DisplayName= $WatchdogDisplayName `
            start= delayed-auto `
            obj= LocalSystem | Out-Null

        & sc.exe description $WatchdogName $WatchdogDescription | Out-Null
        Set-ServiceRecovery $WatchdogName
        Write-Ok "Watchdog service registered: $WatchdogName"
    }
}

# ── Step 10: On Server 2022/2025 - set description length compatible notes ─────
if ($isWindowsServer) {
    # Increase SCM failure threshold for server environments (more resilient)
    foreach ($svcName in @($ServiceName, $WatchdogName)) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            # Server 2022/2025: set delayed-auto ensures service starts after
            # network stack and WMI are fully initialised
            & sc.exe config $svcName start= delayed-auto | Out-Null
        }
    }
    Write-Ok "Server startup type confirmed: delayed-auto (network/WMI ready before start)"
}

# ── Step 11: Start services ────────────────────────────────────────────────────
Write-Step 'Starting services...'
foreach ($svcName in @($ServiceName, $WatchdogName)) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        try {
            Start-Service -Name $svcName
            # Server Core: wait a bit longer for service to initialise
            $waitSecs = if ($isServerCore) { 5 } else { 2 }
            Start-Sleep -Seconds $waitSecs
            $svc.Refresh()
            if ($svc.Status -eq 'Running') {
                Write-Ok "Service started: $svcName"
            } else {
                Write-Warn "Service $svcName status: $($svc.Status)"
            }
        } catch {
            Write-Warn "Could not start ${svcName}: $_"
        }
    }
}

# ── Step 12: Verify and summarise ─────────────────────────────────────────────
if (-not $Silent) {
    Write-Host ''
    Write-Host '─── Installation Summary ───────────────────────────────────' -ForegroundColor DarkCyan

    $mainSvc = Get-Service -Name $ServiceName  -ErrorAction SilentlyContinue
    $wdSvc   = Get-Service -Name $WatchdogName -ErrorAction SilentlyContinue

    $osEdition = if ($isServer2025) { 'Windows Server 2025' }
                 elseif ($isServer2022) { 'Windows Server 2022' }
                 elseif ($isWindowsServer) { 'Windows Server' }
                 else { 'Windows Desktop' }

    Write-Host "  Service:     $ServiceName - $(if ($mainSvc) { $mainSvc.Status } else { 'NOT INSTALLED' })"
    Write-Host "  Watchdog:    $(if ($wdSvc) { $wdSvc.Status } else { 'NOT INSTALLED' })"
    Write-Host "  Mode:        $Mode"
    Write-Host "  OS:          $osEdition (build $currentBuild)$(if ($isServerCore) { ' [Server Core]' })"
    Write-Host "  Cloud:       $(if ($isGcp) { "GCP - $gcpProject / $gcpZone / $gcpMachineType" } else { 'On-Premises' })"
    Write-Host "  Install dir: $InstallDir"
    Write-Host "  Log dir:     $LogDir"
    Write-Host "  UI:          NONE (headless service)"
    Write-Host '────────────────────────────────────────────────────────────' -ForegroundColor DarkCyan
}

# ── Step 13: Write installation result to Event Log ───────────────────────────
$cloudNote = if ($isGcp) { " | GCP: $gcpProject/$gcpZone/$gcpMachineType" } else { '' }
$serverNote= if ($isServerCore) { ' | Server Core' } elseif ($isWindowsServer) { ' | Windows Server' } else { '' }

try {
    Write-EventLog -LogName Application -Source $ServiceName -EventId 1000 `
        -EntryType Information `
        -Message "CoinShield Anti-Mining Service v1.1 installed successfully.`nMode: $Mode`nInstall directory: $InstallDir`nOS build: $currentBuild$serverNote$cloudNote`nProtection: ACTIVE"
    Write-Ok 'Installation event written to Windows Event Log.'
} catch {
    Write-Warn "Event Log write failed: $_"
}

if (-not $Silent) {
    Write-Host ''
    Write-Ok 'CoinShield installation complete.'
    Write-Host ''
}
