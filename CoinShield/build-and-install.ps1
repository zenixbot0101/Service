#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Build and install CoinShield Anti-Mining Service

.DESCRIPTION
    Automated build, publish, and installation script for CoinShield.
    Requires Administrator privileges.

.PARAMETER SkipBuild
    Skip build step (use existing binaries in Installer/build)

.PARAMETER Mode
    Operating mode: Monitor, Enforcement, or Emergency
    Default: Enforcement

.EXAMPLE
    .\build-and-install.ps1
    
.EXAMPLE
    .\build-and-install.ps1 -Mode Monitor
    
.EXAMPLE
    .\build-and-install.ps1 -SkipBuild
#>

param(
    [switch]$SkipBuild,
    [ValidateSet('Monitor','Enforcement','Emergency')]
    [string]$Mode = 'Enforcement'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RootDir = Split-Path $PSScriptRoot -Parent
$SolutionDir = Join-Path $RootDir "CoinShield"

Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  CoinShield Build & Install Script                        ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ── Step 1: Check .NET SDK ───────────────────────────────────────────────────
Write-Host "📌 Checking .NET 10 SDK..." -ForegroundColor Yellow
try {
    $dotnetVersion = dotnet --version 2>$null
    if ($dotnetVersion -notmatch '^10\.') {
        Write-Host "❌ .NET 10 SDK not found. Current: $dotnetVersion" -ForegroundColor Red
        Write-Host "   Download: https://dotnet.microsoft.com/download/dotnet/10.0" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "✅ .NET SDK: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ .NET SDK not installed" -ForegroundColor Red
    Write-Host "   Download: https://dotnet.microsoft.com/download/dotnet/10.0" -ForegroundColor Yellow
    exit 1
}

# ── Step 2: Build ─────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Push-Location $SolutionDir
    try {
        Write-Host "`n🧹 Cleaning..." -ForegroundColor Yellow
        dotnet clean | Out-Null

        Write-Host "📦 Restoring packages..." -ForegroundColor Yellow
        dotnet restore CoinShield.sln
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Package restore failed!" -ForegroundColor Red
            exit 1
        }

        Write-Host "🔨 Building solution..." -ForegroundColor Yellow
        dotnet build CoinShield.sln -c Release
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Build failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host "✅ Build succeeded" -ForegroundColor Green

        Write-Host "`n📦 Publishing CoinShield.Service..." -ForegroundColor Yellow
        dotnet publish CoinShield.Service/CoinShield.Service.csproj -c Release -r win-x64 --self-contained false -o Installer/build | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Service publish failed!" -ForegroundColor Red
            exit 1
        }

        Write-Host "📦 Publishing CoinShield.Watchdog..." -ForegroundColor Yellow
        dotnet publish CoinShield.Watchdog/CoinShield.Watchdog.csproj -c Release -r win-x64 --self-contained false -o Installer/build | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Watchdog publish failed!" -ForegroundColor Red
            exit 1
        }

        Write-Host "📄 Copying config files..." -ForegroundColor Yellow
        Copy-Item CoinShield.Configuration/*.json Installer/build/ -Force

        Write-Host "`n✅ Build complete!`n" -ForegroundColor Green
        
        Write-Host "📊 Output files:" -ForegroundColor Cyan
        Get-ChildItem Installer\build\*.exe, Installer\build\*.json | 
            Select-Object Name, @{Name="Size";Expression={"$([math]::Round($_.Length/1KB,1)) KB"}} |
            Format-Table -AutoSize
    }
    finally {
        Pop-Location
    }
} else {
    Write-Host "⏭️  Skipping build (using existing binaries)" -ForegroundColor Yellow
}

# ── Step 3: Install ───────────────────────────────────────────────────────────
Write-Host "`n🚀 Installing CoinShield (Mode: $Mode)..." -ForegroundColor Cyan
$installerPath = Join-Path $SolutionDir "Installer\install.ps1"

& $installerPath -Silent -Mode $Mode

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Installation complete!`n" -ForegroundColor Green
    
    # Verify services
    Write-Host "📊 Service status:" -ForegroundColor Cyan
    Get-Service CoinShield, CoinShieldWatchdog | 
        Format-Table Status, Name, DisplayName -AutoSize
    
    Write-Host "`n💡 View logs:" -ForegroundColor Yellow
    Write-Host "   Get-EventLog -LogName Application -Source CoinShield -Newest 10" -ForegroundColor Gray
} else {
    Write-Host "`n❌ Installation failed!" -ForegroundColor Red
    exit 1
}
