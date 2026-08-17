# CoinShield Installer

## Installation

### Interactive Installation (Default)
```powershell
# Run as Administrator
.\install.ps1
```

### Silent Installation
```powershell
# Run as Administrator - no output, no prompts
.\install.ps1 -Silent
```

### Custom Installation Directory
```powershell
.\install.ps1 -InstallDir "D:\Security\CoinShield"
```

### Install with Specific Mode
```powershell
# Monitor mode (safe - no termination)
.\install.ps1 -Mode Monitor

# Enforcement mode (terminates mining processes)
.\install.ps1 -Mode Enforcement -Silent

# Emergency mode (system shutdown on confirmed mining)
.\install.ps1 -Mode Emergency
```

### Skip Watchdog Service
```powershell
.\install.ps1 -NoWatchdog
```

## Features

✅ **Auto-start after installation** - Services start automatically after setup completes

✅ **Silent installation support** - Use `-Silent` flag for unattended deployment

✅ **Automatic service restart** - SCM recovery configured (3 restarts with 10s delay)

✅ **Administrator required** - UAC prompt ensures proper permissions

✅ **Low resource usage** - Targets < 1% CPU idle, < 100 MB RAM

✅ **Headless operation** - Runs as Windows Service (no UI)

✅ **Event Log audit trail** - All operations logged to Windows Event Log

## What Gets Installed

- **Service**: CoinShield (Automatic Delayed Start)
- **Watchdog**: CoinShieldWatchdog (Automatic Delayed Start)
- **Location**: `C:\Program Files\CoinShield\` (default)
- **Logs**: `C:\ProgramData\CoinShield\Logs\`
- **Configuration**: `config.json` and `allowlist.json`

## Verification

After installation, verify services are running:

```powershell
Get-Service CoinShield, CoinShieldWatchdog
```

Check Event Log for installation event:

```powershell
Get-EventLog -LogName Application -Source CoinShield -Newest 5
```

## Uninstallation

```powershell
# Run as Administrator
.\uninstall.ps1

# Remove logs during uninstall
.\uninstall.ps1 -RemoveLogs
```

## System Requirements

- Windows 10 or Windows Server 2016+
- .NET 10 Runtime (x64)
- Administrator privileges
- ~100 MB disk space

## Deployment Examples

### Group Policy / SCCM Deployment
```powershell
powershell.exe -ExecutionPolicy Bypass -File "\\server\share\install.ps1" -Silent -Mode Monitor
```

### Automated CI/CD Deployment
```powershell
.\install.ps1 -Silent -Mode Enforcement -InstallDir "C:\Program Files\CoinShield"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

### Manual Testing
```powershell
# Install in monitor mode first
.\install.ps1 -Mode Monitor

# Check logs and alerts, then upgrade to enforcement if needed
.\uninstall.ps1
.\install.ps1 -Mode Enforcement
```

## Configuration

After installation, you can modify settings in:
- `C:\Program Files\CoinShield\config.json`

**Restart the service** after configuration changes:
```powershell
Restart-Service CoinShield
```

## Support

All operations are logged to:
- **Windows Event Log**: Application → CoinShield
- **JSON Logs**: `C:\ProgramData\CoinShield\Logs\`

For debugging, check Event Viewer:
```
Event Viewer → Windows Logs → Application → Filter Current Log → Event sources: CoinShield, CoinShieldWatchdog
```
