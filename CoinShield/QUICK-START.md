# 🚀 CoinShield Quick Start Guide

## ✅ Build Complete!

All files are ready in `Installer\build\`:
- ✅ CoinShield.Service.exe (3.95 MB)
- ✅ CoinShield.Watchdog.exe (2.46 MB)
- ✅ config.json, allowlist.json, mining-domains.json

---

## 📦 Installation Methods

### **Method 1: Double-Click (EASIEST)**

Simply **double-click** `INSTALL-ME.bat` and click **Yes** when UAC prompts.

---

### **Method 2: PowerShell (Manual)**

1. Right-click **PowerShell** → **Run as Administrator**
2. Run:
```powershell
cd C:\Users\dung\Downloads\Anti\CoinShield\Installer
.\install.ps1 -Silent -Mode Enforcement
```

---

### **Method 3: Automated Script**

```powershell
cd C:\Users\dung\Downloads\Anti\CoinShield
.\build-and-install.ps1 -SkipBuild -Mode Enforcement
```

---

## 🔍 Verify Installation

```powershell
# Check service status
Get-Service CoinShield, CoinShieldWatchdog

# Expected output:
# Status   Name               DisplayName
# ------   ----               -----------
# Running  CoinShield         CoinShield Anti-Mining Service
# Running  CoinShieldWatchdog CoinShield Watchdog
```

---

## 📊 View Logs

```powershell
# Event Log
Get-EventLog -LogName Application -Source CoinShield -Newest 10

# JSON Logs
Get-Content "C:\ProgramData\CoinShield\Logs\coinshield-*.json" -Tail 20
```

---

## ⚙️ Operating Modes

| Mode | When to Use | Action on Detection |
|------|-------------|---------------------|
| **Monitor** | Testing, development | Log only (no termination) |
| **Enforcement** | Production (recommended) | Terminate mining process |
| **Emergency** | High-security environments | Terminate + shutdown system |

---

## 🔧 Configuration

Edit: `C:\Program Files\CoinShield\config.json`

After editing, restart service:
```powershell
Restart-Service CoinShield
```

---

## 🛑 Uninstall

```powershell
cd C:\Users\dung\Downloads\Anti\CoinShield\Installer
.\uninstall.ps1
```

---

## 📚 Full Documentation

- **README.md** - Complete technical reference (6000+ lines)
- **HUONG-DAN.md** - Vietnamese deployment guide
- **Installer/HUONG-DAN.md** - Quick installation guide

---

## 🆘 Troubleshooting

### Service not starting?
```powershell
# Check .NET 10 Runtime
dotnet --version

# View errors
Get-EventLog -LogName Application -Source CoinShield -EntryType Error -Newest 5
```

### False positive?
Add to allowlist: `C:\Program Files\CoinShield\allowlist.json`

Then restart:
```powershell
Restart-Service CoinShield
```

---

## 🎯 Next Steps

1. **Install** using one of the methods above
2. **Verify** service is running
3. **Check logs** to confirm detection is active
4. **Monitor** Event Log for mining detection alerts

---

**Repository:** https://github.com/zenixbot0101/Service

**Version:** 1.1.0

**Last Updated:** 2026-08-17
