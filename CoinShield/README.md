# CoinShield — Headless Anti-Cryptomining Windows Service

<p align="center">
  <strong>Version 1.1.0</strong> &nbsp;|&nbsp;
  Windows 10/11 &nbsp;|&nbsp; Server 2022 &nbsp;|&nbsp; Server 2025 &nbsp;|&nbsp; Server Core &nbsp;|&nbsp; Google Cloud VM
</p>

---

> **Core principle:** CoinShield is a *behavioral* detector, not a GPU-usage detector.
> A process at GPU 99% may be training an AI model, rendering video, or running a game.
> Mining is identified only when **multiple independent signals converge** — and every
> decision is independently re-verified before any action is taken.

---

## Table of Contents

1. [What CoinShield Does](#1-what-coinshield-does)
2. [What CoinShield Does NOT Do](#2-what-coinshield-does-not-do)
3. [Architecture Overview](#3-architecture-overview)
4. [Project Structure](#4-project-structure)
5. [System Requirements](#5-system-requirements)
6. [Building from Source](#6-building-from-source)
7. [Installation](#7-installation)
   - [Interactive Install](#71-interactive-install)
   - [Silent Install](#72-silent-install)
   - [Windows Server 2022 / 2025](#73-windows-server-2022--2025)
   - [Server Core (Headless)](#74-server-core-headless)
   - [Google Cloud Platform VM](#75-google-cloud-platform-vm)
   - [Group Policy / SCCM](#76-group-policy--sccm)
8. [Configuration Reference](#8-configuration-reference)
9. [Operating Modes](#9-operating-modes)
10. [Detection Signals & Scoring](#10-detection-signals--scoring)
11. [AI Workload Protection](#11-ai-workload-protection)
12. [Web Mining Protection](#12-web-mining-protection)
13. [Bypass Resistance](#13-bypass-resistance)
14. [Allowlist Management](#14-allowlist-management)
15. [Logs and Evidence](#15-logs-and-evidence)
16. [Service Management](#16-service-management)
17. [Uninstallation](#17-uninstallation)
18. [Troubleshooting](#18-troubleshooting)
19. [Security Notes](#19-security-notes)
20. [FAQ](#20-faq)

---

## 1. What CoinShield Does

CoinShield runs as a **headless Windows Service** (no UI, no console, no tray icon) and:

- **Monitors** all running processes, GPU/CPU usage, network connections, DNS queries, and persistence locations continuously
- **Scores** each process using 14+ weighted signals: path risk, command-line patterns, Stratum protocol, network behavior, persistence, known hashes, browser WebAssembly activity, and more
- **Correlates** signals over time using a state machine with a mandatory confirmation window
- **Protects** legitimate AI/ML workloads from false positives using a dedicated AI classifier
- **Detects** browser-based mining (JavaScript/WebAssembly) including Coinhive-style attacks
- **Blocks** known mining domains via the Windows hosts file
- **Acts** in three configurable modes: Monitor (log only), Enforcement (terminate process), Emergency (terminate + shutdown)
- **Resists** evasion: VPN tunnels, localhost stratum proxy, DNS-over-HTTPS, throttled CPU, process hollowing, signed-binary abuse

---

## 2. What CoinShield Does NOT Do

| What it does NOT do | Why |
|---|---|
| Act on GPU usage alone | GPU 99% is normal for gaming, AI training, video rendering |
| Shut down for crypto-related domain names | "bitcoin.org", "coinbase.com" are legitimate sites |
| Terminate browsers | Only terminates specific mining tab/renderer, never entire browser |
| Require internet connectivity | All detection is fully offline |
| Phone home or send telemetry | No outbound connections initiated by CoinShield itself |
| Modify system files | Only modifies `hosts` file when blocking confirmed mining domains |

---

## 3. Architecture Overview

```
Windows Boot
     │
     ▼
CoinShield.Service.exe  ──  Automatic Delayed Start  ──  LocalSystem
     │
     ├─ CloudEnvironment  (startup: GCP/Azure/AWS detect, OS edition, Server Core)
     │
     ├─ Worker  (1-second tick loop)
     │     │
     │     ├─ CpuAnalyzer         every  1 s  — system + per-process CPU delta
     │     ├─ GpuAnalyzer         every  1 s  — GPU Engine perf counters, VRAM
     │     ├─ ProcessAnalyzer     every  2 s  — enumerate, path, cmd-line, hash, signature
     │     ├─ NetworkAnalyzer     every  5 s  — TCP table, mining port/hostname/loopback
     │     ├─ PersistenceAnalyzer every 30 s  — registry, startup, tasks, services, WMI
     │     │
     │     ├─ DnsAnalyzer         every  5 s  — DNS cache + DoH detection + direct-IP
     │     └─ WebMiningDetector   every  5 s  — browser process + renderer + WASM
     │
     ├─ RiskScorer  (14+ weighted signals → total score)
     │     └─ AllowlistEngine  (trusted publishers / paths / hashes / AI frameworks)
     │
     ├─ CorrelationEngine  (state machine + confirmation window)
     │     Normal → Suspicious → Analyzing → AiWorkload / HighRisk → ConfirmedMining
     │
     └─ ResponseEngine  (ONLY component allowed to act)
           │  Re-verifies ALL 4 gates independently before acting
           ├─ BlockDomain     → adds 0.0.0.0 entry to hosts file
           ├─ TerminateTab    → kills specific browser renderer (not whole browser)
           ├─ TerminateProcess→ kills confirmed miner (Enforcement mode)
           └─ Shutdown        → initiates OS shutdown (Emergency mode only)

CoinShield.Watchdog.exe  ──  Monitors CoinShield service health  ──  No detection
```

### Confirmation Gates (all four must pass simultaneously)

```
Gate 1: Score  ≥  85      (configurable confirmedMiningThreshold)
Gate 2: Strong indicators ≥ 2  (independent signals, not correlated)
Gate 3: AI confidence  < 0.65  (process not classified as AI workload)
Gate 4: Confirmation window  ≥ 60 s  (sustained behavior, not a spike)
```

---

## 4. Project Structure

```
CoinShield/
├── CoinShield.Service/              # Windows Service entry point
│   ├── Program.cs                   # Host builder, cloud env init, GCP mode override
│   ├── Worker.cs                    # BackgroundService — 1-second tick loop
│   ├── ServiceHost.cs               # Service constants, startup banner
│   ├── ServiceRegistration.cs       # Full DI wiring
│   └── app.manifest                 # UAC manifest, Server 2022/2025 compatibility IDs
│
├── CoinShield.Core/                 # All detection logic
│   ├── DetectionEngine.cs           # Orchestrator — interval scheduling
│   ├── RiskScorer.cs                # 14+ weighted signals → risk score
│   ├── CorrelationEngine.cs         # State machine + FirstSuspicionTime window
│   ├── ResponseEngine.cs            # ONLY component that terminates/shuts down
│   ├── ProcessAnalyzer.cs           # Path, cmd-line, tree, hash, signature, GetOwner
│   ├── NetworkAnalyzer.cs           # TCP table, mining ports, loopback proxy detection
│   ├── GpuAnalyzer.cs               # Batch-primed perf counters (single sleep), VRAM
│   ├── CpuAnalyzer.cs               # System + per-process CPU (delta sampling)
│   ├── PersistenceAnalyzer.cs       # Registry Run/RunOnce, startup, tasks, services, WMI
│   ├── AllowlistEngine.cs           # Trusted classification + known-miner list
│   ├── CloudEnvironment.cs          # GCP/Azure/AWS + Server 2022/2025/Core detection
│   │
│   ├── ── Web Mining ───────────────────────────────────────────────────────
│   ├── WebMiningDetector.cs         # Orchestrator: DNS + Browser + Network
│   ├── DnsAnalyzer.cs               # DNS cache (absolute path, 10s timeout), DoH detect
│   ├── BrowserAnalyzer.cs           # Chrome/Edge/Firefox — delta CPU, WMI parent-PID
│   ├── DomainReputationEngine.cs    # Mining pool + JS CDN blacklist + file load
│   └── ProcessResurrectionDetector.cs  # A→B→A pattern, _historyLock thread-safe
│
├── CoinShield.Models/               # Shared data types (snapshots, results, indicators)
│
├── CoinShield.Logging/              # EventLogger + JsonLogger
│
├── CoinShield.Configuration/
│   ├── Config.cs                    # All config classes incl. CloudConfig
│   ├── config.json                  # Runtime configuration
│   ├── allowlist.json               # Trusted publishers, paths, AI frameworks
│   └── mining-domains.json          # Mining pool + script CDN blacklist (loaded at startup)
│
├── CoinShield.Watchdog/             # Minimal health monitor (no detection decisions)
│
└── Installer/
    ├── install.ps1                  # v1.1: Server 2022/2025, GCP detect, .NET auto-install
    ├── uninstall.ps1                # Clean removal, optional log keep
    ├── gcp-startup-script.ps1       # GCP VM startup script (idempotent, GCS download)
    ├── README.md                    # English installer guide
    └── HUONG-DAN.md                 # Vietnamese installer guide
```

---

## 5. System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 (build 19041+) | Windows Server 2022 / 2025 |
| Architecture | x64 | x64 |
| .NET Runtime | .NET 10 (runtime only, not SDK) | .NET 10 |
| RAM | 50 MB available | 100+ MB |
| Disk | 50 MB | 200 MB (logs) |
| Privileges | Administrator (install only) | LocalSystem (service) |
| GPU telemetry | Optional | Windows WDDM 2.0+ driver |

**Supported OS versions:**

| OS | Status | Notes |
|---|---|---|
| Windows 10 (21H2+) | ✅ Full support | All features |
| Windows 11 | ✅ Full support | All features |
| Windows Server 2019 | ✅ Full support | All features |
| Windows Server 2022 | ✅ Full support | Optimized, delayed-auto start |
| Windows Server 2025 | ✅ Full support | Tested, manifest updated |
| Windows Server Core 2022/2025 | ✅ Full support | Browser detection auto-disabled |
| Google Cloud VM (any above OS) | ✅ Full support | GCP metadata integration |
| Azure VM (any above OS) | ✅ Detected | Standard service install |
| AWS EC2 (any above OS) | ✅ Detected | Standard service install |

---

## 6. Building from Source

### Prerequisites

```powershell
# Install .NET 10 SDK
winget install Microsoft.DotNet.SDK.10

# Verify
dotnet --version  # should show 10.x.x
```

### Build Commands

```powershell
# Navigate to solution root
cd CoinShield

# Restore all packages
dotnet restore CoinShield.sln

# Build (Debug)
dotnet build CoinShield.sln -c Debug

# Publish — Service (x64, framework-dependent, single file)
dotnet publish CoinShield.Service/CoinShield.Service.csproj `
    -c Release -r win-x64 --self-contained false `
    -o ./publish/service

# Publish — Watchdog
dotnet publish CoinShield.Watchdog/CoinShield.Watchdog.csproj `
    -c Release -r win-x64 --self-contained false `
    -o ./publish/watchdog

# Copy config files (already set as CopyToOutputDirectory in .csproj)
# config.json, allowlist.json, mining-domains.json are auto-copied
```

### Build Output

After publish, `./publish/service/` will contain:
```
CoinShield.Service.exe
CoinShield.Service.runtimeconfig.json
config.json
allowlist.json
mining-domains.json
```

Copy `install.ps1`, `uninstall.ps1` from `Installer/` to the same directory before running the installer.

---

## 7. Installation

### 7.1 Interactive Install

```powershell
# Run PowerShell as Administrator
cd CoinShield\Installer

# Default: Monitor mode, install to C:\Program Files\CoinShield
.\install.ps1

# Enforcement mode (auto-terminates mining processes)
.\install.ps1 -Mode Enforcement

# Custom directory
.\install.ps1 -Mode Monitor -InstallDir "D:\Security\CoinShield"

# Without Watchdog service
.\install.ps1 -NoWatchdog
```

### 7.2 Silent Install

Silent mode: no colored output, no prompts. All audit events still written to Windows Event Log.

```powershell
# Silent — Monitor mode (recommended for initial deployment)
.\install.ps1 -Silent

# Silent — Enforcement mode
.\install.ps1 -Silent -Mode Enforcement

# Silent — Auto-download .NET 10 if not present
.\install.ps1 -Silent -Mode Monitor -AutoInstallDotNet
```

### 7.3 Windows Server 2022 / 2025

The installer automatically detects Windows Server by build number:
- Server 2022: build ≥ 20348
- Server 2025: build ≥ 26100

Server-specific behavior (automatic):
- `delayed-auto` start confirmed (ensures network stack + WMI are ready before service starts)
- Service start wait increased to 5 seconds (vs 2 seconds on desktop)
- `config.json` patched with `cloud.reduceWmiOverheadOnCloud: true` automatically

```powershell
# Install on Windows Server 2022 / 2025
# Run PowerShell as Administrator
.\install.ps1 -Mode Enforcement -Silent

# Verify
Get-Service CoinShield | Select-Object Name, Status, StartType
# Expected: Running, AutomaticDelayedStart
```

### 7.4 Server Core (Headless)

Server Core has no Desktop Experience. CoinShield automatically detects `InstallationType = "Server Core"` and:
- Disables browser correlation (`webMining.enableBrowserCorrelation = false`) — no browsers run on Server Core
- All process, network, DNS, persistence detection remains active
- Web mining DNS-layer detection remains active (catches miners tunneling through browsers on other machines)
- `-AutoInstallDotNet` is enabled automatically (no GUI package manager)

```powershell
# Install on Server Core (all flags can be used via remote PowerShell session)
# Connect via PowerShell remoting or RDP with enhanced session
Enter-PSSession -ComputerName <server> -Credential (Get-Credential)

# Inside remote session:
.\install.ps1 -Silent -Mode Enforcement
# .NET 10 will be downloaded and installed automatically

# Verify remotely
Get-Service -ComputerName <server> -Name CoinShield
```

### 7.5 Google Cloud Platform VM

#### Option A — Manual install on existing VM

```powershell
# On the GCP VM (RDP or gcloud compute ssh --os-login)
.\install.ps1 -Silent -Mode Monitor -AutoInstallDotNet
```

#### Option B — Startup script (installs on every first boot)

**Step 1: Upload binaries to GCS**

```powershell
# Publish and upload
dotnet publish CoinShield.Service -c Release -r win-x64 -o ./publish/service
gsutil -m cp -r ./publish/service/* gs://YOUR-BUCKET/coinshield/binaries/
gsutil cp ./Installer/*.ps1 gs://YOUR-BUCKET/coinshield/
```

**Step 2: Create VM with startup script**

```bash
gcloud compute instances create my-vm \
  --image-family=windows-2022 \
  --image-project=windows-cloud \
  --metadata=windows-startup-script-url=gs://YOUR-BUCKET/coinshield/gcp-startup-script.ps1 \
  --metadata=coinshield-mode=Enforcement \
  --metadata=coinshield-gcs-source=gs://YOUR-BUCKET/coinshield/binaries/
```

**Step 3: Attach to existing VM**

```bash
gcloud compute instances add-metadata my-vm \
  --metadata=windows-startup-script-url=gs://YOUR-BUCKET/coinshield/gcp-startup-script.ps1 \
  --metadata=coinshield-mode=Monitor \
  --metadata=coinshield-gcs-source=gs://YOUR-BUCKET/coinshield/binaries/
```

**GCP metadata keys supported:**

| Key | Values | Description |
|---|---|---|
| `coinshield-mode` | `Monitor` \| `Enforcement` \| `Emergency` | Override operating mode per VM |
| `coinshield-gcs-source` | `gs://bucket/path/` | GCS path to binaries folder |
| `coinshield-skip-if-running` | `true` \| `false` | Skip install if service already running (default: `true`) |

**Change mode without reinstalling:**

```bash
# Switch to Enforcement on a running VM
gcloud compute instances add-metadata my-vm --metadata=coinshield-mode=Enforcement
# Then restart the service on the VM:
gcloud compute ssh my-vm --command="Restart-Service CoinShield" --os-login
```

**View startup script logs:**

```bash
# Via GCP Cloud Logging (requires Ops Agent)
gcloud logging read 'logName="projects/PROJECT/logs/winevt.raw" AND jsonPayload.Channel="Application" AND jsonPayload.SourceName="CoinShield-Startup"'

# Or directly on the VM
type C:\ProgramData\CoinShield\Logs\startup-script.log
```

#### Option C — Instance template (new VMs in a managed group)

```bash
gcloud compute instance-templates create coinshield-template \
  --image-family=windows-2022 \
  --image-project=windows-cloud \
  --metadata=windows-startup-script-url=gs://YOUR-BUCKET/coinshield/gcp-startup-script.ps1 \
  --metadata=coinshield-mode=Enforcement \
  --metadata=coinshield-gcs-source=gs://YOUR-BUCKET/coinshield/binaries/ \
  --metadata=coinshield-skip-if-running=true

gcloud compute instance-groups managed create coinshield-group \
  --template=coinshield-template \
  --size=5
```

### 7.6 Group Policy / SCCM

```powershell
# Deploy via network share (Group Policy Software Installation or SCCM)
powershell.exe -ExecutionPolicy Bypass `
    -File "\\fileserver\share\CoinShield\install.ps1" `
    -Silent -Mode Monitor -AutoInstallDotNet

# Verify exit code in SCCM
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

---

## 8. Configuration Reference

Configuration file: `C:\Program Files\CoinShield\config.json`

**Restart the service after any change:**
```powershell
Restart-Service CoinShield
```

### 8.1 Monitoring Intervals

```json
"monitoring": {
    "cpuIntervalSeconds":              1,   // CPU sample rate
    "gpuIntervalSeconds":              1,   // GPU sample rate
    "processIntervalSeconds":          2,   // Process enumeration
    "networkIntervalSeconds":          5,   // TCP table + web mining scan
    "persistenceScanIntervalSeconds": 30,   // Registry/tasks/WMI scan
    "deepAnalysisMinLifetimeSeconds": 120   // Min process age before hash check
}
```

### 8.2 Detection Thresholds

```json
"detection": {
    "suspiciousThreshold":     30,    // Score to enter Suspicious state
    "highRiskThreshold":       60,    // Score to enter HighRisk/Analyzing state
    "confirmedMiningThreshold":85,    // Score gate for ConfirmedMining
    "confirmationSeconds":     60,    // Time window gate (oscillation-resistant)
    "minimumStrongIndicators":  2,    // Independent signal count gate
    "gpuUtilizationThreshold": 90.0, // GPU % that contributes to score
    "gpuSustainedMinutes":     10,    // Minutes sustained above threshold
    "mode": "Monitor"                 // Monitor | Enforcement | Emergency
}
```

### 8.3 Scoring Weights

```json
"scoring": {
    "gpuSustained10Min":      10,   // GPU > threshold for 10 min
    "gpuSustained30Min":      10,   // GPU > threshold for 30 min (additional)
    "unknownExecutable":      15,   // Not in any trusted list
    "unsignedExecutable":     10,   // No Authenticode signature
    "suspiciousPath":         10,   // In Temp, AppData (non-Programs)
    "suspiciousCommandLine":  25,   // Mining tokens, pool params
    "suspiciousNetwork":      25,   // Mining port connections
    "miningProtocol":         30,   // Stratum URI in command line
    "suspiciousPersistence":  20,   // Registry/startup/task/WMI persistence
    "knownMaliciousHash":    100,   // Hash on block list
    "aiTrainingMitigation":   40,   // Mitigation: reduces score
    "trustedApplication":     50,   // Mitigation: reduces score
    "trustedPublisher":       15,   // Mitigation: reduces score
    "userLaunchedProcess":    10    // Mitigation: reduces score
}
```

### 8.4 AI Protection

```json
"aiProtection": {
    "enabled":           true,
    "minimumConfidence": 0.65   // AI confidence >= 0.65 → cannot escalate to ConfirmedMining
}
```

### 8.5 Response Behavior

```json
"response": {
    "terminateMiningProcess": false,  // true = kill confirmed miners (Enforcement/Emergency)
    "emergencyShutdown":      false,  // true = shutdown OS (Emergency mode only)
    "shutdownGraceSeconds":   30      // Wait before shutdown command
}
```

### 8.6 Logging

```json
"logging": {
    "eventLog":      true,   // Write to Windows Event Log
    "jsonLog":       true,   // Write JSON log files
    "retentionDays": 14,     // JSON log retention
    "verbosity":     2        // 0=Error, 1=Warning, 2=Info, 3=Debug
}
```

### 8.7 Web Mining

```json
"webMining": {
    "enabled":                  true,
    "confirmedMiningThreshold": 60,    // Confidence to confirm browser miner
    "suspiciousThreshold":      35,    // Confidence to log browser suspicion
    "browserIntervalSeconds":   5,     // Browser + DNS scan interval
    "rendererCpuThreshold":     50.0,  // % CPU for renderer to be "high" (lowered from 80%)
    "longRunningWorkerSeconds": 30,    // JS worker duration to be suspicious
    "enableDomainBlocking":     true,  // Block mining domains via hosts file
    "miningDomainsFile":        "mining-domains.json",
    "enableBrowserCorrelation": true,  // false on Server Core (auto-set)
    "enableResurrectionDetection": true,
    "resurrectionScoreBonus":   30,
    "miningScriptDomainBonus":  50,    // Score bonus for Coinhive/CryptoLoot contact
    "miningPoolDomainBonus":    35     // Score bonus for mining pool DNS query
}
```

### 8.8 Cloud Environment

```json
"cloud": {
    "enabled":                     true,
    "gcpMetadataTimeoutSeconds":    2,      // Keep short — metadata either responds immediately or not
    "reduceWmiOverheadOnCloud":     true,   // Increase persistence scan interval on cloud VMs
    "allowGcpModeOverride":         true,   // Allow coinshield-mode metadata key to override mode
    "serverCoreMode":               "HeadlessOnly",  // HeadlessOnly | Full
    "logInstanceMetadataAtStartup": true    // Log GCP project/zone/machine at startup
}
```

---

## 9. Operating Modes

| Mode | Detect | Log | Block Domain | Terminate Process | Shutdown OS |
|---|---|---|---|---|---|
| **Monitor** (default) | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Enforcement** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Emergency** | ✅ | ✅ | ✅ | ✅ | ✅ |

**Recommended rollout sequence:**

```
1. Deploy Monitor mode → run for 1-2 weeks → review logs for false positives
2. Add any legitimate processes to allowlist.json
3. Switch to Enforcement mode → validate no legitimate processes terminated
4. Switch to Emergency only for isolated/dedicated mining-risk environments
```

**Change mode without reinstalling:**

```powershell
# Edit config directly
$cfg = Get-Content 'C:\Program Files\CoinShield\config.json' | ConvertFrom-Json
$cfg.detection.mode = 'Enforcement'
$cfg.response.terminateMiningProcess = $true
$cfg | ConvertTo-Json -Depth 10 | Set-Content 'C:\Program Files\CoinShield\config.json' -Encoding UTF8
Restart-Service CoinShield
```

---

## 10. Detection Signals & Scoring

### Process Layer Signals

| Signal | Score | Notes |
|---|---|---|
| GPU sustained > 10 min | +10 | Requires other signals to be meaningful |
| GPU sustained > 30 min | +10 | Additive |
| VRAM stable during high GPU | +5 | Miners hold VRAM constant |
| Unknown executable | +15 | Not in allowlist |
| Unsigned executable | +10 | No Authenticode signature |
| Suspicious path (Temp/AppData) | +10 | Common dropper locations |
| Malicious path (random hex in Temp) | +20 | Strong indicator |
| Stratum URI in command line | +30 | `stratum+tcp://` found |
| Pool address in command line | +20 | `host:port` on known mining port |
| Wallet address in command line | +15 | ETH/XMR address pattern |
| Known miner process name | +30 | xmrig, ccminer, etc. |
| Suspicious network (mining port) | +15 | Connection to port 3333, 4444, etc. |
| Loopback stratum proxy (BYPASS-01) | +20 | `127.0.0.1:3333` — local VPN/proxy |
| Mining pool hostname | +20 | Hostname matches pool pattern |
| Long-lived connection (> 10 min) | +5 | External persistent connection |
| Long-lived connection (> 1 hour) | +10 | Very persistent external connection |
| Suspicious persistence | +20 | Registry/startup/task/service/WMI |
| Known malicious hash | +100 | Hash on explicit block list |
| Process hollowing hint (BYPASS-02) | +30 | Trusted binary with anomalous memory |
| Process resurrection pattern | +25–40 | A→B→A kill-and-restart loop |

### Mitigations (reduce score)

| Signal | Score | Notes |
|---|---|---|
| AI training evidence (≥ 3 signals) | −40 | torch, tensorflow, --epochs, etc. |
| Trusted application | −50 | In allowlist |
| Trusted publisher (signed) | −15 | Authenticode publisher in allowlist |
| User-launched interactively | −10 | Parent is explorer/VS Code/terminal |

### Web Mining Signals (separate confidence 0–100)

| Signal | Confidence | Notes |
|---|---|---|
| Mining script CDN queried (Coinhive, CryptoLoot) | +50 | No legitimate use |
| Mining pool DNS query | +35 | Strong indicator |
| High-CPU renderer + WebAssembly | +25 | Combined signal |
| Long-running JS worker | +15 | > 30 seconds |
| Throttled miner (moderate CPU + DNS + worker) | +20 | BYPASS-06 patch |
| Sustained high scans (3+ cycles) | +15 | Persistence confirmation |

---

## 11. AI Workload Protection

CoinShield will **never** confirm mining for a process with AI confidence ≥ 0.65.

### AI Evidence Signals (require ≥ 3 independent signals to bypass name-only protection)

| Signal | AI Points | Example |
|---|---|---|
| AI framework in command line | 40 | `--torch`, `import tensorflow` |
| Training script patterns | 30 | `train.py`, `--epochs`, `--batch-size` |
| Python/Jupyter process name | 20 | `python.exe`, `jupyter-notebook` |
| Trusted publisher (signed binary) | 15 | Python.org signed python.exe |
| Trusted application (in allowlist) | 20 | Path matches `allowlist.json` |
| User-launched (interactive parent) | 10 | Launched from VS Code, terminal |

### Test Scenarios

| Scenario | Expected Outcome |
|---|---|
| `python train.py --epochs 100 --batch-size 32` (GPU 99%) | `AI_WORKLOAD` — no action |
| `python.exe` renamed from xmrig (no AI signals) | AI confidence capped at 0.50, can reach ConfirmedMining |
| Blender 3D rendering (GPU 98%) | `LEGITIMATE` — no action |
| Steam game (GPU 99%) | `LEGITIMATE` — no action |
| `xmrig --pool pool.minexmr.com:4444 --wallet ...` | `CONFIRMED_MINING` in ~60 seconds |
| xmrig throttled to 50% CPU | Detected via sustained pattern + DNS signal |
| xmrig via SOCKS5 to `127.0.0.1:3333` | Detected via loopback stratum proxy |
| xmrig injected into `python.exe` (hollowing) | +30 hollowing score, can still confirm |

---

## 12. Web Mining Protection

CoinShield detects browser-based JavaScript/WebAssembly mining across 4 layers:

### Layer 1 — DNS Cache Monitoring
- Reads Windows DNS cache via `%SystemRoot%\System32\ipconfig.exe /displaydns` (absolute path, 10-second timeout)
- Checks all queried domains against mining-domains.json blacklist (Coinhive, CryptoLoot, 50+ known CDNs)
- Legitimate crypto exchanges (Coinbase, Binance, Kraken) are whitelisted and do not trigger alerts

### Layer 2 — Direct IP Detection
- Detects connections to hardcoded mining pool IPs (bypasses DNS entirely)
- NiceHash, Slushpool, SupportXMR IP ranges covered

### Layer 3 — DoH Detection (DNS-over-HTTPS)
- Firefox, Chrome, Brave support DoH — these do not populate Windows DNS cache
- CoinShield detects HTTPS connections to known DoH resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9, AdGuard, NextDNS)
- DoH usage adds medium suspicion when combined with other browser signals

### Layer 4 — Localhost Stratum Proxy (BYPASS-01)
- Miners behind xmrig-proxy or SOCKS5 VPN connect only to `127.0.0.1:3333`
- CoinShield specifically scores loopback connections on Stratum ports as suspicious (+20)

### Browser Process Correlation
- Identifies main browser process via WMI parent-PID (not `SessionId > 0` which was a bug)
- Uses delta CPU sampling for renderers (not lifetime average — catches new miners immediately)
- Attempts to terminate only the specific tab/renderer, not the entire browser

**Action flow:**

```
Browser contacts Coinhive CDN
         ↓
DNS layer detects query (+50 confidence)
         ↓
High-CPU renderer detected (+25 confidence)
         ↓
Long-running JS worker detected (+15 confidence)
         ↓
Total confidence: 90 → CONFIRMED (threshold: 60)
         ↓
Block domain: 0.0.0.0 coinhive.com → hosts file
         ↓
Terminate renderer process (not entire browser)
         ↓
Incident logged to Event Log + JSON
```

---

## 13. Bypass Resistance

| Bypass Technique | Detection Method |
|---|---|
| VPN tunnel (miner → VPN → pool) | Connection still uses mining ports; exit node hostname matched |
| Localhost stratum proxy (`127.0.0.1:3333`) | Loopback + stratum port → +20 score (BYPASS-01) |
| DNS-over-HTTPS (no Windows DNS cache) | HTTPS to known DoH resolver IPs detected |
| Hardcoded IP (no DNS query) | Known mining pool IP prefix matching |
| CPU throttling (50% instead of 100%) | Lowered `rendererCpuThreshold` to 50%; sustained pattern + DNS signal scoring |
| Process hollowing (inject into python.exe) | Trusted binary + anomalous memory → +30 hollowing score |
| Rename miner to python.exe | Requires ≥ 3 AI signals; name-only bypass capped at AI confidence 0.50 |
| Oscillating score (59s above, 1s below threshold) | `FirstSuspicionTime` set once, never reset — confirmation window counts from first elevation |
| Watchdog resurrection (A kills B starts A) | ProcessResurrectionDetector A→B→A pattern: +40 score |
| Scheduled task restart | Regular interval detection → +35 score |
| Browser-based WebAssembly mining | 4-layer DNS/IP/DoH/browser correlation |
| Signed legitimate binary used as miner host | Hash-mismatch tracking; hollowing heuristic |

---

## 14. Allowlist Management

Edit `C:\Program Files\CoinShield\allowlist.json`.

**Restart the service after changes:**
```powershell
Restart-Service CoinShield
```

### Add a trusted publisher

```json
"trustedPublishers": [
    "Microsoft Corporation",
    "Your Company Name Here"
]
```

### Add a trusted path

```json
"trustedExecutablePaths": [
    "%ProgramFiles%\\MyApp\\*",
    "%LOCALAPPDATA%\\Programs\\MyTool\\*"
]
```

### Add a trusted process by name

```json
"trustedProcessNames": [
    "mylegitapp",
    "render-worker"
]
```

### Add a trusted hash (most precise)

```powershell
# Get SHA-256 hash of your binary
Get-FileHash "C:\Program Files\MyApp\myapp.exe" -Algorithm SHA256 | Select-Object Hash
```

```json
"trustedSha256Hashes": [
    "A1B2C3D4E5F6..."
]
```

### Add an AI framework (for custom ML libraries)

```json
"aiFrameworks": [
    "torch",
    "my_custom_ml_framework"
]
```

---

## 15. Logs and Evidence

### Log Locations

| Location | Content | Format |
|---|---|---|
| Windows Event Log — Application → CoinShield | Service lifecycle, detections, actions | Event Log |
| `%ProgramData%\CoinShield\Logs\coinshield-YYYYMMDD.jsonl` | Structured activity log | JSON Lines |
| `%ProgramData%\CoinShield\Logs\incident-YYYYMMDD-HHmmss.json` | Full evidence bundle (pre-action) | JSON |
| `%ProgramData%\CoinShield\Logs\startup-script.log` | GCP startup script execution log | Plain text |

### Event Log Entry Types

| Event ID | Type | Meaning |
|---|---|---|
| 1000 | Information | Service started / installed |
| 1001 | Information | Service stopped |
| 1002 | Error | Service error |
| 1003 | Warning | Service degraded mode |
| 2000 | Information | Process detected |
| 2001 | Warning | Suspicious activity |
| 2002 | Information | AI workload identified |
| 2003 | Error | Mining confirmed |
| 3000 | Warning | Action taken |
| 3001 | Warning | Process terminated |
| 3002 | Error | Emergency shutdown initiated |
| 4000 | Information | Config loaded |
| 5000 | Warning | Detection error |

### Reading Logs

```powershell
# View recent events in Event Viewer (PowerShell)
Get-EventLog -LogName Application -Source CoinShield -Newest 20

# Filter by severity
Get-EventLog -LogName Application -Source CoinShield -EntryType Error, Warning

# Read JSON log
Get-Content "$env:ProgramData\CoinShield\Logs\coinshield-$(Get-Date -f 'yyyyMMdd').jsonl" |
    ConvertFrom-Json | Select-Object timestamp, level, component, message | Format-Table -Wrap

# Find all incidents
Get-ChildItem "$env:ProgramData\CoinShield\Logs\incident-*.json" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
    ForEach-Object { Get-Content $_.FullName | ConvertFrom-Json }
```

### Example Incident Bundle

```json
{
  "timestamp": "2026-08-17T14:23:01Z",
  "process": {
    "pid": 4210,
    "name": "unknown.exe",
    "path": "C:\\Users\\user\\AppData\\Local\\Temp\\a3f9b2c1.exe",
    "sha256": "8A9B2C3D...",
    "commandLine": "unknown.exe --pool stratum+tcp://pool.minexmr.com:4444 --wallet 4A...",
    "publisher": ""
  },
  "system": {
    "cpuPercent": 82,
    "gpuPercent": 98,
    "vramPercent": 91,
    "memoryMb": 142
  },
  "scores": {
    "miningScore": 94,
    "aiConfidence": 0.02,
    "miningConfidence": 0.97,
    "strongIndicators": 4
  },
  "evidence": [
    "Stratum protocol URI in command line. (+30)",
    "Pool address pattern detected. (+20)",
    "GPU sustained 35 minutes above 90%. (+20)",
    "Unknown unsigned executable in AppData\\Temp. (+25)",
    "Process resurrection detected (killed at 14:21, restarted). (+25)"
  ],
  "decision": "ConfirmedMining",
  "action": "TERMINATE"
}
```

---

## 16. Service Management

### Check Status

```powershell
# Quick status check
Get-Service CoinShield, CoinShieldWatchdog

# Detailed status
Get-Service CoinShield | Select-Object Name, Status, StartType, CanStop

# Check if service is degraded (look for Event ID 1003)
Get-EventLog -LogName Application -Source CoinShield -InstanceId 1003 -Newest 1
```

### Start / Stop / Restart

```powershell
# Start
Start-Service CoinShield

# Stop (requires Administrator)
Stop-Service CoinShield

# Restart after config change
Restart-Service CoinShield

# Restart both services
Restart-Service CoinShield, CoinShieldWatchdog
```

### Remote Management (Windows Server)

```powershell
# Check status on remote server
Get-Service -ComputerName SERVER01 -Name CoinShield

# Restart on remote server
Invoke-Command -ComputerName SERVER01 -ScriptBlock { Restart-Service CoinShield }
```

### Change Operating Mode

```powershell
# Helper function — run as Administrator
function Set-CoinShieldMode {
    param([ValidateSet('Monitor','Enforcement','Emergency')] [string]$Mode)

    $cfgPath = 'C:\Program Files\CoinShield\config.json'
    $cfg = Get-Content $cfgPath | ConvertFrom-Json

    $cfg.detection.mode = $Mode
    $cfg.response.terminateMiningProcess = ($Mode -ne 'Monitor')
    $cfg.response.emergencyShutdown = ($Mode -eq 'Emergency')

    $cfg | ConvertTo-Json -Depth 10 | Set-Content $cfgPath -Encoding UTF8
    Restart-Service CoinShield
    Write-Host "CoinShield mode set to: $Mode" -ForegroundColor Green
}

Set-CoinShieldMode -Mode Enforcement
```

---

## 17. Uninstallation

```powershell
# Default — preserve logs in %ProgramData%\CoinShield\Logs
.\uninstall.ps1

# Remove logs as well
.\uninstall.ps1 -RemoveLogs

# Custom install directory
.\uninstall.ps1 -InstallDir "D:\Security\CoinShield" -RemoveLogs

# Do not remove Event Log source (keep history)
.\uninstall.ps1 -RemoveEventLogSource:$false
```

The uninstaller:
1. Stops Watchdog service
2. Stops CoinShield service
3. Removes both service registrations (`sc delete`)
4. Removes known CoinShield files from install directory (safe — only `.exe`, `.dll`, `.json` extensions)
5. Removes empty install directory
6. Removes Windows Event Log sources
7. Optionally removes log directory (default: preserved)

---

## 18. Troubleshooting

### Service won't start

```powershell
# Check for .NET 10 runtime
dotnet --list-runtimes | Select-String '10\.'

# If missing, install it
.\install.ps1 -AutoInstallDotNet
# Or download manually: https://dotnet.microsoft.com/download/dotnet/10.0

# Check Event Log for startup error
Get-EventLog -LogName Application -Source CoinShield -EntryType Error -Newest 5
```

### Service starts then stops immediately

```powershell
# Look for fatal configuration error
Get-EventLog -LogName Application -Source CoinShield -Newest 10

# Common cause: invalid config.json
# Validate JSON syntax
Get-Content 'C:\Program Files\CoinShield\config.json' | ConvertFrom-Json
```

### False positive — legitimate process flagged

```powershell
# Check what signals triggered the score
Get-EventLog -LogName Application -Source CoinShield -EntryType Warning -Newest 5 |
    Select-Object -ExpandProperty Message

# Add the process to allowlist
notepad 'C:\Program Files\CoinShield\allowlist.json'
# Add publisher, path, or hash as appropriate
Restart-Service CoinShield
```

### Mining not detected after confirmed miner running

```powershell
# Check current mode
(Get-Content 'C:\Program Files\CoinShield\config.json' | ConvertFrom-Json).detection.mode

# Check if service is in degraded mode (too many consecutive failures)
Get-EventLog -LogName Application -Source CoinShield -InstanceId 1003 -Newest 1

# View recent activity log
Get-Content "$env:ProgramData\CoinShield\Logs\coinshield-$(Get-Date -f 'yyyyMMdd').jsonl" |
    ConvertFrom-Json | Where-Object level -eq 'Warning' | Select-Object -Last 20
```

### GCP startup script not running

```bash
# Check serial port output on GCP VM
gcloud compute instances get-serial-port-output my-vm

# Check startup script log via Cloud Logging
gcloud logging read 'resource.type="gce_instance" AND logName=~"winevt" AND jsonPayload.SourceName="CoinShield-Startup"' --limit 20
```

### Server Core — service runs but no browser detection

This is expected. Server Core has no Desktop Experience and no browsers.  
All process/network/DNS/persistence detection remains active.  
Check `config.json`: `webMining.enableBrowserCorrelation` should be `false` (set automatically).

---

## 19. Security Notes

- Runs as **LocalSystem** — has access to all processes and network connections
- `config.json` and log directory ACLs are set to **SYSTEM + Administrators only** during install
- Configuration is validated at startup — malformed JSON causes a fatal error (service does not start with invalid config)
- CoinShield **never** executes commands read from configuration files
- CoinShield **never** downloads arbitrary binaries at runtime
- All ipconfig.exe calls use **absolute path** (`%SystemRoot%\System32\ipconfig.exe`) to prevent PATH hijacking
- Command lines in logs are sanitised — wallet addresses and pool passwords are redacted
- Incident evidence files never contain authentication tokens or secrets
- The `hosts` file is modified only to add specific `0.0.0.0 domain` entries for confirmed mining domains; no existing entries are removed

---

## 20. FAQ

**Q: Will CoinShield detect mining in a browser like Chrome?**  
A: Yes. CoinShield monitors DNS queries, browser renderer CPU, WebAssembly activity, and JavaScript worker duration. It will detect Coinhive-style attacks and terminate only the specific mining tab renderer, not your entire browser.

**Q: Will CoinShield terminate my AI training job?**  
A: No — if your training process has ≥ 3 independent AI evidence signals (e.g., Python process + AI framework in command line + training script pattern), its AI confidence will exceed 0.65 and it cannot reach ConfirmedMining regardless of score.

**Q: Does CoinShield work without internet access?**  
A: Yes — all detection is local. The only outbound connection CoinShield makes is to the GCP metadata server (`169.254.169.254`) at startup on GCP VMs, and this times out after 2 seconds with no impact on detection.

**Q: Will CoinShield detect mining via a VPN?**  
A: Yes — mining processes still use Stratum ports locally and appear in the TCP table. A VPN only changes the remote IP; the local connection to the VPN client's port is still detected (loopback stratum proxy detection, BYPASS-01).

**Q: How much CPU/RAM does CoinShield use?**  
A: Target: < 1% CPU idle, < 100 MB RAM. The heaviest operations (WMI process enumeration, GPU counter sampling) run at 2-5 second intervals and are designed to be lightweight. GPU counters are batch-primed with a single 50ms sleep instead of per-instance sleeps.

**Q: Can I run CoinShield on Windows Server Core without a desktop?**  
A: Yes — CoinShield detects Server Core automatically and disables browser correlation (no browsers on Server Core). All other detection layers remain active.

**Q: Can I deploy CoinShield to many GCP VMs automatically?**  
A: Yes — use the `gcp-startup-script.ps1` with an instance template. The script is idempotent (skips reinstall if service is already running), downloads binaries from GCS, and supports per-VM mode via `coinshield-mode` metadata key.

**Q: What happens if CoinShield crashes?**  
A: The Windows SCM is configured to restart the service after 10 seconds (3 consecutive attempts, failure count resets after 24 hours). The Watchdog service independently monitors CoinShield and logs alerts to Event Log if it stops unexpectedly.

**Q: How do I know if CoinShield is working?**  
A: Check `Get-Service CoinShield` (should be Running) and `Get-EventLog -LogName Application -Source CoinShield -Newest 1` (should show a recent activity entry).

**Q: Can the service be stopped without Administrator access?**  
A: No — the installer configures the service to require Administrator credentials to stop or modify. The uninstaller also requires Administrator.

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.1.0 | 2026-08-17 | Windows Server 2022/2025, Server Core, GCP startup script, web mining protection, 17 bug/bypass patches |
| 1.0.0 | 2026-08-01 | Initial release — process/GPU/network/persistence detection, AI workload protection |

---

*Copyright © 2026. All rights reserved.*
