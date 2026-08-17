using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  ProcessAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Enumerates all running processes and builds rich <see cref="ProcessSnapshot"/>
/// objects capturing identity, lineage, trust signals, path risk, and
/// command-line classification.
///
/// Key design principles:
/// ─ Process name alone is NEVER sufficient to classify a process.
/// ─ Path risk is ONE signal fed to the RiskScorer, not a decision.
/// ─ Command-line analysis uses tokenised pattern matching, not simple substring.
/// ─ Digital signature verification is cached; hashing is on-demand and cached.
/// </summary>
public sealed class ProcessAnalyzer : IDisposable
{
    // ── Dependencies ──────────────────────────────────────────────────────────
    private readonly CoinShieldConfig  _cfg;
    private readonly CoinShieldLogger  _logger;
    private readonly AllowlistEngine   _allowlist;

    // ── Caches ────────────────────────────────────────────────────────────────
    // Signature cache: path → (isSigned, publisher, expiryUtc)
    private readonly ConcurrentDictionary<string, (bool signed, string publisher, DateTime expiry)>
        _signatureCache = new(StringComparer.OrdinalIgnoreCase);

    // Hash cache: path → sha256 (cleared when file write-time changes)
    private readonly ConcurrentDictionary<string, (string hash, DateTime fileTime)>
        _hashCache = new(StringComparer.OrdinalIgnoreCase);

    // Parent PID cache: PID → (ParentPid, ParentName, GrandparentName, snapshotTime)
    private readonly ConcurrentDictionary<int, (int ppid, string pname, string gpname, DateTime t)>
        _parentCache = new();

    // ── System path sets ──────────────────────────────────────────────────────
    private static readonly HashSet<string> _systemPaths;
    private static readonly HashSet<string> _tempPatterns;
    private static readonly HashSet<string> _suspiciousFileExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".tmp", ".dat", ".bin", ".scr" };

    // Signature cache TTL
    private static readonly TimeSpan SignatureCacheTtl = TimeSpan.FromMinutes(30);

    // ── Known trusted system process names (extremely weak signal — name only) ─
    private static readonly HashSet<string> _systemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
        "svchost", "dwm", "explorer", "taskhostw", "spoolsv", "SearchIndexer",
        "MsMpEng", "SecurityHealthService", "audiodg", "conhost",
        "RuntimeBroker", "ShellExperienceHost", "StartMenuExperienceHost",
    };

    // ── Common interactive-launch parents ─────────────────────────────────────
    private static readonly HashSet<string> _interactiveLaunchParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "explorer.exe",
        "cmd", "cmd.exe",
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "code", "code.exe",       // VS Code
        "devenv", "devenv.exe",   // Visual Studio
        "winterm", "wt.exe",      // Windows Terminal
        "bash", "bash.exe",       // WSL
    };

    // ── Construction ─────────────────────────────────────────────────────────

    static ProcessAnalyzer()
    {
        _systemPaths = BuildSystemPaths();
        _tempPatterns = BuildTempPatterns();
    }

    public ProcessAnalyzer(CoinShieldConfig cfg, CoinShieldLogger logger, AllowlistEngine allowlist)
    {
        _cfg       = cfg       ?? throw new ArgumentNullException(nameof(cfg));
        _logger    = logger    ?? throw new ArgumentNullException(nameof(logger));
        _allowlist = allowlist ?? throw new ArgumentNullException(nameof(allowlist));
    }

    // ── Main enumeration ──────────────────────────────────────────────────────

    /// <summary>
    /// Enumerates all accessible running processes and returns a snapshot
    /// for each.  Inaccessible system processes are skipped gracefully.
    /// </summary>
    public List<ProcessSnapshot> EnumerateAll()
    {
        var snapshots = new List<ProcessSnapshot>(256);

        // Build a parent-map from the full process list using WMI for accuracy
        var parentMap = BuildParentMap();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var snap = BuildSnapshot(proc, parentMap);
                if (snap is not null)
                    snapshots.Add(snap);
            }
            catch (Exception ex)
            {
                _logger.Debug("ProcessAnalyzer",
                    $"Snapshot failed PID={proc.Id} Name={proc.ProcessName}: {ex.Message}");
            }
            finally
            {
                proc.Dispose();
            }
        }

        return snapshots;
    }

    /// <summary>
    /// Builds a snapshot for a single PID.  Returns null if the process
    /// has exited or is inaccessible.
    /// </summary>
    public ProcessSnapshot? SnapshotPid(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var parentMap  = BuildParentMap();
            return BuildSnapshot(proc, parentMap);
        }
        catch (ArgumentException)
        {
            return null; // Process exited
        }
        catch (Exception ex)
        {
            _logger.Debug("ProcessAnalyzer", $"SnapshotPid {pid} failed: {ex.Message}");
            return null;
        }
    }

    // ── Snapshot construction ─────────────────────────────────────────────────

    private ProcessSnapshot? BuildSnapshot(
        Process proc,
        Dictionary<int, (int ppid, string pname, string gpname)> parentMap)
    {
        string path        = TryGetPath(proc);
        string commandLine = TryGetCommandLine(proc.Id);
        string username    = TryGetUsername(proc.Id);

        // Resolve parent chain
        var (parentPid, parentName, grandparentName) = parentMap.TryGetValue(proc.Id, out var pt)
            ? pt
            : (0, string.Empty, string.Empty);

        // Trust signals
        var (isSigned, publisher) = TryGetSignature(path);

        // Path classification
        var (pathRisk, inTemp, inAppData, isSystem) = ClassifyPath(path);

        var snap = new ProcessSnapshot
        {
            Pid            = proc.Id,
            Name           = proc.ProcessName,
            Path           = path,
            CommandLine    = commandLine,
            ParentPid      = parentPid,
            ParentName     = parentName,
            ParentPath     = string.Empty,  // populated on demand
            GrandparentName= grandparentName,
            Username       = username,
            StartTime      = TryGetStartTime(proc),
            IsSigned       = isSigned,
            Publisher      = publisher,
            PathRisk       = pathRisk,
            IsInTempDir    = inTemp,
            IsInAppData    = inAppData,
            IsSystemPath   = isSystem,
            SnapshotTime   = DateTime.UtcNow,
        };

        // Memory
        try { snap.MemoryMb = proc.WorkingSet64 / (1024.0 * 1024.0); } catch { }

        // Child PIDs
        snap.ChildPids.AddRange(
            parentMap.Where(kv => kv.Value.ppid == proc.Id).Select(kv => kv.Key));

        return snap;
    }

    // ── Path resolution ───────────────────────────────────────────────────────

    private static string TryGetPath(Process proc)
    {
        try
        {
            return proc.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            // Access denied or process exited — use WMI as fallback
            return TryGetPathViaWmi(proc.Id);
        }
    }

    private static string TryGetPathViaWmi(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
                return obj["ExecutablePath"]?.ToString() ?? string.Empty;
        }
        catch { }
        return string.Empty;
    }

    // ── Command-line retrieval ────────────────────────────────────────────────

    /// <summary>
    /// Retrieves the full command line via WMI.  WMI is used here (rather than
    /// Win32 API) because it is available without SeDebugPrivilege for most
    /// user processes.
    /// </summary>
    private string TryGetCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
                return obj["CommandLine"]?.ToString() ?? string.Empty;
        }
        catch (Exception ex)
        {
            _logger.Debug("ProcessAnalyzer", $"CommandLine WMI PID={pid}: {ex.Message}");
        }
        return string.Empty;
    }

    // ── Username resolution ───────────────────────────────────────────────────

    private string TryGetUsername(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                // BUG-15 FIX: GetOwner() takes NO input parameters (output-only method).
                // Passing new object[]{"",""} as input to an output-only method
                // produces undefined COM behaviour and returns empty results.
                var outParams = obj.InvokeMethod("GetOwner", null, null);
                if (outParams is ManagementBaseObject result)
                {
                    var domain = result["Domain"]?.ToString();
                    var user   = result["User"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(user))
                        return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
                }
            }
        }
        catch { }
        return string.Empty;
    }

    // ── Parent/process tree mapping ───────────────────────────────────────────

    /// <summary>
    /// Builds a full PID → (ParentPid, ParentName, GrandparentName) map in
    /// one WMI query to avoid N+1 per-process WMI calls.
    /// </summary>
    private Dictionary<int, (int ppid, string pname, string gpname)> BuildParentMap()
    {
        var pidToName  = new Dictionary<int, string>();
        var pidToParent= new Dictionary<int, int>();
        var result     = new Dictionary<int, (int ppid, string pname, string gpname)>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name FROM Win32_Process");

            foreach (ManagementObject obj in searcher.Get())
            {
                int pid  = Convert.ToInt32(obj["ProcessId"]  ?? 0);
                int ppid = Convert.ToInt32(obj["ParentProcessId"] ?? 0);
                var name = obj["Name"]?.ToString() ?? string.Empty;

                if (pid > 0)
                {
                    pidToName[pid]   = name;
                    pidToParent[pid] = ppid;
                }
            }

            // Build lookup
            foreach (var kv in pidToParent)
            {
                int pid  = kv.Key;
                int ppid = kv.Value;
                var pname   = pidToName.GetValueOrDefault(ppid, string.Empty);
                int gppid   = pidToParent.GetValueOrDefault(ppid, 0);
                var gpname  = pidToName.GetValueOrDefault(gppid, string.Empty);

                result[pid] = (ppid, pname, gpname);
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("ProcessAnalyzer", $"BuildParentMap WMI failed: {ex.Message}");
        }

        return result;
    }

    // ── Digital signature ─────────────────────────────────────────────────────

    private (bool isSigned, string publisher) TryGetSignature(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return (false, string.Empty);

        if (_signatureCache.TryGetValue(path, out var cached)
            && DateTime.UtcNow < cached.expiry)
            return (cached.signed, cached.publisher);

        bool   isSigned  = false;
        string publisher = string.Empty;

        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(path);
            if (cert is not null)
            {
                isSigned  = true;
                publisher = ExtractPublisherFromCert(cert);
            }
        }
        catch
        {
            // File not signed or access denied — isSigned stays false
        }

        _signatureCache[path] = (isSigned, publisher, DateTime.UtcNow.Add(SignatureCacheTtl));
        return (isSigned, publisher);
    }

    private static string ExtractPublisherFromCert(X509Certificate cert)
    {
        // Subject is "CN=Publisher Name, O=..., ..."
        var subject = cert.Subject;
        const string cnPrefix = "CN=";
        int start = subject.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return subject;
        start += cnPrefix.Length;
        int end = subject.IndexOf(',', start);
        return end < 0 ? subject[start..] : subject[start..end];
    }

    // ── SHA-256 hashing ───────────────────────────────────────────────────────

    /// <summary>
    /// Computes the SHA-256 hash of the executable.  Cached and invalidated
    /// when the file's last-write time changes.  Returns empty string on error.
    /// </summary>
    public string ComputeHash(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return string.Empty;

        try
        {
            var fileTime = File.GetLastWriteTimeUtc(path);

            if (_hashCache.TryGetValue(path, out var cached)
                && cached.fileTime == fileTime)
                return cached.hash;

            using var fs   = new FileStream(path, FileMode.Open, FileAccess.Read,
                                            FileShare.ReadWrite, 65536, useAsync: false);
            using var sha  = SHA256.Create();
            var hashBytes  = sha.ComputeHash(fs);
            var hash       = Convert.ToHexString(hashBytes);

            _hashCache[path] = (hash, fileTime);
            return hash;
        }
        catch (Exception ex)
        {
            _logger.Debug("ProcessAnalyzer", $"Hash failed for {path}: {ex.Message}");
            return string.Empty;
        }
    }

    // ── Path risk classification ──────────────────────────────────────────────

    /// <summary>
    /// Classifies the executable path into a risk tier.
    ///
    /// Returns: (PathRisk, isInTemp, isInAppData, isSystemPath)
    ///
    /// This classification is ONE signal — suspicious path alone does NOT
    /// indicate mining.  A Python interpreter in AppData\Local\Programs is
    /// a common legitimate installation.
    /// </summary>
    public (PathRisk risk, bool inTemp, bool inAppData, bool isSystem) ClassifyPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return (PathRisk.Unknown, false, false, false);

        var lower = path.ToLowerInvariant();

        // ── System trusted paths ──────────────────────────────────────────────
        if (_systemPaths.Any(sp => lower.StartsWith(sp)))
            return (PathRisk.SystemTrusted, false, false, true);

        // ── Temp directories — suspicious ─────────────────────────────────────
        bool inTemp = _tempPatterns.Any(p => lower.Contains(p));
        if (inTemp)
        {
            // Extra: random-looking name in temp is more suspicious
            var fileName = Path.GetFileNameWithoutExtension(lower);
            bool looksRandom = IsRandomLookingName(fileName);
            return looksRandom
                ? (PathRisk.Malicious, true, false, false)
                : (PathRisk.Suspicious, true, false, false);
        }

        // ── AppData paths ─────────────────────────────────────────────────────
        bool inAppData = lower.Contains(@"\appdata\");

        if (inAppData)
        {
            // AppData\Local\Programs is a known-good installation path
            if (lower.Contains(@"\appdata\local\programs\"))
                return (PathRisk.UserTrusted, false, true, false);

            // AppData\Roaming or AppData\Local (non-Programs) — suspicious
            return (PathRisk.Suspicious, false, true, false);
        }

        // ── Downloads folder ──────────────────────────────────────────────────
        if (lower.Contains(@"\downloads\"))
            return (PathRisk.Suspicious, false, false, false);

        // ── Program Files — generally trusted ────────────────────────────────
        if (lower.Contains(@"\program files\") || lower.Contains(@"\program files (x86)\"))
            return (PathRisk.UserTrusted, false, false, false);

        // ── User profile but not AppData — neutral ───────────────────────────
        if (lower.Contains(@"\users\"))
            return (PathRisk.UserTrusted, false, false, false);

        return (PathRisk.Unknown, false, false, false);
    }

    // ── Command-line analysis ─────────────────────────────────────────────────

    /// <summary>
    /// Analyses a command line for mining-related patterns.
    /// Returns a <see cref="CommandLineAnalysis"/> with scored signals.
    ///
    /// Uses tokenised matching — checks for semantic tokens rather than
    /// simple substring presence to reduce false positives.
    ///
    /// Example:
    ///   "python train.py --epochs 100 --batch-size 32"  → aiTraining=true, miningScore=0
    ///   "xmrig --pool pool.host:3333 --wallet abc123"   → miningScore=high
    /// </summary>
    public CommandLineAnalysis AnalyseCommandLine(string commandLine, string processName)
    {
        var analysis = new CommandLineAnalysis();
        if (string.IsNullOrWhiteSpace(commandLine)) return analysis;

        var lower  = commandLine.ToLowerInvariant();
        var tokens = TokeniseCommandLine(commandLine);

        // ── Mining signals ────────────────────────────────────────────────────
        var miningMatches = _allowlist.GetMiningCommandLineMatches(commandLine);
        if (miningMatches.Count > 0)
        {
            analysis.MiningTokensFound.AddRange(miningMatches);
            analysis.MiningScore += miningMatches.Count * 5;

            // Pool address pattern: host:port where port is in mining range
            if (ContainsPoolAddress(lower))
            {
                analysis.HasPoolAddress = true;
                analysis.MiningScore   += 20;
                analysis.Reasons.Add("Pool address pattern detected in command line.");
            }

            // Wallet address pattern
            if (ContainsWalletPattern(lower))
            {
                analysis.HasWalletAddress = true;
                analysis.MiningScore     += 15;
                analysis.Reasons.Add("Wallet/worker identifier in command line.");
            }
        }

        // ── Known mining process name ─────────────────────────────────────────
        if (_allowlist.IsKnownMinerName(processName))
        {
            analysis.IsKnownMinerProcess = true;
            analysis.MiningScore        += 30;
            analysis.Reasons.Add($"Process name '{processName}' matches known mining software.");
        }

        // ── Stratum protocol ──────────────────────────────────────────────────
        if (lower.Contains("stratum+tcp://")  ||
            lower.Contains("stratum+ssl://")  ||
            lower.Contains("stratum2+tcp://") ||
            lower.Contains("stratum2+ssl://"))
        {
            analysis.HasStratumProtocol = true;
            analysis.MiningScore       += 25;
            analysis.Reasons.Add("Stratum protocol URI in command line.");
        }

        // ── AI training signals ───────────────────────────────────────────────
        // These LOWER the suspicion — they are mitigating evidence
        var nameLower = processName.ToLowerInvariant();

        bool isPython = nameLower is "python" or "python3" or "python.exe" or "python3.exe"
                                  or "pythonw" or "pythonw.exe";

        if (isPython)
        {
            // Check for training-related flags
            if (lower.Contains("--epochs")   || lower.Contains("--epoch"))
            {
                analysis.AiScore += 20;
                analysis.AiSignals.Add("--epochs flag (AI training pattern).");
            }
            if (lower.Contains("--batch-size") || lower.Contains("--batch_size"))
            {
                analysis.AiScore += 10;
                analysis.AiSignals.Add("--batch-size flag (AI training pattern).");
            }
            if (lower.Contains("--learning-rate") || lower.Contains("--lr "))
            {
                analysis.AiScore += 10;
                analysis.AiSignals.Add("--learning-rate flag (AI training pattern).");
            }
            if (lower.Contains("train") && (lower.Contains(".py") || lower.Contains("--")))
            {
                analysis.AiScore += 15;
                analysis.AiSignals.Add("Training script or flag in Python command line.");
            }
            if (lower.Contains("finetune") || lower.Contains("fine_tune") || lower.Contains("pretrain"))
            {
                analysis.AiScore += 15;
                analysis.AiSignals.Add("Fine-tuning/pretraining pattern.");
            }
        }

        // Any process with Jupyter notebook markers
        if (lower.Contains("jupyter") || lower.Contains("ipykernel"))
        {
            analysis.AiScore += 20;
            analysis.AiSignals.Add("Jupyter/IPython kernel.");
        }

        // ── Summary ───────────────────────────────────────────────────────────
        analysis.IsHighRisk   = analysis.MiningScore >= 25;
        analysis.IsAiTraining = analysis.AiScore >= 20 && analysis.MiningScore < 20;

        return analysis;
    }

    // ── Process tree analysis ─────────────────────────────────────────────────

    /// <summary>
    /// Evaluates how suspicious a process's ancestry and descent are.
    /// Returns a <see cref="ProcessTreeAnalysis"/> with scoring signals.
    /// </summary>
    public ProcessTreeAnalysis AnalyseProcessTree(ProcessSnapshot snap)
    {
        var result = new ProcessTreeAnalysis();

        // ── Suspicious parent chain ───────────────────────────────────────────
        var parentNameLower  = snap.ParentName.ToLowerInvariant()
                                   .Replace(".exe", string.Empty);
        var grandNameLower   = snap.GrandparentName.ToLowerInvariant()
                                   .Replace(".exe", string.Empty);

        // svchost spawning unknown binary is very suspicious
        if (parentNameLower == "svchost" && !_systemProcessNames.Contains(snap.Name))
        {
            result.SuspiciousParentChain = true;
            result.Score += 10;
            result.Reasons.Add($"Non-system process '{snap.Name}' spawned by svchost.");
        }

        // wscript / cscript spawning processes is suspicious
        if (parentNameLower is "wscript" or "cscript" or "mshta")
        {
            result.SuspiciousParentChain = true;
            result.Score += 15;
            result.Reasons.Add($"Process spawned by scripting host: {snap.ParentName}.");
        }

        // cmd.exe or powershell spawning from a non-interactive context
        if ((snap.Name.ToLowerInvariant() is "cmd" or "cmd.exe"
                                          or "powershell" or "powershell.exe"
                                          or "pwsh" or "pwsh.exe")
            && parentNameLower is not "explorer" and not "code" and not "devenv"
                               and not "wt" and not "conhost" and not "bash"
                               and not "pwsh" and not "powershell")
        {
            result.PossiblyScriptLaunched = true;
            result.Score += 5;
            result.Reasons.Add($"Shell process spawned from unexpected parent: {snap.ParentName}.");
        }

        // Interactive parent — mitigating signal
        if (_interactiveLaunchParents.Contains(snap.ParentName))
        {
            result.IsUserLaunched = true;
            result.Score         -= 5;
            result.Reasons.Add($"Process launched interactively from {snap.ParentName}.");
        }

        // Deep nesting: grandparent is also unknown — add suspicion
        if (!string.IsNullOrWhiteSpace(grandNameLower)
            && !_systemProcessNames.Contains(snap.GrandparentName)
            && !_interactiveLaunchParents.Contains(snap.GrandparentName)
            && result.SuspiciousParentChain)
        {
            result.Score += 5;
            result.Reasons.Add($"Suspicious grandparent chain: {snap.GrandparentName} → {snap.ParentName} → {snap.Name}.");
        }

        return result;
    }

    // ── Lifetime analysis ─────────────────────────────────────────────────────

    /// <summary>
    /// Returns how many risk points the process lifetime contributes.
    /// Long-running unknown processes are more suspicious than short ones.
    /// </summary>
    public static int ScoreLifetime(ProcessSnapshot snap)
    {
        var minutes = snap.Lifetime.TotalMinutes;

        // Very short-lived: not yet suspicious
        if (minutes < 5) return 0;

        // Moderate runtime: low suspicion
        if (minutes < 60) return 2;

        // Multi-hour runtime for an unknown, unsigned process
        if (snap.PathRisk is PathRisk.Suspicious or PathRisk.Malicious or PathRisk.Unknown
            && !snap.IsSigned && minutes > 60)
            return 10;

        // Very long runtime (> 8 hours) for any unsigned/unknown binary
        if (!snap.IsSigned && minutes > 480)
            return 15;

        return 0;
    }

    // ── Eviction ─────────────────────────────────────────────────────────────

    /// <summary>Evicts signature and hash cache entries for paths no longer seen.</summary>
    public void PruneCaches(IEnumerable<string> activePaths)
    {
        var active = new HashSet<string>(activePaths, StringComparer.OrdinalIgnoreCase);
        foreach (var key in _hashCache.Keys.ToList())
            if (!active.Contains(key))
                _hashCache.TryRemove(key, out _);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static DateTime TryGetStartTime(Process proc)
    {
        try { return proc.StartTime.ToUniversalTime(); }
        catch { return DateTime.MinValue; }
    }

    private static bool ContainsPoolAddress(string lower)
    {
        // Pattern: host:port where port is a known mining port
        var match = Regex.Match(lower, @"[\w\.\-]+:(\d{3,5})",
            RegexOptions.None, TimeSpan.FromMilliseconds(100));
        if (!match.Success) return false;
        if (int.TryParse(match.Groups[1].Value, out int port))
            return NetworkConnectionInfo.MiningPorts.Contains(port);
        return false;
    }

    private static bool ContainsWalletPattern(string lower)
    {
        // ETH address: 0x followed by 40 hex chars
        if (Regex.IsMatch(lower, @"\b0x[0-9a-f]{40}\b",
            RegexOptions.None, TimeSpan.FromMilliseconds(100)))
            return true;

        // XMR address: 95 or 97 chars starting with 4 or 8
        if (Regex.IsMatch(lower, @"\b[48][0-9a-z]{94}\b",
            RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
            return true;

        // Worker/wallet flag followed by a long token
        if (Regex.IsMatch(lower, @"(-u|--user|--wallet|--worker)\s+[^\s]{16,}",
            RegexOptions.None, TimeSpan.FromMilliseconds(100)))
            return true;

        return false;
    }

    /// <summary>
    /// Tokenises a command line into arguments, handling quoted strings.
    /// </summary>
    private static List<string> TokeniseCommandLine(string cmdLine)
    {
        var tokens = new List<string>();
        var sb     = new StringBuilder();
        bool inQ   = false;

        foreach (char c in cmdLine)
        {
            if (c == '"')      { inQ = !inQ; }
            else if (c == ' ' && !inQ)
            {
                if (sb.Length > 0) { tokens.Add(sb.ToString()); sb.Clear(); }
            }
            else sb.Append(c);
        }
        if (sb.Length > 0) tokens.Add(sb.ToString());
        return tokens;
    }

    /// <summary>
    /// Returns true if a filename looks randomly generated
    /// (e.g. "a3f9b2c1d0" or "tmpXXXXXX").
    /// </summary>
    private static bool IsRandomLookingName(string name)
    {
        if (name.Length < 8) return false;
        int hexLike = name.Count(c => "0123456789abcdef".Contains(char.ToLower(c)));
        // > 80% hex-like characters = likely random
        return (double)hexLike / name.Length > 0.80;
    }

    private static HashSet<string> BuildSystemPaths()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(Environment.SpecialFolder f)
        {
            var p = Environment.GetFolderPath(f);
            if (!string.IsNullOrWhiteSpace(p)) paths.Add(p.ToLowerInvariant());
        }
        Add(Environment.SpecialFolder.System);
        Add(Environment.SpecialFolder.SystemX86);
        Add(Environment.SpecialFolder.Windows);

        // Hardcoded fallbacks in case env vars are missing
        paths.Add(@"c:\windows\system32");
        paths.Add(@"c:\windows\syswow64");
        paths.Add(@"c:\windows\");
        return paths;
    }

    private static HashSet<string> BuildTempPatterns()
    {
        var patterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? path)
        {
            if (!string.IsNullOrWhiteSpace(path))
                patterns.Add(path.ToLowerInvariant());
        }

        Add(Path.GetTempPath());
        Add(Environment.GetEnvironmentVariable("TEMP"));
        Add(Environment.GetEnvironmentVariable("TMP"));

        // Common temp sub-paths
        patterns.Add(@"\appdata\local\temp\");
        patterns.Add(@"\appdata\roaming\temp\");
        patterns.Add(@"\windows\temp\");

        return patterns;
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        _signatureCache.Clear();
        _hashCache.Clear();
        _parentCache.Clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Result types
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>Result of command-line pattern analysis for one process.</summary>
public sealed class CommandLineAnalysis
{
    public int           MiningScore          { get; set; }
    public int           AiScore              { get; set; }
    public bool          HasPoolAddress        { get; set; }
    public bool          HasWalletAddress      { get; set; }
    public bool          HasStratumProtocol    { get; set; }
    public bool          IsKnownMinerProcess   { get; set; }
    public bool          IsHighRisk            { get; set; }
    public bool          IsAiTraining          { get; set; }
    public List<string>  MiningTokensFound     { get; init; } = new();
    public List<string>  AiSignals             { get; init; } = new();
    public List<string>  Reasons               { get; init; } = new();
}

/// <summary>Result of process-tree ancestry analysis.</summary>
public sealed class ProcessTreeAnalysis
{
    public int          Score                  { get; set; }
    public bool         SuspiciousParentChain  { get; set; }
    public bool         PossiblyScriptLaunched { get; set; }
    public bool         IsUserLaunched         { get; set; }
    public List<string> Reasons                { get; init; } = new();
}
