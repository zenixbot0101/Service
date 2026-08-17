using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  WebMiningDetector
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Orchestrator for browser-based / web cryptomining detection.
///
/// Correlates signals from three independent layers:
///   1. DNS layer     — queries to mining pool domains, JS miner CDNs
///   2. Browser layer — high-CPU renderer, WebAssembly, long-running workers
///   3. Network layer — persistent connections to mining infrastructure
///
/// Architecture:
///   Application
///     ↓
///   DNS queries  ──►  DnsAnalyzer  ──►  DomainReputationEngine
///     ↓
///   Browser procs ──► BrowserAnalyzer ──► tab/renderer correlation
///     ↓
///   Network conns ──► connection fingerprint
///     ↓
///   WebMiningDetector.Correlate()
///     ↓
///   WebMiningConfirmed event  (fed to ResponseEngine)
///
/// Critical safety rule: DO NOT shutdown Windows for a suspicious domain.
/// Domains containing "crypto", "bitcoin", "ethereum" are NOT treated as
/// mining indicators on their own.  Shutdown is only triggered by the main
/// ResponseEngine when ALL existing gates pass.
/// </summary>
public sealed class WebMiningDetector : IDisposable
{
    // ── Dependencies ──────────────────────────────────────────────────────────
    private readonly CoinShieldConfig        _cfg;
    private readonly CoinShieldLogger        _logger;
    private readonly DnsAnalyzer             _dnsAnalyzer;
    private readonly BrowserAnalyzer         _browserAnalyzer;
    private readonly DomainReputationEngine  _reputationEngine;

    // ── State ─────────────────────────────────────────────────────────────────
    private readonly ConcurrentDictionary<int, WebMiningTrackingState> _states  = new();
    private readonly ConcurrentDictionary<string, DateTime>            _blocked = new();
    private DateTime _lastDnsScan = DateTime.MinValue;

    // ── Events ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Raised when browser-based mining is confirmed.
    /// Subscribers must NOT call back into WebMiningDetector from this handler.
    /// </summary>
    public event Action<WebMiningCorrelation>? WebMiningConfirmed;

    /// <summary>
    /// Raised when a suspicious web mining attempt is detected (not yet confirmed).
    /// </summary>
    public event Action<WebMiningCorrelation>? WebMiningSuspicious;

    private bool _disposed;

    // ── Thresholds ────────────────────────────────────────────────────────────
    private WebMiningConfig W => _cfg.WebMining;

    // ── Construction ─────────────────────────────────────────────────────────
    public WebMiningDetector(
        CoinShieldConfig       cfg,
        CoinShieldLogger       logger,
        DnsAnalyzer            dnsAnalyzer,
        BrowserAnalyzer        browserAnalyzer,
        DomainReputationEngine reputationEngine)
    {
        _cfg              = cfg              ?? throw new ArgumentNullException(nameof(cfg));
        _logger           = logger           ?? throw new ArgumentNullException(nameof(logger));
        _dnsAnalyzer      = dnsAnalyzer      ?? throw new ArgumentNullException(nameof(dnsAnalyzer));
        _browserAnalyzer  = browserAnalyzer  ?? throw new ArgumentNullException(nameof(browserAnalyzer));
        _reputationEngine = reputationEngine ?? throw new ArgumentNullException(nameof(reputationEngine));
    }

    // ── Main tick (called by DetectionEngine every 5 s) ───────────────────────

    /// <summary>
    /// Evaluates all currently running browser processes for web mining activity.
    /// Should be called at network interval cadence (every 5 s).
    /// </summary>
    public void Tick(CancellationToken ct)
    {
        if (_disposed || ct.IsCancellationRequested || !W.Enabled) return;

        try
        {
            // 1. Refresh DNS picture every BrowserIntervalSeconds
            var now = DateTime.UtcNow;
            bool dnsTime = (now - _lastDnsScan).TotalSeconds >= W.BrowserIntervalSeconds;
            if (dnsTime)
            {
                _lastDnsScan = now;
                RunDnsScan(ct);
            }

            // 2. Evaluate all browser processes
            EvaluateBrowserProcesses(ct);

            // 3. Prune stale tracking states
            PruneDeadProcesses();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.Debug("WebMiningDetector", $"Tick error: {ex.Message}");
        }
    }

    // ── DNS scan ──────────────────────────────────────────────────────────────

    private void RunDnsScan(CancellationToken ct)
    {
        try
        {
            // Get all running browser PIDs so DNS queries can be correlated
            var browsers = GetRunningBrowserProcesses();

            foreach (var (pid, name) in browsers)
            {
                if (ct.IsCancellationRequested) return;

                var snapshot = _dnsAnalyzer.CaptureDnsSnapshot(pid, name);
                
                // Flag any mining script domains immediately — these are
                // unambiguous (Coinhive, CryptoLoot, etc.)
                var criticalDomains = snapshot.Queries
                    .Where(q => q.Reputation.HostsMiningScript || q.Reputation.IsMiningPool)
                    .Select(q => q.Domain)
                    .Distinct()
                    .ToList();

                foreach (var domain in criticalDomains)
                {
                    _logger.Warning("WebMiningDetector",
                        $"MINING_DOMAIN_QUERY: PID={pid} Name={name} Domain={domain}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("WebMiningDetector", $"DNS scan error: {ex.Message}");
        }
    }

    // ── Browser process evaluation ────────────────────────────────────────────

    private void EvaluateBrowserProcesses(CancellationToken ct)
    {
        var browsers = GetRunningBrowserProcesses();

        foreach (var (pid, name) in browsers)
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                EvaluateSingleBrowser(pid, name);
            }
            catch (Exception ex)
            {
                _logger.Debug("WebMiningDetector",
                    $"EvaluateBrowser PID={pid}: {ex.Message}");
            }
        }
    }

    private void EvaluateSingleBrowser(int mainPid, string name)
    {
        // Capture browser snapshot (all child processes)
        var browserSnap = _browserAnalyzer.CaptureBrowserSnapshot(mainPid);

        // Analyze DNS patterns for this browser
        var dnsResult = _dnsAnalyzer.AnalyzeProcessDnsPatterns(mainPid);

        // Build web mining indicators
        var indicators = BuildIndicators(mainPid, name, browserSnap, dnsResult);

        // Update tracking state
        var state = _states.GetOrAdd(mainPid, _ => new WebMiningTrackingState
        {
            ProcessId   = mainPid,
            ProcessName = name,
            FirstSeen   = DateTime.UtcNow
        });

        state.UpdateWith(indicators);

        // Determine action
        var correlation = Correlate(state, indicators, browserSnap);

        if (correlation is null) return;

        // Dispatch events based on confidence
        if (correlation.Confidence >= W.ConfirmedMiningThreshold)
        {
            _logger.Warning("WebMiningDetector",
                $"WEB_MINER_CONFIRMED: PID={mainPid} Name={name} " +
                $"Confidence={correlation.Confidence} " +
                $"Domain={correlation.MiningDomain} " +
                $"Action={correlation.RecommendedAction}");

            WebMiningConfirmed?.Invoke(correlation);
        }
        else if (correlation.Confidence >= W.SuspiciousThreshold)
        {
            _logger.Warning("WebMiningDetector",
                $"WEB_MINER_SUSPICIOUS: PID={mainPid} Name={name} " +
                $"Confidence={correlation.Confidence}");

            WebMiningSuspicious?.Invoke(correlation);
        }
    }

    // ── Correlation logic ─────────────────────────────────────────────────────

    private WebMiningIndicators BuildIndicators(
        int              pid,
        string           name,
        BrowserSnapshot  browserSnap,
        DnsAnalysisResult dnsResult)
    {
        var detectedIndicators = new List<string>();

        // DNS indicators
        if (dnsResult.MiningPoolQueryCount > 0)
            detectedIndicators.Add($"DNS queries to {dnsResult.MiningPoolQueryCount} mining pool domain(s)");
        if (dnsResult.MiningScriptQueryCount > 0)
            detectedIndicators.Add($"DNS queries to {dnsResult.MiningScriptQueryCount} mining script CDN(s)");
        if (dnsResult.StratumQueryCount > 0)
            detectedIndicators.Add($"{dnsResult.StratumQueryCount} stratum-related DNS query(ies)");

        // Browser behavior indicators
        if (browserSnap.HasWebAssemblyActivity)
            detectedIndicators.Add("WebAssembly activity detected in browser renderer");
        if (browserSnap.LongRunningWorkerCount > 0)
            detectedIndicators.Add($"{browserSnap.LongRunningWorkerCount} long-running JS worker(s) detected");
        if (browserSnap.HighCpuRendererCount > 0)
            detectedIndicators.Add($"{browserSnap.HighCpuRendererCount} high-CPU renderer(s) detected");

        return new WebMiningIndicators
        {
            ProcessId              = pid,
            ProcessName            = name,
            IsBrowserProcess       = true,
            BrowserType            = browserSnap.Type,
            MiningPoolDnsQueries   = dnsResult.MiningPoolQueryCount,
            CryptoDnsQueries       = dnsResult.CryptoQueryCount,
            SuspiciousJsCdnQueries = dnsResult.MiningScriptQueryCount,
            SuspiciousDomains      = dnsResult.SuspiciousDomains,
            HasWebAssemblyExecution= browserSnap.HasWebAssemblyActivity,
            LongRunningWorkers     = browserSnap.LongRunningWorkerCount,
            HighCpuRenderers       = browserSnap.HighCpuRendererCount,
            BrowserCpuUsage        = browserSnap.TotalCpuUsage,
            DetectedIndicators     = detectedIndicators,
            Timestamp              = DateTime.UtcNow
        };
    }

    private WebMiningCorrelation? Correlate(
        WebMiningTrackingState state,
        WebMiningIndicators    indicators,
        BrowserSnapshot        browserSnap)
    {
        int confidence = 0;
        var evidenceParts = new List<string>();
        string? miningDomain = indicators.SuspiciousDomains.FirstOrDefault();

        // ── Signal 1: DNS mining script query (critical — unambiguous) ─────────
        // Coinhive, CryptoLoot etc. — no legitimate use
        if (indicators.SuspiciousJsCdnQueries > 0)
        {
            confidence += 50;
            evidenceParts.Add("Mining script CDN queried");
        }

        // ── Signal 2: Mining pool DNS query ────────────────────────────────────
        if (indicators.MiningPoolDnsQueries > 0)
        {
            confidence += 35;
            evidenceParts.Add("Mining pool domain queried");
        }

        // ── Signal 3: High-CPU renderer + WASM ────────────────────────────────
        if (browserSnap.HasWebAssemblyActivity && browserSnap.HighCpuRendererCount > 0)
        {
            confidence += 25;
            evidenceParts.Add("WebAssembly + high-CPU renderer");
        }
        else if (browserSnap.HighCpuRendererCount > 0)
        {
            confidence += 10;
            evidenceParts.Add("High-CPU renderer");
        }

        // ── Signal 4: Long-running worker ─────────────────────────────────────
        if (indicators.LongRunningWorkers > 0)
        {
            confidence += 15;
            evidenceParts.Add($"{indicators.LongRunningWorkers} long-running worker(s)");
        }

        // ── Signal 5: Sustained detection over time ───────────────────────────
        if (state.ConsecutiveHighScans >= 3)
        {
            confidence += 15;
            evidenceParts.Add($"Sustained mining behavior ({state.ConsecutiveHighScans} scans)");
        }

        // ── Signal 6: BYPASS-06 — throttled miner (moderate CPU + DNS hit) ────
        // A miner throttling to 50-60% CPU to avoid detection still leaves
        // DNS traces and has a persistently elevated renderer with > 30s uptime.
        if (indicators.BrowserCpuUsage is > 30.0 and < 80.0
            && (indicators.MiningPoolDnsQueries > 0 || indicators.SuspiciousJsCdnQueries > 0)
            && indicators.LongRunningWorkers > 0)
        {
            confidence += 20;
            evidenceParts.Add("Throttled-miner pattern: moderate CPU + mining DNS + long-running worker");
        }

        if (confidence == 0) return null;

        // Determine recommended action
        var action = DetermineAction(indicators, browserSnap, confidence);

        // Can we isolate just the tab?
        int? tabPid = browserSnap.HighCpuRendererCount > 0
            ? _browserAnalyzer.IdentifyMiningTab(browserSnap, W.RendererCpuThreshold)
            : null;

        return new WebMiningCorrelation
        {
            ProcessId          = indicators.ProcessId,
            ProcessName        = indicators.ProcessName,
            IsConfirmedWebMiner= confidence >= W.ConfirmedMiningThreshold,
            Confidence         = Math.Min(100, confidence),
            TabProcessId       = tabPid,
            CanTerminateTabOnly= tabPid.HasValue,
            MiningDomain       = miningDomain,
            Evidence           = string.Join("; ", evidenceParts),
            RecommendedAction  = action,
            Timestamp          = DateTime.UtcNow
        };
    }

    private WebMiningAction DetermineAction(
        WebMiningIndicators indicators,
        BrowserSnapshot     browserSnap,
        int                 confidence)
    {
        // Monitor mode: always just alert
        if (_cfg.Detection.Mode == OperatingMode.Monitor)
            return WebMiningAction.Alert;

        // Critical: known mining script CDN contacted
        if (indicators.SuspiciousJsCdnQueries > 0 && confidence >= 50)
        {
            // Block domain first, then isolate renderer
            return WebMiningAction.BlockDomain;
        }

        // High confidence with identifiable renderer
        if (confidence >= W.ConfirmedMiningThreshold && browserSnap.HighCpuRendererCount > 0)
        {
            var tabPid = _browserAnalyzer.IdentifyMiningTab(browserSnap, W.RendererCpuThreshold);
            return tabPid.HasValue
                ? WebMiningAction.TerminateTab        // Kill just the tab
                : WebMiningAction.TerminateRenderer;  // Kill renderer process
        }

        // Medium confidence: block domain
        if (confidence >= W.SuspiciousThreshold)
            return WebMiningAction.BlockDomain;

        return WebMiningAction.Alert;
    }

    // ── Domain blocking ───────────────────────────────────────────────────────

    /// <summary>
    /// Block a domain by adding it to the Windows hosts file.
    /// Redirects domain to 0.0.0.0 to prevent connections.
    /// </summary>
    public bool BlockDomain(string domain)
    {
        if (!_cfg.WebMining.EnableDomainBlocking) return false;
        if (_blocked.ContainsKey(domain)) return true;

        try
        {
            var hostsPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"drivers\etc\hosts");

            var entry = $"\n# CoinShield blocked — mining domain\n0.0.0.0 {domain}\n";
            System.IO.File.AppendAllText(hostsPath, entry);

            _blocked[domain] = DateTime.UtcNow;
            _reputationEngine.AddToBlacklist(domain);

            _logger.Warning("WebMiningDetector", $"DOMAIN_BLOCKED: {domain}");
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error("WebMiningDetector", $"Failed to block domain {domain}: {ex.Message}");
            return false;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<(int Pid, string Name)> GetRunningBrowserProcesses()
    {
        var results     = new List<(int, string)>();
        var browserExes = new[] { "chrome", "msedge", "firefox", "opera", "brave", "chromium", "vivaldi" };

        // BUG-07 FIX: Build a PID→ParentPID map so we can identify true main
        // browser processes (those whose parent is NOT another browser instance).
        // Previously `p.SessionId > 0` matched ALL user-session processes.
        var browserPids = new HashSet<int>();

        foreach (var exe in browserExes)
        {
            try
            {
                var procs = Process.GetProcessesByName(exe);
                foreach (var p in procs)
                {
                    try { browserPids.Add(p.Id); }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }

        if (browserPids.Count == 0) return results;

        // Query parent PIDs in one WMI call
        var parentMap = new Dictionary<int, int>(); // pid → parentPid
        try
        {
            var pidList = string.Join(" OR ", browserPids.Select(p => $"ProcessId={p}"));
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ProcessId, ParentProcessId FROM Win32_Process WHERE {pidList}");
            using var queryResults = searcher.Get();
            foreach (System.Management.ManagementObject obj in queryResults)
            {
                int pid  = Convert.ToInt32(obj["ProcessId"]);
                int ppid = Convert.ToInt32(obj["ParentProcessId"]);
                parentMap[pid] = ppid;
            }
        }
        catch { }

        // Main browser process = browser PID whose parent is NOT another browser PID
        foreach (var exe in browserExes)
        {
            try
            {
                var procs = Process.GetProcessesByName(exe);
                foreach (var p in procs)
                {
                    try
                    {
                        bool parentIsAlsoBrowser = parentMap.TryGetValue(p.Id, out int ppid)
                                                   && browserPids.Contains(ppid);
                        if (!parentIsAlsoBrowser)
                            results.Add((p.Id, p.ProcessName));
                    }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }

        return results;
    }

    private void PruneDeadProcesses()
    {
        var toRemove = _states.Keys
            .Where(pid =>
            {
                try { Process.GetProcessById(pid); return false; }
                catch { return true; }
            })
            .ToList();

        foreach (var pid in toRemove)
        {
            _states.TryRemove(pid, out _);
            _dnsAnalyzer.ClearProcessHistory(pid);
            _browserAnalyzer.ClearBrowserTree(pid);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal tracking state per browser process
// ─────────────────────────────────────────────────────────────────────────────

internal sealed class WebMiningTrackingState
{
    public int      ProcessId         { get; init; }
    public string   ProcessName       { get; init; } = string.Empty;
    public DateTime FirstSeen         { get; init; }
    public DateTime LastUpdated       { get; set; } = DateTime.UtcNow;
    public int      ConsecutiveHighScans { get; set; }
    public int      TotalScans        { get; set; }
    public int      PeakConfidence    { get; set; }

    public void UpdateWith(WebMiningIndicators indicators)
    {
        TotalScans++;
        LastUpdated = DateTime.UtcNow;

        bool thisHigh = indicators.MiningPoolDnsQueries > 0
                     || indicators.SuspiciousJsCdnQueries > 0
                     || (indicators.HasWebAssemblyExecution && indicators.HighCpuRenderers > 0)
                     || indicators.LongRunningWorkers > 0;

        if (thisHigh)
            ConsecutiveHighScans++;
        else
            ConsecutiveHighScans = 0;
    }
}
