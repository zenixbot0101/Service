using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>
/// Collection of indicators for browser-based web mining detection.
/// Combines browser behavior, DNS queries, network connections, and process correlation.
/// </summary>
public sealed class WebMiningIndicators
{
    /// <summary>Process ID being assessed</summary>
    public int ProcessId { get; set; }

    /// <summary>Process name</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>Whether this is a browser process</summary>
    public bool IsBrowserProcess { get; set; }

    /// <summary>Browser type (if applicable)</summary>
    public BrowserType BrowserType { get; set; } = BrowserType.Unknown;

    // ── DNS Indicators ────────────────────────────────────────────────────────
    /// <summary>Number of mining pool domain queries</summary>
    public int MiningPoolDnsQueries { get; set; }

    /// <summary>Number of cryptocurrency-related domain queries</summary>
    public int CryptoDnsQueries { get; set; }

    /// <summary>Number of suspicious JavaScript CDN queries</summary>
    public int SuspiciousJsCdnQueries { get; set; }

    /// <summary>List of suspicious domains accessed</summary>
    public List<string> SuspiciousDomains { get; set; } = new();

    // ── Browser Behavior Indicators ───────────────────────────────────────────
    /// <summary>Whether WebAssembly execution detected</summary>
    public bool HasWebAssemblyExecution { get; set; }

    /// <summary>Number of long-running JavaScript workers (> 30s)</summary>
    public int LongRunningWorkers { get; set; }

    /// <summary>Number of high-CPU renderer processes (> 80%)</summary>
    public int HighCpuRenderers { get; set; }

    /// <summary>Total browser CPU usage (%)</summary>
    public double BrowserCpuUsage { get; set; }

    /// <summary>Browser process uptime (seconds)</summary>
    public double BrowserUptimeSeconds { get; set; }

    // ── Network Indicators ────────────────────────────────────────────────────
    /// <summary>Number of connections to mining pool infrastructure</summary>
    public int MiningPoolConnections { get; set; }

    /// <summary>Number of persistent long-duration connections (> 5 min)</summary>
    public int LongDurationConnections { get; set; }

    /// <summary>Number of connections using Stratum protocol patterns</summary>
    public int StratumConnections { get; set; }

    /// <summary>List of low-reputation domains connected to</summary>
    public List<string> LowReputationDomains { get; set; } = new();

    // ── Process Correlation Indicators ────────────────────────────────────────
    /// <summary>Whether a parent process is suspicious</summary>
    public bool HasSuspiciousParent { get; set; }

    /// <summary>Whether process has been restarted multiple times recently</summary>
    public bool HasResurrectionPattern { get; set; }

    /// <summary>Number of times this process was killed and restarted</summary>
    public int ResurrectionCount { get; set; }

    // ── Aggregated Scores ─────────────────────────────────────────────────────
    /// <summary>DNS reputation score (0-100, lower is more suspicious)</summary>
    public int DnsReputationScore { get; set; } = 100;

    /// <summary>Browser behavior score (0-100, higher is more suspicious)</summary>
    public int BrowserBehaviorScore { get; set; }

    /// <summary>Network pattern score (0-100, higher is more suspicious)</summary>
    public int NetworkPatternScore { get; set; }

    /// <summary>Overall web mining confidence (0-100)</summary>
    public int WebMiningConfidence { get; set; }

    // ── Evidence ──────────────────────────────────────────────────────────────
    /// <summary>List of specific indicators detected</summary>
    public List<string> DetectedIndicators { get; set; } = new();

    /// <summary>Timestamp when indicators were captured</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Correlation result between browser activity, DNS, and process behavior
/// </summary>
public sealed class WebMiningCorrelation
{
    /// <summary>Process ID</summary>
    public int ProcessId { get; set; }

    /// <summary>Process name</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>Is this a confirmed web mining attack?</summary>
    public bool IsConfirmedWebMiner { get; set; }

    /// <summary>Confidence level (0-100)</summary>
    public int Confidence { get; set; }

    /// <summary>Specific browser tab/worker PID (if identifiable)</summary>
    public int? TabProcessId { get; set; }

    /// <summary>Whether we can safely terminate just the tab vs. entire browser</summary>
    public bool CanTerminateTabOnly { get; set; }

    /// <summary>Mining domain/URL detected</summary>
    public string? MiningDomain { get; set; }

    /// <summary>Evidence summary</summary>
    public string Evidence { get; set; } = string.Empty;

    /// <summary>Recommended action (BlockDomain, TerminateTab, TerminateProcess, Alert)</summary>
    public WebMiningAction RecommendedAction { get; set; } = WebMiningAction.Alert;

    /// <summary>Timestamp</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Recommended response action for web mining detection
/// </summary>
public enum WebMiningAction
{
    /// <summary>No action needed</summary>
    None = 0,

    /// <summary>Alert only, log the incident</summary>
    Alert = 1,

    /// <summary>Block the mining domain (DNS/firewall level)</summary>
    BlockDomain = 2,

    /// <summary>Terminate the specific browser tab/worker</summary>
    TerminateTab = 3,

    /// <summary>Terminate the browser renderer process</summary>
    TerminateRenderer = 4,

    /// <summary>Terminate entire browser process (last resort)</summary>
    TerminateBrowser = 5,

    /// <summary>Block network connection</summary>
    BlockConnection = 6
}

/// <summary>
/// Tracks process resurrection patterns (A→kill→B→A cycle)
/// </summary>
public sealed class ProcessResurrectionRecord
{
    /// <summary>Process ID</summary>
    public int ProcessId { get; set; }

    /// <summary>Process name</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>Process path</summary>
    public string ProcessPath { get; set; } = string.Empty;

    /// <summary>Number of times this process was killed</summary>
    public int KillCount { get; set; }

    /// <summary>Number of times this process reappeared after being killed</summary>
    public int ResurrectionCount { get; set; }

    /// <summary>Last kill timestamp</summary>
    public DateTime? LastKillTime { get; set; }

    /// <summary>Last resurrection timestamp</summary>
    public DateTime? LastResurrectionTime { get; set; }

    /// <summary>Parent process that resurrects this process (if detected)</summary>
    public int? ResurrectorProcessId { get; set; }

    /// <summary>Resurrection pattern (e.g., "A→B→A", "scheduled-task", "service")</summary>
    public string? ResurrectionPattern { get; set; }

    /// <summary>Is this a confirmed persistence mechanism?</summary>
    public bool IsConfirmedPersistence { get; set; }
}
