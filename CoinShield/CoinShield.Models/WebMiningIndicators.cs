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
    public int ProcessId { get; init; }

    /// <summary>Process name</summary>
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>Whether this is a browser process</summary>
    public bool IsBrowserProcess { get; init; }

    /// <summary>Browser type (if applicable)</summary>
    public BrowserType BrowserType { get; init; } = BrowserType.Unknown;

    // ── DNS Indicators ────────────────────────────────────────────────────────
    /// <summary>Number of mining pool domain queries</summary>
    public int MiningPoolDnsQueries { get; init; }

    /// <summary>Number of cryptocurrency-related domain queries</summary>
    public int CryptoDnsQueries { get; init; }

    /// <summary>Number of suspicious JavaScript CDN queries</summary>
    public int SuspiciousJsCdnQueries { get; init; }

    /// <summary>List of suspicious domains accessed</summary>
    public List<string> SuspiciousDomains { get; init; } = new();

    // ── Browser Behavior Indicators ───────────────────────────────────────────
    /// <summary>Whether WebAssembly execution detected</summary>
    public bool HasWebAssemblyExecution { get; init; }

    /// <summary>Number of long-running JavaScript workers (> 30s)</summary>
    public int LongRunningWorkers { get; init; }

    /// <summary>Number of high-CPU renderer processes (> 80%)</summary>
    public int HighCpuRenderers { get; init; }

    /// <summary>Total browser CPU usage (%)</summary>
    public double BrowserCpuUsage { get; init; }

    /// <summary>Browser process uptime (seconds)</summary>
    public double BrowserUptimeSeconds { get; init; }

    // ── Network Indicators ────────────────────────────────────────────────────
    /// <summary>Number of connections to mining pool infrastructure</summary>
    public int MiningPoolConnections { get; init; }

    /// <summary>Number of persistent long-duration connections (> 5 min)</summary>
    public int LongDurationConnections { get; init; }

    /// <summary>Number of connections using Stratum protocol patterns</summary>
    public int StratumConnections { get; init; }

    /// <summary>List of low-reputation domains connected to</summary>
    public List<string> LowReputationDomains { get; init; } = new();

    // ── Process Correlation Indicators ────────────────────────────────────────
    /// <summary>Whether a parent process is suspicious</summary>
    public bool HasSuspiciousParent { get; init; }

    /// <summary>Whether process has been restarted multiple times recently</summary>
    public bool HasResurrectionPattern { get; init; }

    /// <summary>Number of times this process was killed and restarted</summary>
    public int ResurrectionCount { get; init; }

    // ── Aggregated Scores ─────────────────────────────────────────────────────
    /// <summary>DNS reputation score (0-100, lower is more suspicious)</summary>
    public int DnsReputationScore { get; init; } = 100;

    /// <summary>Browser behavior score (0-100, higher is more suspicious)</summary>
    public int BrowserBehaviorScore { get; init; }

    /// <summary>Network pattern score (0-100, higher is more suspicious)</summary>
    public int NetworkPatternScore { get; init; }

    /// <summary>Overall web mining confidence (0-100)</summary>
    public int WebMiningConfidence { get; init; }

    // ── Evidence ──────────────────────────────────────────────────────────────
    /// <summary>List of specific indicators detected</summary>
    public List<string> DetectedIndicators { get; init; } = new();

    /// <summary>Timestamp when indicators were captured</summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Correlation result between browser activity, DNS, and process behavior
/// </summary>
public sealed class WebMiningCorrelation
{
    /// <summary>Process ID</summary>
    public int ProcessId { get; init; }

    /// <summary>Process name</summary>
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>Is this a confirmed web mining attack?</summary>
    public bool IsConfirmedWebMiner { get; init; }

    /// <summary>Confidence level (0-100)</summary>
    public int Confidence { get; init; }

    /// <summary>Specific browser tab/worker PID (if identifiable)</summary>
    public int? TabProcessId { get; init; }

    /// <summary>Whether we can safely terminate just the tab vs. entire browser</summary>
    public bool CanTerminateTabOnly { get; init; }

    /// <summary>Mining domain/URL detected</summary>
    public string? MiningDomain { get; init; }

    /// <summary>Evidence summary</summary>
    public string Evidence { get; init; } = string.Empty;

    /// <summary>Recommended action (BlockDomain, TerminateTab, TerminateProcess, Alert)</summary>
    public WebMiningAction RecommendedAction { get; init; } = WebMiningAction.Alert;

    /// <summary>Timestamp</summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
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
    public int ProcessId { get; init; }

    /// <summary>Process name</summary>
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>Process path</summary>
    public string ProcessPath { get; init; } = string.Empty;

    /// <summary>Number of times this process was killed</summary>
    public int KillCount { get; init; }

    /// <summary>Number of times this process reappeared after being killed</summary>
    public int ResurrectionCount { get; init; }

    /// <summary>Last kill timestamp</summary>
    public DateTime? LastKillTime { get; init; }

    /// <summary>Last resurrection timestamp</summary>
    public DateTime? LastResurrectionTime { get; init; }

    /// <summary>Parent process that resurrects this process (if detected)</summary>
    public int? ResurrectorProcessId { get; init; }

    /// <summary>Resurrection pattern (e.g., "A→B→A", "scheduled-task", "service")</summary>
    public string? ResurrectionPattern { get; init; }

    /// <summary>Is this a confirmed persistence mechanism?</summary>
    public bool IsConfirmedPersistence { get; init; }
}
