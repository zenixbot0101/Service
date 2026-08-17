using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>
/// Snapshot of a browser process and its associated tabs/workers.
/// Tracks browser-based mining indicators (WebAssembly, workers, persistent connections).
/// </summary>
public sealed class BrowserSnapshot
{
    /// <summary>Process ID of the browser (chrome.exe, msedge.exe, firefox.exe)</summary>
    public int ProcessId { get; set; }

    /// <summary>Browser type (Chrome, Edge, Firefox, Opera, Brave)</summary>
    public BrowserType Type { get; set; }

    /// <summary>Main browser process name</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>Browser version (if detectable)</summary>
    public string? Version { get; set; }

    /// <summary>Child processes (renderer, GPU, utility, tab processes)</summary>
    public List<BrowserChildProcess> ChildProcesses { get; set; } = new();

    /// <summary>Total CPU usage across all browser processes (%)</summary>
    public double TotalCpuUsage { get; set; }

    /// <summary>Total memory usage (MB)</summary>
    public long TotalMemoryMB { get; set; }

    /// <summary>Active network connections from browser processes</summary>
    public List<BrowserConnection> Connections { get; set; } = new();

    /// <summary>Detected WebAssembly activity</summary>
    public bool HasWebAssemblyActivity { get; set; }

    /// <summary>Number of long-running JavaScript workers (> 30 seconds)</summary>
    public int LongRunningWorkerCount { get; set; }

    /// <summary>Number of renderer processes with high CPU (> 80%)</summary>
    public int HighCpuRendererCount { get; set; }

    /// <summary>Timestamp when snapshot was captured</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Browser type enumeration
/// </summary>
public enum BrowserType
{
    Unknown = 0,
    Chrome,
    Edge,
    Firefox,
    Opera,
    Brave,
    Chromium,
    Vivaldi,
    Safari
}

/// <summary>
/// Represents a child process of a browser (tab, renderer, GPU, utility)
/// </summary>
public sealed class BrowserChildProcess
{
    /// <summary>Process ID</summary>
    public int ProcessId { get; set; }

    /// <summary>Process type (renderer, GPU, utility, tab)</summary>
    public string ProcessType { get; set; } = string.Empty;

    /// <summary>Command line arguments (may contain tab URL or purpose)</summary>
    public string CommandLine { get; set; } = string.Empty;

    /// <summary>CPU usage (%) for this specific child process</summary>
    public double CpuUsage { get; set; }

    /// <summary>Memory usage (MB)</summary>
    public long MemoryMB { get; set; }

    /// <summary>Process uptime (seconds)</summary>
    public double UptimeSeconds { get; set; }

    /// <summary>Whether this process is suspected to be a tab renderer</summary>
    public bool IsTabRenderer { get; set; }

    /// <summary>Whether WebAssembly execution is detected in this process</summary>
    public bool HasWebAssembly { get; set; }
}

/// <summary>
/// Network connection from a browser process
/// </summary>
public sealed class BrowserConnection
{
    /// <summary>Process ID that owns this connection</summary>
    public int ProcessId { get; set; }

    /// <summary>Remote IP address</summary>
    public string RemoteAddress { get; set; } = string.Empty;

    /// <summary>Remote port</summary>
    public int RemotePort { get; set; }

    /// <summary>Remote domain (if resolved from DNS cache)</summary>
    public string? RemoteDomain { get; set; }

    /// <summary>Protocol (TCP, UDP, WebSocket)</summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>Connection state (ESTABLISHED, LISTEN, etc.)</summary>
    public string State { get; set; } = string.Empty;

    /// <summary>Connection duration (seconds)</summary>
    public double DurationSeconds { get; set; }

    /// <summary>Whether this connection is to a known mining pool</summary>
    public bool IsMiningPoolConnection { get; set; }

    /// <summary>Whether this connection uses Stratum protocol patterns</summary>
    public bool IsStratumProtocol { get; set; }

    /// <summary>Domain reputation score (0-100, lower is more suspicious)</summary>
    public int DomainReputationScore { get; set; } = 50;
}
