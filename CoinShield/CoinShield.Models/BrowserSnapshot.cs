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
    public int ProcessId { get; init; }

    /// <summary>Browser type (Chrome, Edge, Firefox, Opera, Brave)</summary>
    public BrowserType Type { get; init; }

    /// <summary>Main browser process name</summary>
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>Browser version (if detectable)</summary>
    public string? Version { get; init; }

    /// <summary>Child processes (renderer, GPU, utility, tab processes)</summary>
    public List<BrowserChildProcess> ChildProcesses { get; init; } = new();

    /// <summary>Total CPU usage across all browser processes (%)</summary>
    public double TotalCpuUsage { get; init; }

    /// <summary>Total memory usage (MB)</summary>
    public long TotalMemoryMB { get; init; }

    /// <summary>Active network connections from browser processes</summary>
    public List<BrowserConnection> Connections { get; init; } = new();

    /// <summary>Detected WebAssembly activity</summary>
    public bool HasWebAssemblyActivity { get; init; }

    /// <summary>Number of long-running JavaScript workers (> 30 seconds)</summary>
    public int LongRunningWorkerCount { get; init; }

    /// <summary>Number of renderer processes with high CPU (> 80%)</summary>
    public int HighCpuRendererCount { get; init; }

    /// <summary>Timestamp when snapshot was captured</summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
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
    public int ProcessId { get; init; }

    /// <summary>Process type (renderer, GPU, utility, tab)</summary>
    public string ProcessType { get; init; } = string.Empty;

    /// <summary>Command line arguments (may contain tab URL or purpose)</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>CPU usage (%) for this specific child process</summary>
    public double CpuUsage { get; init; }

    /// <summary>Memory usage (MB)</summary>
    public long MemoryMB { get; init; }

    /// <summary>Process uptime (seconds)</summary>
    public double UptimeSeconds { get; init; }

    /// <summary>Whether this process is suspected to be a tab renderer</summary>
    public bool IsTabRenderer { get; init; }

    /// <summary>Whether WebAssembly execution is detected in this process</summary>
    public bool HasWebAssembly { get; init; }
}

/// <summary>
/// Network connection from a browser process
/// </summary>
public sealed class BrowserConnection
{
    /// <summary>Process ID that owns this connection</summary>
    public int ProcessId { get; init; }

    /// <summary>Remote IP address</summary>
    public string RemoteAddress { get; init; } = string.Empty;

    /// <summary>Remote port</summary>
    public int RemotePort { get; init; }

    /// <summary>Remote domain (if resolved from DNS cache)</summary>
    public string? RemoteDomain { get; init; }

    /// <summary>Protocol (TCP, UDP, WebSocket)</summary>
    public string Protocol { get; init; } = string.Empty;

    /// <summary>Connection state (ESTABLISHED, LISTEN, etc.)</summary>
    public string State { get; init; } = string.Empty;

    /// <summary>Connection duration (seconds)</summary>
    public double DurationSeconds { get; init; }

    /// <summary>Whether this connection is to a known mining pool</summary>
    public bool IsMiningPoolConnection { get; init; }

    /// <summary>Whether this connection uses Stratum protocol patterns</summary>
    public bool IsStratumProtocol { get; init; }

    /// <summary>Domain reputation score (0-100, lower is more suspicious)</summary>
    public int DomainReputationScore { get; init; } = 50;
}
