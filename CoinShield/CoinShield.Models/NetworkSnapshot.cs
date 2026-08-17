using System;
using System.Collections.Generic;
using System.Net;

namespace CoinShield.Models;

/// <summary>
/// Network connection information correlated to a specific process.
/// </summary>
public sealed class NetworkConnectionInfo
{
    public int     OwnerPid          { get; set; }
    public string  OwnerProcessName  { get; set; } = string.Empty;

    public IPAddress LocalAddress    { get; set; } = IPAddress.None;
    public int       LocalPort       { get; set; }
    public IPAddress RemoteAddress   { get; set; } = IPAddress.None;
    public int       RemotePort      { get; set; }

    public string  Protocol          { get; set; } = string.Empty; // TCP / UDP
    public string  State             { get; set; } = string.Empty; // ESTABLISHED, LISTEN, …

    /// <summary>Reverse-DNS hostname for the remote address, if resolved.</summary>
    public string  RemoteHostname    { get; set;  } = string.Empty;

    public DateTime FirstSeen        { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen         { get; set;  } = DateTime.UtcNow;
    public TimeSpan Duration         => LastSeen - FirstSeen;

    // ── Scoring helpers ───────────────────────────────────────────────────────
    /// <summary>True when the remote port matches common mining-pool ports.</summary>
    public bool IsMiningPort => MiningPorts.Contains(RemotePort);

    /// <summary>True when the connection has been alive for an extended period.</summary>
    public bool IsLongLived(TimeSpan threshold) => Duration >= threshold;

    /// <summary>Known stratum / mining pool TCP ports.</summary>
    public static readonly HashSet<int> MiningPorts = new()
    {
        // Stratum v1 / v2
        3333, 3334, 3335, 3336, 3337,
        4444, 4445,
        5555, 5556,
        7777, 8888, 9999,
        // XMR / RandomX common
        14444, 14433,
        // Nicehash
        3353, 3357,
        // Ethermine / 2Miners
        4000, 4001,
        // Generic high-numbered stratum variants
        25000, 25001,
    };
}

/// <summary>
/// Aggregate network snapshot for a single scan cycle.
/// </summary>
public sealed class NetworkSnapshot
{
    public List<NetworkConnectionInfo> Connections { get; set; } = new();

    /// <summary>All unique remote IPs observed this cycle.</summary>
    public HashSet<string> RemoteAddresses { get; set; } = new();

    /// <summary>Total active TCP connections on this system.</summary>
    public int TotalTcpConnections { get; set; }

    public DateTime SnapshotTime { get; set; } = DateTime.UtcNow;

    // ── Convenience queries ───────────────────────────────────────────────────
    /// <summary>Returns all connections owned by the given PID.</summary>
    public IEnumerable<NetworkConnectionInfo> ForProcess(int pid)
    {
        foreach (var c in Connections)
            if (c.OwnerPid == pid)
                yield return c;
    }

    /// <summary>Returns all connections on known mining ports.</summary>
    public IEnumerable<NetworkConnectionInfo> MiningPortConnections()
    {
        foreach (var c in Connections)
            if (c.IsMiningPort)
                yield return c;
    }
}
