using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  Native TCP table structures (used to correlate PID → TCP connection)
// ─────────────────────────────────────────────────────────────────────────────

internal static class NativeTcpTable
{
    // TCP_TABLE_OWNER_PID_ALL = 5
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwSize, bool sort,
        int ipVersion, int tableClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    private static uint ReversePort(uint port) =>
        ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);

    private static string IntToIp(uint addr)
    {
        var bytes = BitConverter.GetBytes(addr);
        return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
    }

    private static string TcpState(uint state) => state switch
    {
        1  => "CLOSED",
        2  => "LISTEN",
        3  => "SYN_SENT",
        4  => "SYN_RCVD",
        5  => "ESTABLISHED",
        6  => "FIN_WAIT1",
        7  => "FIN_WAIT2",
        8  => "CLOSE_WAIT",
        9  => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _  => "UNKNOWN",
    };

    /// <summary>
    /// Returns all TCP connections (IPv4) with owning PID.
    /// Returns an empty list if the call fails.
    /// </summary>
    internal static List<(IPAddress local, int localPort,
                           IPAddress remote, int remotePort,
                           string state, int pid)> GetTcpConnections()
    {
        var results = new List<(IPAddress, int, IPAddress, int, string, int)>();

        int bufferSize = 0;
        // First call to get required buffer size
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false,
            (int)AddressFamily.InterNetwork, TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr tablePtr = IntPtr.Zero;
        try
        {
            tablePtr = Marshal.AllocHGlobal(bufferSize);
            uint ret = GetExtendedTcpTable(tablePtr, ref bufferSize, false,
                (int)AddressFamily.InterNetwork, TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret != 0) return results;

            int rowCount = Marshal.ReadInt32(tablePtr);
            int rowSize  = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            int offset   = sizeof(int); // skip dwNumEntries

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                    IntPtr.Add(tablePtr, offset + i * rowSize));

                var local   = new IPAddress(row.dwLocalAddr);
                var remote  = new IPAddress(row.dwRemoteAddr);
                int lPort   = (int)ReversePort(row.dwLocalPort);
                int rPort   = (int)ReversePort(row.dwRemotePort);
                var state   = TcpState(row.dwState);
                int pid     = (int)row.dwOwningPid;

                results.Add((local, lPort, remote, rPort, state, pid));
            }
        }
        catch
        {
            // P/Invoke failure — return empty; caller falls back to netstat
        }
        finally
        {
            if (tablePtr != IntPtr.Zero)
                Marshal.FreeHGlobal(tablePtr);
        }

        return results;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Enumerates all active TCP connections and correlates them with owning
/// process PIDs using the Windows <c>GetExtendedTcpTable</c> API.
///
/// Key design principles:
/// ─ IP address alone is NOT a shutdown trigger.
/// ─ Network behaviour is ONE signal; it must be correlated with process
///   identity, GPU behaviour, command line, and persistence.
/// ─ DNS reverse-lookup is optional and time-bounded to avoid slowing the loop.
/// ─ Connection tracking maintains history so long-lived mining pool connections
///   can be scored by duration, not just existence.
/// </summary>
public sealed class NetworkAnalyzer : IDisposable
{
    // ── Dependencies ──────────────────────────────────────────────────────────
    private readonly MonitoringConfig _cfg;
    private readonly CoinShieldLogger _logger;
    // BYPASS-01 FIX: Reference to DnsAnalyzer so we can feed RecordConnection()
    // for direct-IP and localhost stratum proxy detection.
    private DnsAnalyzer? _dnsAnalyzer;

    // ── Connection tracking ───────────────────────────────────────────────────
    // Key: "pid:localPort:remoteIp:remotePort"
    private readonly ConcurrentDictionary<string, NetworkConnectionInfo> _tracked = new();

    // DNS reverse-lookup cache: IP → hostname
    private readonly ConcurrentDictionary<string, (string host, DateTime expiry)>
        _dnsCache = new();

    private static readonly TimeSpan DnsCacheTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan DnsTimeout   = TimeSpan.FromSeconds(2);

    // ── Known mining pool IP/hostname patterns ────────────────────────────────
    // Substring matches against resolved hostnames (lower-case)
    private static readonly string[] _miningHostPatterns =
    {
        "pool.", "mining.", "miner.", "mine.",
        "ethermine.", "nanopool.", "f2pool.", "2miners.", "poolin.",
        "nicehash.", "hiveon.", "antpool.", "viabtc.", "slushpool.",
        "btc.com", "foundry", "luxor.", "braiins.",
        "xmrpool.", "moneroocean.", "supportxmr.",
    };

    // ── Private IP ranges ─────────────────────────────────────────────────────
    // Connections to private/loopback IPs are de-weighted (not miner traffic)
    private static readonly (uint start, uint end)[] _privateRanges =
    {
        (IpToUint("10.0.0.0"),   IpToUint("10.255.255.255")),
        (IpToUint("172.16.0.0"), IpToUint("172.31.255.255")),
        (IpToUint("192.168.0.0"),IpToUint("192.168.255.255")),
        (IpToUint("127.0.0.0"),  IpToUint("127.255.255.255")),
    };

    private bool _disposed;

    // ── Construction ─────────────────────────────────────────────────────────

    public NetworkAnalyzer(MonitoringConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Inject DnsAnalyzer reference so NetworkAnalyzer can feed connection data
    /// for DoH and localhost stratum proxy detection (BYPASS-01).
    /// Called by DetectionEngine after construction.
    /// </summary>
    public void SetDnsAnalyzer(DnsAnalyzer dnsAnalyzer)
    {
        _dnsAnalyzer = dnsAnalyzer;
    }

    // ── Main sample ───────────────────────────────────────────────────────────

    /// <summary>
    /// Samples all current TCP connections and returns a <see cref="NetworkSnapshot"/>
    /// with per-process connection lists, mining-port hits, and duration tracking.
    /// </summary>
    public NetworkSnapshot Sample(IEnumerable<string>? processNameMap = null)
    {
        var snapshot = new NetworkSnapshot { SnapshotTime = DateTime.UtcNow };

        var rawConnections = TryGetConnections();
        snapshot.TotalTcpConnections = rawConnections.Count;

        var now = DateTime.UtcNow;

        foreach (var (local, lPort, remote, rPort, state, pid) in rawConnections)
        {
            // Skip pure listen sockets and loopback
            if (state == "LISTEN") continue;
            if (remote.Equals(IPAddress.Any) || remote.Equals(IPAddress.None)) continue;

            var remoteStr = remote.ToString();
            var key       = $"{pid}:{lPort}:{remoteStr}:{rPort}";

            // Update or create tracking entry
            if (!_tracked.TryGetValue(key, out var info))
            {
                info = new NetworkConnectionInfo
                {
                    OwnerPid       = pid,
                    LocalAddress   = local,
                    LocalPort      = lPort,
                    RemoteAddress  = remote,
                    RemotePort     = rPort,
                    Protocol       = "TCP",
                    FirstSeen      = now,
                };
                _tracked[key] = info;
            }

            info.State    = state;
            info.LastSeen = now;

            // Async hostname resolution (non-blocking best-effort)
            if (string.IsNullOrEmpty(info.RemoteHostname))
                info.RemoteHostname = TryResolveDns(remoteStr);

            // BYPASS-01 FIX: Feed every connection into DnsAnalyzer so it can
            // detect DoH (HTTPS to DoH resolver IPs) and localhost stratum proxies.
            _dnsAnalyzer?.RecordConnection(pid, remoteStr, rPort);

            snapshot.Connections.Add(info);
            snapshot.RemoteAddresses.Add(remoteStr);
        }

        // Evict stale connections (not seen in this sample)
        var activeKeys = new HashSet<string>(
            rawConnections.Select(c => $"{c.pid}:{c.localPort}:{c.remote}:{c.remotePort}"));

        foreach (var key in _tracked.Keys.ToList())
            if (!activeKeys.Contains(key))
                _tracked.TryRemove(key, out _);

        return snapshot;
    }

    // ── Per-process analysis ──────────────────────────────────────────────────

    /// <summary>
    /// Analyses network behaviour for a specific PID and returns a scored result.
    /// </summary>
    public NetworkAnalysis AnalyseProcess(int pid, NetworkSnapshot snapshot)
    {
        var result      = new NetworkAnalysis { Pid = pid };
        var connections = snapshot.ForProcess(pid).ToList();

        result.ConnectionCount = connections.Count;

        foreach (var conn in connections)
        {
            // Mining port match
            if (conn.IsMiningPort)
            {
                result.MiningPortConnections++;
                result.Score += 15;
                result.Reasons.Add(
                    $"Connection on known mining port {conn.RemotePort} " +
                    $"→ {conn.RemoteAddress}");
                result.SuspiciousConnections.Add(conn);
            }

            // BYPASS-01 FIX: Localhost/loopback connections to stratum ports.
            // A miner using xmrig-proxy or SOCKS5 tunnel connects only to 127.0.0.1:3333.
            // Old code: IsPrivateIp() gated all long-lived/hostname checks → zero score.
            if (IsLoopbackAddress(conn.RemoteAddress) && conn.IsMiningPort)
            {
                result.Score += 20;
                result.Reasons.Add(
                    $"Loopback connection on mining port {conn.RemotePort} — " +
                    "likely local stratum proxy (VPN/tunnel bypass pattern).");
                if (!result.SuspiciousConnections.Contains(conn))
                    result.SuspiciousConnections.Add(conn);
            }

            // Long-lived external connection
            if (conn.Duration >= TimeSpan.FromMinutes(10) && !IsPrivateIp(conn.RemoteAddress))
            {
                result.LongLivedConnections++;
                result.Score += 5;
                result.Reasons.Add(
                    $"Long-lived connection ({conn.Duration.TotalMinutes:F0} min) " +
                    $"→ {conn.RemoteAddress}:{conn.RemotePort}");
            }

            // Very long-lived (> 1 hour)
            if (conn.Duration >= TimeSpan.FromHours(1) && !IsPrivateIp(conn.RemoteAddress))
            {
                result.Score += 10;
                result.Reasons.Add(
                    $"Connection alive > 1 hour → {conn.RemoteAddress}:{conn.RemotePort}");
            }

            // Hostname matches mining pool pattern
            if (!string.IsNullOrWhiteSpace(conn.RemoteHostname)
                && IsMiningHostname(conn.RemoteHostname))
            {
                result.MiningPoolConnections++;
                result.Score += 20;
                result.Reasons.Add(
                    $"Connection to suspected mining pool host: {conn.RemoteHostname}");
                if (!result.SuspiciousConnections.Contains(conn))
                    result.SuspiciousConnections.Add(conn);
            }

            // Multiple simultaneous external connections to the same remote
            // (can indicate stratum pool with multiple workers)
            if (!IsPrivateIp(conn.RemoteAddress))
                result.ExternalConnectionCount++;
        }

        // Many simultaneous external connections from a single unknown process
        if (result.ExternalConnectionCount >= 5)
        {
            result.Score += 5;
            result.Reasons.Add(
                $"Process has {result.ExternalConnectionCount} external connections.");
        }

        result.IsHighRisk = result.Score >= 25;
        return result;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<(IPAddress local, int localPort,
                  IPAddress remote, int remotePort,
                  string state, int pid)> TryGetConnections()
    {
        try
        {
            return NativeTcpTable.GetTcpConnections();
        }
        catch (Exception ex)
        {
            _logger.Warning("NetworkAnalyzer",
                $"GetExtendedTcpTable failed: {ex.Message}");
            return new List<(IPAddress, int, IPAddress, int, string, int)>();
        }
    }

    private string TryResolveDns(string ip)
    {
        if (_dnsCache.TryGetValue(ip, out var cached) && DateTime.UtcNow < cached.expiry)
            return cached.host;

        try
        {
            // Fire-and-forget — we don't want DNS resolution blocking the monitor loop.
            // Store the result when it arrives; return empty for now if not cached.
            var task = System.Threading.Tasks.Task.Run(async () =>
            {
                try
                {
                    using var cts = new System.Threading.CancellationTokenSource(DnsTimeout);
                    var entry     = await Dns.GetHostEntryAsync(ip, cts.Token);
                    var host      = entry.HostName.ToLowerInvariant();
                    _dnsCache[ip] = (host, DateTime.UtcNow.Add(DnsCacheTtl));
                }
                catch
                {
                    // DNS failed — store empty string so we don't retry too often
                    _dnsCache[ip] = (string.Empty, DateTime.UtcNow.AddMinutes(2));
                }
            });
            // Don't await — intentionally fire-and-forget
        }
        catch { }

        return _dnsCache.TryGetValue(ip, out var c2) ? c2.host : string.Empty;
    }

    private static bool IsPrivateIp(IPAddress addr)
    {
        if (addr.AddressFamily != AddressFamily.InterNetwork) return false;
        if (IPAddress.IsLoopback(addr)) return true;
        uint ipUint = IpToUint(addr.ToString());
        return _privateRanges.Any(r => ipUint >= r.start && ipUint <= r.end);
    }

    private static bool IsLoopbackAddress(IPAddress addr)
    {
        return IPAddress.IsLoopback(addr) ||
               addr.ToString() == "127.0.0.1" ||
               addr.ToString() == "::1";
    }

    private static bool IsMiningHostname(string hostname)
    {
        var lower = hostname.ToLowerInvariant();
        return _miningHostPatterns.Any(p => lower.Contains(p));
    }

    private static uint IpToUint(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) return 0;
        uint result = 0;
        foreach (var part in parts)
        {
            result = (result << 8) | (uint.TryParse(part, out uint b) ? b : 0);
        }
        return result;
    }

    /// <summary>Evicts DNS cache entries for IPs no longer seen.</summary>
    public void PruneDnsCache()
    {
        var cutoff = DateTime.UtcNow;
        foreach (var kv in _dnsCache)
            if (kv.Value.expiry < cutoff)
                _dnsCache.TryRemove(kv.Key, out _);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _tracked.Clear();
        _dnsCache.Clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Result type
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>Scored network analysis result for a single process.</summary>
public sealed class NetworkAnalysis
{
    public int  Pid                      { get; init; }
    public int  Score                    { get; set; }
    public int  ConnectionCount          { get; set; }
    public int  ExternalConnectionCount  { get; set; }
    public int  MiningPortConnections    { get; set; }
    public int  LongLivedConnections     { get; set; }
    public int  MiningPoolConnections    { get; set; }
    public bool IsHighRisk               { get; set; }

    public List<NetworkConnectionInfo> SuspiciousConnections { get; init; } = new();
    public List<string>                Reasons               { get; init; } = new();
}
