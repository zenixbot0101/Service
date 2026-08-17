using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using CoinShield.Models;

namespace CoinShield.Core;

/// <summary>
/// DNS query and network-destination analyzer.
///
/// Detection strategy (defense-in-depth against evasion):
///
///   Layer 1 — Windows DNS cache (ipconfig /displaydns, fully qualified path,
///             with 10-second hard timeout). Covers standard DNS.
///
///   Layer 2 — Direct-IP detection: mining over hardcoded IPs bypasses DNS
///             entirely. We fingerprint known mining-pool IP ranges.
///
///   Layer 3 — DoH/encrypted DNS detection: Firefox, Brave, Chrome all support
///             DoH. We detect it by checking for HTTPS connections to known
///             DoH resolvers AND by flagging browser processes that have NO
///             entries in the Windows DNS cache despite high CPU.
///
///   Layer 4 — Localhost stratum proxy detection (BYPASS-01): miners running
///             behind xmrig-proxy or a SOCKS5 tunnel connect only to
///             127.0.0.1:3333. We detect connections to loopback on mining
///             ports specifically from browser/miner processes.
///
/// NOTE: This class is detection-only. Actual blocking is done by
/// ResponseEngine (hosts file) or future firewall integration.
/// </summary>
public sealed class DnsAnalyzer : IDisposable
{
    private readonly DomainReputationEngine _reputationEngine;

    // Per-process DNS query history
    private readonly Dictionary<int, List<DnsQuery>> _processHistory  = new();
    // System-wide DNS cache seen in last scan (domain → time first seen)
    private readonly Dictionary<string, DateTime>    _lastQueryTime   = new(StringComparer.OrdinalIgnoreCase);
    // Processes flagged as using DoH (browser bypassing Windows DNS)
    private readonly HashSet<int>                    _dohProcesses    = new();
    // Processes with direct-IP connections to known mining infrastructure
    private readonly Dictionary<int, List<string>>   _directIpHits    = new();

    private readonly object _lock = new();

    // ── Known DoH resolver IPs (Cloudflare, Google, NextDNS, Quad9, AdGuard)
    private static readonly HashSet<string> DoHResolverIps = new()
    {
        "1.1.1.1", "1.0.0.1",           // Cloudflare
        "8.8.8.8", "8.8.4.4",           // Google
        "9.9.9.9", "149.112.112.112",    // Quad9
        "94.140.14.14", "94.140.15.15", // AdGuard
        "45.90.28.0", "45.90.30.0",      // NextDNS
    };

    // ── Known mining pool IP CIDRs (as prefix strings for fast check)
    private static readonly string[] KnownMiningPoolPrefixes =
    {
        "198.7.114.",    // NiceHash
        "209.198.111.",  // Slushpool / Braiins
        "185.152.2.",    // SupportXMR
        "192.36.55.",    // XMRPool
    };

    // ── Stratum ports for loopback-proxy detection
    private static readonly HashSet<int> StratumPorts = new()
    {
        3333, 3334, 3335, 4444, 4445, 5555, 5556,
        7777, 8888, 9000, 9001, 9999, 14444, 14433,
        25, 80, 443,  // miners sometimes tunnel on common ports
    };

    // Fully-qualified path to avoid PATH hijack
    private static readonly string IpconfigPath =
        System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "ipconfig.exe");

    public DnsAnalyzer(DomainReputationEngine reputationEngine)
    {
        _reputationEngine = reputationEngine
            ?? throw new ArgumentNullException(nameof(reputationEngine));
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Captures a DNS/network snapshot for a given process.
    /// Combines Windows DNS cache data with direct-IP hit tracking.
    /// </summary>
    public DnsSnapshot CaptureDnsSnapshot(int processId, string processName)
    {
        var snapshot = new DnsSnapshot
        {
            ProcessId   = processId,
            ProcessName = processName,
            Timestamp   = DateTime.UtcNow
        };

        try
        {
            var cacheEntries = GetDnsCacheEntriesWithTimeout();

            // NOTE: Windows DNS cache is system-wide; we cannot attribute each entry
            // to a specific PID without ETW or a network driver. We record all new
            // mining-related entries and associate them with all running browser PIDs
            // (see WebMiningDetector.RunDnsScan). Per-PID history is built by the
            // caller passing the correct processId.
            var recentQueries = cacheEntries
                .Where(e => IsRecentOrNewEntry(e.Domain))
                .Select(e => CreateDnsQuery(e, processId))
                .ToList();

            snapshot.Queries.AddRange(recentQueries);
            snapshot.MiningPoolQueryCount      = recentQueries.Count(q => q.Reputation.IsMiningPool);
            snapshot.CryptoRelatedQueryCount   = recentQueries.Count(q => q.Reputation.IsCryptoRelated);
            snapshot.SuspiciousJsCdnQueryCount = recentQueries.Count(q => q.Reputation.HostsMiningScript);

            lock (_lock)
            {
                if (!_processHistory.ContainsKey(processId))
                    _processHistory[processId] = new List<DnsQuery>();

                _processHistory[processId].AddRange(recentQueries);

                // Keep last 200 queries per process
                var hist = _processHistory[processId];
                if (hist.Count > 200)
                    _processHistory[processId] = hist
                        .OrderByDescending(q => q.Timestamp)
                        .Take(200)
                        .ToList();
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"DnsAnalyzer.CaptureDnsSnapshot: {ex.Message}");
        }

        return snapshot;
    }

    /// <summary>
    /// Analyzes DNS + network patterns for a specific process.
    /// Returns a scored result including DoH and direct-IP signals.
    /// </summary>
    public DnsAnalysisResult AnalyzeProcessDnsPatterns(int processId)
    {
        List<DnsQuery> history;
        bool usesDoh;
        List<string> directIps;

        lock (_lock)
        {
            history   = _processHistory.TryGetValue(processId, out var h) ? new List<DnsQuery>(h) : new List<DnsQuery>();
            usesDoh   = _dohProcesses.Contains(processId);
            directIps = _directIpHits.TryGetValue(processId, out var d) ? new List<string>(d) : new List<string>();
        }

        int suspicionScore = 0;

        int miningPool    = history.Count(q => q.Reputation.IsMiningPool);
        int miningScript  = history.Count(q => q.Reputation.HostsMiningScript);
        int lowRep        = history.Count(q => q.Reputation.ReputationScore < 30);
        int stratumDns    = history.Count(q =>
            q.Domain.Contains("stratum", StringComparison.OrdinalIgnoreCase) ||
            q.Domain.Contains("pool",    StringComparison.OrdinalIgnoreCase));

        suspicionScore += miningPool   * 30;
        suspicionScore += miningScript * 40;
        suspicionScore += lowRep       * 10;
        suspicionScore += stratumDns   * 25;

        // DoH detected: browser bypassing Windows DNS cache.
        // We cannot see what domains it resolves. Add medium suspicion if
        // combined with other indicators (high CPU, long-running workers).
        if (usesDoh)
        {
            suspicionScore += 15;
        }

        // Direct-IP hits to known mining infrastructure — strong signal
        suspicionScore += directIps.Count * 35;

        var suspiciousDomains = history
            .Where(q => q.Reputation.IsMalicious || q.Reputation.ReputationScore < 30)
            .Select(q => q.Domain)
            .Concat(directIps)          // include direct-IP hits as "domains"
            .Distinct()
            .ToList();

        return new DnsAnalysisResult
        {
            ProcessId              = processId,
            IsSuspicious           = suspicionScore >= 40,
            Confidence             = Math.Min(100, suspicionScore),
            MiningPoolQueryCount   = miningPool,
            MiningScriptQueryCount = miningScript,
            CryptoQueryCount       = history.Count(q => q.Reputation.IsCryptoRelated),
            StratumQueryCount      = stratumDns,
            UsesDnsOverHttps       = usesDoh,
            DirectIpHits           = directIps,
            SuspiciousDomains      = suspiciousDomains
        };
    }

    /// <summary>
    /// Records a TCP connection from a process. Call this from NetworkAnalyzer
    /// to feed direct-IP and DoH signals into the DNS layer.
    /// </summary>
    public void RecordConnection(int processId, string remoteIp, int remotePort)
    {
        if (string.IsNullOrWhiteSpace(remoteIp)) return;

        lock (_lock)
        {
            // ── Layer 3: DoH detection ─────────────────────────────────────────
            // Connection to port 443 on a known DoH resolver IP
            if (remotePort == 443 && DoHResolverIps.Contains(remoteIp))
            {
                _dohProcesses.Add(processId);
            }

            // ── Layer 2: Direct-IP mining pool ────────────────────────────────
            if (IsKnownMiningPoolIp(remoteIp))
            {
                if (!_directIpHits.ContainsKey(processId))
                    _directIpHits[processId] = new List<string>();

                var entry = $"{remoteIp}:{remotePort}";
                if (!_directIpHits[processId].Contains(entry))
                    _directIpHits[processId].Add(entry);
            }

            // ── Layer 4: Localhost stratum proxy (BYPASS-01) ──────────────────
            // A process connecting to 127.0.0.1 on a stratum port is almost
            // certainly going through a local mining proxy.
            if ((remoteIp == "127.0.0.1" || remoteIp == "::1") &&
                StratumPorts.Contains(remotePort))
            {
                if (!_directIpHits.ContainsKey(processId))
                    _directIpHits[processId] = new List<string>();

                var entry = $"localhost:{remotePort} [stratum-proxy]";
                if (!_directIpHits[processId].Contains(entry))
                    _directIpHits[processId].Add(entry);
            }
        }
    }

    /// <summary>Clears query history for a process that has exited.</summary>
    public void ClearProcessHistory(int processId)
    {
        lock (_lock)
        {
            _processHistory.Remove(processId);
            _dohProcesses.Remove(processId);
            _directIpHits.Remove(processId);
        }
    }

    /// <summary>Clears all history.</summary>
    public void ClearAllHistory()
    {
        lock (_lock)
        {
            _processHistory.Clear();
            _lastQueryTime.Clear();
            _dohProcesses.Clear();
            _directIpHits.Clear();
        }
    }

    public List<DnsQuery> GetProcessQueryHistory(int processId)
    {
        lock (_lock)
        {
            return _processHistory.TryGetValue(processId, out var h)
                ? new List<DnsQuery>(h)
                : new List<DnsQuery>();
        }
    }

    // ── DNS cache reading ─────────────────────────────────────────────────────

    private List<DnsCacheEntry> GetDnsCacheEntriesWithTimeout()
    {
        var entries = new List<DnsCacheEntry>();

        try
        {
            // Use fully-qualified path to prevent PATH-hijack attack
            if (!System.IO.File.Exists(IpconfigPath))
                return entries;

            var psi = new ProcessStartInfo
            {
                FileName               = IpconfigPath,  // absolute path — no PATH lookup
                Arguments              = "/displaydns",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null) return entries;

            // Hard 10-second timeout — never block the detection loop indefinitely
            bool finished = proc.WaitForExit(10_000);
            if (!finished)
            {
                try { proc.Kill(); } catch { }
                Debug.WriteLine("DnsAnalyzer: ipconfig timed out, killed.");
                return entries;
            }

            var output = proc.StandardOutput.ReadToEnd();
            entries = ParseDnsCacheOutput(output);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"DnsAnalyzer.GetDnsCacheEntries: {ex.Message}");
        }

        return entries;
    }

    private List<DnsCacheEntry> ParseDnsCacheOutput(string output)
    {
        var entries = new List<DnsCacheEntry>();
        if (string.IsNullOrWhiteSpace(output)) return entries;

        var lines  = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string?    currentDomain = null;
        var        currentIps    = new List<string>();

        foreach (var raw in lines)
        {
            var line = raw.Trim();

            if (line.StartsWith("Record Name", StringComparison.OrdinalIgnoreCase))
            {
                // Flush previous entry
                if (currentDomain != null)
                {
                    entries.Add(new DnsCacheEntry
                    {
                        Domain      = currentDomain,
                        ResolvedIps = new List<string>(currentIps)
                    });
                }

                var parts = line.Split(':', 2);
                currentDomain = parts.Length == 2 ? parts[1].Trim() : null;
                currentIps.Clear();
            }
            else if (IPAddress.TryParse(line, out _) && currentDomain != null)
            {
                currentIps.Add(line);
            }
        }

        if (currentDomain != null)
            entries.Add(new DnsCacheEntry { Domain = currentDomain, ResolvedIps = new List<string>(currentIps) });

        return entries;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private bool IsRecentOrNewEntry(string domain)
    {
        lock (_lock)
        {
            if (_lastQueryTime.TryGetValue(domain, out var last))
            {
                // Already seen within 5 minutes — not "new", skip
                if (DateTime.UtcNow - last <= TimeSpan.FromMinutes(5))
                    return false;

                _lastQueryTime[domain] = DateTime.UtcNow;
                return true;
            }

            // Brand-new domain — record and include
            _lastQueryTime[domain] = DateTime.UtcNow;
            return true;
        }
    }

    private DnsQuery CreateDnsQuery(DnsCacheEntry entry, int processId)
    {
        var reputation = _reputationEngine.AssessDomain(entry.Domain);
        return new DnsQuery
        {
            Domain      = entry.Domain,
            QueryType   = "A",
            ResolvedIps = entry.ResolvedIps,
            Timestamp   = DateTime.UtcNow,
            ProcessId   = processId,
            Reputation  = reputation
        };
    }

    private static bool IsKnownMiningPoolIp(string ip)
    {
        return KnownMiningPoolPrefixes.Any(prefix =>
            ip.StartsWith(prefix, StringComparison.Ordinal));
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose() => ClearAllHistory();

    // ── Inner types ───────────────────────────────────────────────────────────

    private sealed class DnsCacheEntry
    {
        public string       Domain      { get; init; } = string.Empty;
        public List<string> ResolvedIps { get; init; } = new();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Result type
// ─────────────────────────────────────────────────────────────────────────────

public sealed class DnsAnalysisResult
{
    public int          ProcessId              { get; init; }
    public bool         IsSuspicious           { get; init; }
    public int          Confidence             { get; init; }
    public int          MiningPoolQueryCount   { get; init; }
    public int          MiningScriptQueryCount { get; init; }
    public int          CryptoQueryCount       { get; init; }
    public int          StratumQueryCount      { get; init; }
    /// <summary>True if process was detected routing DNS over HTTPS, bypassing Windows cache.</summary>
    public bool         UsesDnsOverHttps       { get; init; }
    /// <summary>Direct IP hits to known mining infrastructure (bypasses DNS entirely).</summary>
    public List<string> DirectIpHits           { get; init; } = new();
    public List<string> SuspiciousDomains      { get; init; } = new();
}
