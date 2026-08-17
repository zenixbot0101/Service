using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>
/// Snapshot of DNS queries and domain resolutions.
/// Used to detect mining pool domains, suspicious JavaScript CDNs, and crypto-related lookups.
/// </summary>
public sealed class DnsSnapshot
{
    /// <summary>Process ID that initiated the DNS query</summary>
    public int ProcessId { get; init; }

    /// <summary>Process name</summary>
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>DNS queries captured since last snapshot</summary>
    public List<DnsQuery> Queries { get; init; } = new();

    /// <summary>Number of queries to known mining pool domains</summary>
    public int MiningPoolQueryCount { get; init; }

    /// <summary>Number of queries to cryptocurrency-related domains</summary>
    public int CryptoRelatedQueryCount { get; init; }

    /// <summary>Number of queries to suspicious JavaScript CDNs</summary>
    public int SuspiciousJsCdnQueryCount { get; init; }

    /// <summary>Timestamp when snapshot was captured</summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Represents a single DNS query
/// </summary>
public sealed class DnsQuery
{
    /// <summary>Domain name being queried</summary>
    public string Domain { get; init; } = string.Empty;

    /// <summary>Query type (A, AAAA, CNAME, etc.)</summary>
    public string QueryType { get; init; } = "A";

    /// <summary>Resolved IP addresses (if query succeeded)</summary>
    public List<string> ResolvedIps { get; init; } = new();

    /// <summary>Query timestamp</summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    /// <summary>Process ID that initiated this query</summary>
    public int ProcessId { get; init; }

    /// <summary>Domain reputation assessment</summary>
    public DomainReputation Reputation { get; init; } = new();
}

/// <summary>
/// Domain reputation assessment based on threat intelligence
/// </summary>
public sealed class DomainReputation
{
    /// <summary>Domain being assessed</summary>
    public string Domain { get; init; } = string.Empty;

    /// <summary>Overall reputation score (0-100, lower is more suspicious)</summary>
    public int ReputationScore { get; init; } = 50;

    /// <summary>Whether domain is on mining pool blacklist</summary>
    public bool IsMiningPool { get; init; }

    /// <summary>Whether domain hosts known mining JavaScript (e.g., Coinhive, CryptoLoot)</summary>
    public bool HostsMiningScript { get; init; }

    /// <summary>Whether domain is cryptocurrency-related (not necessarily malicious)</summary>
    public bool IsCryptoRelated { get; init; }

    /// <summary>Whether domain is flagged as malicious by threat intelligence</summary>
    public bool IsMalicious { get; init; }

    /// <summary>Domain category (e.g., "mining-pool", "crypto-exchange", "mining-script-cdn")</summary>
    public string Category { get; init; } = string.Empty;

    /// <summary>Threat level (None, Low, Medium, High, Critical)</summary>
    public ThreatLevel ThreatLevel { get; init; } = ThreatLevel.None;

    /// <summary>Source of reputation data (e.g., "local-blacklist", "threat-intel-api")</summary>
    public string Source { get; init; } = "unknown";

    /// <summary>Additional notes or evidence</summary>
    public string? Notes { get; init; }
}

/// <summary>
/// Threat level enumeration
/// </summary>
public enum ThreatLevel
{
    /// <summary>No known threat</summary>
    None = 0,

    /// <summary>Low threat (crypto-related but not necessarily malicious)</summary>
    Low = 1,

    /// <summary>Medium threat (suspicious patterns, unknown reputation)</summary>
    Medium = 2,

    /// <summary>High threat (known mining infrastructure)</summary>
    High = 3,

    /// <summary>Critical threat (active mining attack confirmed)</summary>
    Critical = 4
}
