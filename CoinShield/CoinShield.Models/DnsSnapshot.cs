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
    public int ProcessId { get; set; }

    /// <summary>Process name</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>DNS queries captured since last snapshot</summary>
    public List<DnsQuery> Queries { get; set; } = new();

    /// <summary>Number of queries to known mining pool domains</summary>
    public int MiningPoolQueryCount { get; set; }

    /// <summary>Number of queries to cryptocurrency-related domains</summary>
    public int CryptoRelatedQueryCount { get; set; }

    /// <summary>Number of queries to suspicious JavaScript CDNs</summary>
    public int SuspiciousJsCdnQueryCount { get; set; }

    /// <summary>Timestamp when snapshot was captured</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Represents a single DNS query
/// </summary>
public sealed class DnsQuery
{
    /// <summary>Domain name being queried</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Query type (A, AAAA, CNAME, etc.)</summary>
    public string QueryType { get; set; } = "A";

    /// <summary>Resolved IP addresses (if query succeeded)</summary>
    public List<string> ResolvedIps { get; set; } = new();

    /// <summary>Query timestamp</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>Process ID that initiated this query</summary>
    public int ProcessId { get; set; }

    /// <summary>Domain reputation assessment</summary>
    public DomainReputation Reputation { get; set; } = new();
}

/// <summary>
/// Domain reputation assessment based on threat intelligence
/// </summary>
public sealed class DomainReputation
{
    /// <summary>Domain being assessed</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Overall reputation score (0-100, lower is more suspicious)</summary>
    public int ReputationScore { get; set; } = 50;

    /// <summary>Whether domain is on mining pool blacklist</summary>
    public bool IsMiningPool { get; set; }

    /// <summary>Whether domain hosts known mining JavaScript (e.g., Coinhive, CryptoLoot)</summary>
    public bool HostsMiningScript { get; set; }

    /// <summary>Whether domain is cryptocurrency-related (not necessarily malicious)</summary>
    public bool IsCryptoRelated { get; set; }

    /// <summary>Whether domain is flagged as malicious by threat intelligence</summary>
    public bool IsMalicious { get; set; }

    /// <summary>Domain category (e.g., "mining-pool", "crypto-exchange", "mining-script-cdn")</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Threat level (None, Low, Medium, High, Critical)</summary>
    public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;

    /// <summary>Source of reputation data (e.g., "local-blacklist", "threat-intel-api")</summary>
    public string Source { get; set; } = "unknown";

    /// <summary>Additional notes or evidence</summary>
    public string? Notes { get; set; }
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
