using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using CoinShield.Models;

namespace CoinShield.Core;

/// <summary>
/// Domain reputation engine with mining pool blacklist and threat intelligence.
/// Assesses domain reputation without blocking legitimate crypto-related domains.
/// </summary>
public sealed class DomainReputationEngine
{
    private readonly HashSet<string> _miningPoolDomains;
    private readonly HashSet<string> _miningScriptDomains;
    private readonly HashSet<string> _stratumDomains;
    private readonly HashSet<string> _legitimateDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Regex> _suspiciousPatterns;
    private readonly Dictionary<string, DomainReputation> _reputationCache;
    private readonly object _cacheLock = new();

    // Known browser mining scripts (Coinhive-style)
    private static readonly string[] KnownMiningScriptDomains = new[]
    {
        "coinhive.com",
        "coin-hive.com",
        "cnhv.co",
        "authedmine.com",
        "crypto-loot.com",
        "cryptoloot.pro",
        "webminepool.com",
        "webmine.pro",
        "jsecoin.com",
        "papoto.com",
        "minero.cc",
        "miner.pr0gramm.com",
        "coinerra.com",
        "minemytraffic.com",
        "coinnebula.com",
        "kiwifarms.net",
        "ppoi.org",
        "jsccnn.com",
        "host.d-ns.ga",
        "cdn.cloudcoins.co",
        "kisshentai.net",
        "afminer.com",
        "ppoi.org",
        "minr.pw",
        "webassembly.stream",
        "monerominer.rocks",
        "cryptonight.cc",
        "browsermine.com"
    };

    // Known mining pool infrastructure
    private static readonly string[] KnownMiningPools = new[]
    {
        // Monero pools
        "xmr.pool.minergate.com",
        "xmr-eu.dwarfpool.com",
        "xmr-usa.dwarfpool.com",
        "pool.supportxmr.com",
        "pool.minexmr.com",
        "mine.xmrpool.net",
        "xmr.nanopool.org",
        "monero.crypto-pool.fr",
        "xmrpool.eu",
        "monerohash.com",
        "moneroocean.stream",
        
        // Ethereum pools (less common for browser mining but possible)
        "eth.pool.minergate.com",
        "eu1.ethermine.org",
        "us1.ethermine.org",
        "asia1.ethermine.org",
        
        // Generic stratum endpoints
        "stratum.pool",
        "mining.pool",
        "pool.mining",
        
        // Other known pools
        "2miners.com",
        "f2pool.com",
        "hiveon.net",
        "nicehash.com",
        "prohashing.com"
    };

    // Suspicious domain patterns (not necessarily malicious)
    private static readonly string[] SuspiciousDomainPatterns = new[]
    {
        @"^(mine|mining|miner|pool|stratum|crypto|xmr|monero|eth)\d*\.",  // mine123.example.com
        @"\.(xyz|top|gq|ga|ml|cf|tk)$",  // Free TLDs often abused
        @"^(js|cdn|static|assets?|lib)\d*\.",  // Suspicious CDN-like names
        @"(webassembly|wasm|worker|miner|hash|crypto)",  // WASM/mining keywords in subdomain
        @"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.",  // IP-like subdomain (1-2-3-4.example.com)
    };

    public DomainReputationEngine(string? miningDomainsFilePath = null, List<string>? customBlacklist = null)
    {
        _miningPoolDomains  = new HashSet<string>(KnownMiningPools,       StringComparer.OrdinalIgnoreCase);
        _miningScriptDomains= new HashSet<string>(KnownMiningScriptDomains, StringComparer.OrdinalIgnoreCase);
        _stratumDomains     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _reputationCache    = new Dictionary<string, DomainReputation>(StringComparer.OrdinalIgnoreCase);

        _suspiciousPatterns = SuspiciousDomainPatterns
            .Select(p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.Compiled))
            .ToList();

        // BUG-11 FIX: Load blacklist from mining-domains.json if path provided
        if (!string.IsNullOrWhiteSpace(miningDomainsFilePath) &&
            System.IO.File.Exists(miningDomainsFilePath))
        {
            LoadFromFile(miningDomainsFilePath);
        }

        if (customBlacklist != null)
            foreach (var domain in customBlacklist)
                _miningPoolDomains.Add(domain);

        foreach (var domain in KnownMiningPools)
        {
            if (domain.Contains("stratum", StringComparison.OrdinalIgnoreCase) ||
                domain.Contains("pool",    StringComparison.OrdinalIgnoreCase))
                _stratumDomains.Add(domain);
        }
    }

    private void LoadFromFile(string path)
    {
        try
        {
            var json = System.IO.File.ReadAllText(path);
            using var doc = System.Text.Json.JsonDocument.Parse(json,
                new System.Text.Json.JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    CommentHandling     = System.Text.Json.JsonCommentHandling.Skip
                });

            var root = doc.RootElement;

            void LoadArray(string key, HashSet<string> target)
            {
                if (root.TryGetProperty(key, out var arr) &&
                    arr.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var item in arr.EnumerateArray())
                    {
                        var val = item.GetString();
                        if (!string.IsNullOrWhiteSpace(val))
                            target.Add(val);
                    }
                }
            }

            LoadArray("miningPools",    _miningPoolDomains);
            LoadArray("miningScriptCdns", _miningScriptDomains);

            // Load legitimate domains into a temporary set to whitelist them
            if (root.TryGetProperty("legitimateCryptoDomains", out var legit) &&
                legit.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var item in legit.EnumerateArray())
                {
                    var val = item.GetString();
                    if (!string.IsNullOrWhiteSpace(val))
                        _legitimateDomains.Add(val);
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"DomainReputationEngine: failed to load {path}: {ex.Message}");
        }
    }

    /// <summary>
    /// Assess domain reputation. Returns cached result if available.
    /// </summary>
    public DomainReputation AssessDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return new DomainReputation { Domain = domain, ReputationScore = 50 };
        }

        domain = NormalizeDomain(domain);

        // Check cache first
        lock (_cacheLock)
        {
            if (_reputationCache.TryGetValue(domain, out var cached))
            {
                return cached;
            }
        }

        // Compute reputation
        var reputation = ComputeReputation(domain);

        // Cache result
        lock (_cacheLock)
        {
            _reputationCache[domain] = reputation;
        }

        return reputation;
    }

    /// <summary>
    /// Check if domain is a known mining pool
    /// </summary>
    public bool IsMiningPool(string domain)
    {
        domain = NormalizeDomain(domain);
        return _miningPoolDomains.Contains(domain) || 
               _miningPoolDomains.Any(pool => domain.EndsWith(pool, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Check if domain hosts known mining scripts
    /// </summary>
    public bool HostsMiningScript(string domain)
    {
        domain = NormalizeDomain(domain);
        return _miningScriptDomains.Contains(domain) ||
               _miningScriptDomains.Any(script => domain.EndsWith(script, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Check if domain is cryptocurrency-related (not necessarily malicious)
    /// </summary>
    public bool IsCryptoRelated(string domain)
    {
        domain = NormalizeDomain(domain);
        
        // Legitimate exchanges and services should NOT trigger mining detection
        var legitimateCryptoKeywords = new[] 
        { 
            "coinbase", "binance", "kraken", "gemini", "blockchain.com", 
            "bitcoin.org", "ethereum.org", "bitcointalk.org",
            "coinmarketcap", "coingecko"
        };

        if (legitimateCryptoKeywords.Any(kw => domain.Contains(kw, StringComparison.OrdinalIgnoreCase)))
        {
            return true; // Crypto-related but legitimate
        }

        // Generic crypto keywords (weaker signal)
        var cryptoKeywords = new[] { "crypto", "bitcoin", "btc", "ethereum", "eth", "monero", "xmr" };
        return cryptoKeywords.Any(kw => domain.Contains(kw, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Add domain to custom blacklist at runtime
    /// </summary>
    public void AddToBlacklist(string domain, string category = "mining-pool")
    {
        domain = NormalizeDomain(domain);
        
        lock (_cacheLock)
        {
            if (category == "mining-script")
            {
                _miningScriptDomains.Add(domain);
            }
            else
            {
                _miningPoolDomains.Add(domain);
            }

            // Invalidate cache for this domain
            _reputationCache.Remove(domain);
        }
    }

    /// <summary>
    /// Clear reputation cache (call after updating blacklists)
    /// </summary>
    public void ClearCache()
    {
        lock (_cacheLock)
        {
            _reputationCache.Clear();
        }
    }

    /// <summary>
    /// Get statistics about blacklists
    /// </summary>
    public (int MiningPools, int MiningScripts, int Cached) GetStatistics()
    {
        lock (_cacheLock)
        {
            return (_miningPoolDomains.Count, _miningScriptDomains.Count, _reputationCache.Count);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private DomainReputation ComputeReputation(string domain)
    {
        var reputation = new DomainReputation { Domain = domain };

        // ── 0. File-loaded legitimate whitelist (highest priority) ─────────────
        if (_legitimateDomains.Contains(domain) ||
            _legitimateDomains.Any(ld => domain.EndsWith($".{ld}", StringComparison.OrdinalIgnoreCase)))
        {
            return new DomainReputation
            {
                Domain           = domain,
                IsCryptoRelated  = true,
                ReputationScore  = 90,
                ThreatLevel      = ThreatLevel.None,
                Category         = "crypto-exchange-whitelisted",
                Source           = "local-whitelist"
            };
        }

        // Check exact matches first (highest confidence)
        if (_miningPoolDomains.Contains(domain))
        {
            return new DomainReputation
            {
                Domain = domain,
                IsMiningPool = true,
                ReputationScore = 5,
                ThreatLevel = ThreatLevel.High,
                Category = "mining-pool",
                Source = "local-blacklist",
                IsMalicious = true
            };
        }

        if (_miningScriptDomains.Contains(domain))
        {
            return new DomainReputation
            {
                Domain = domain,
                HostsMiningScript = true,
                ReputationScore = 0,
                ThreatLevel = ThreatLevel.Critical,
                Category = "mining-script-cdn",
                Source = "local-blacklist",
                IsMalicious = true
            };
        }

        // Check subdomain matches (e.g., subdomain.coinhive.com)
        foreach (var scriptDomain in _miningScriptDomains)
        {
            if (domain.EndsWith($".{scriptDomain}", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainReputation
                {
                    Domain = domain,
                    HostsMiningScript = true,
                    ReputationScore = 0,
                    ThreatLevel = ThreatLevel.Critical,
                    Category = "mining-script-cdn",
                    Source = "local-blacklist",
                    IsMalicious = true,
                    Notes = $"Subdomain of known mining script host: {scriptDomain}"
                };
            }
        }

        // Check if domain is crypto-related but legitimate
        var isCrypto = IsCryptoRelated(domain);
        if (isCrypto)
        {
            // Check if it's a legitimate service
            var legitimateServices = new[] 
            { 
                "coinbase", "binance", "kraken", "gemini", "blockchain.com",
                "bitcoin.org", "ethereum.org", "coinmarketcap", "coingecko"
            };

            if (legitimateServices.Any(s => domain.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return new DomainReputation
                {
                    Domain = domain,
                    IsCryptoRelated = true,
                    ReputationScore = 80,  // High reputation for legitimate services
                    ThreatLevel = ThreatLevel.None,
                    Category = "crypto-exchange",
                    Source = "local-whitelist"
                };
            }

            // Crypto-related but unknown
            reputation.IsCryptoRelated = true;
            reputation.ReputationScore = 40;  // Lower score but not necessarily malicious
            reputation.ThreatLevel = ThreatLevel.Low;
            reputation.Category = "crypto-related";
        }

        // Check suspicious patterns
        int suspiciousMatches = 0;
        foreach (var pattern in _suspiciousPatterns)
        {
            if (pattern.IsMatch(domain))
            {
                suspiciousMatches++;
            }
        }

        if (suspiciousMatches > 0)
        {
            reputation.ReputationScore = Math.Max(0, reputation.ReputationScore - (suspiciousMatches * 15));
            reputation.ThreatLevel = suspiciousMatches >= 2 ? ThreatLevel.Medium : ThreatLevel.Low;
            reputation.Notes = $"Matched {suspiciousMatches} suspicious pattern(s)";
            reputation.Source = "pattern-analysis";
        }

        // Default: unknown reputation
        if (reputation.ReputationScore == 0 && !reputation.IsMalicious)
        {
            reputation.ReputationScore = 50;  // Neutral
            reputation.Source = "unknown";
        }

        return reputation;
    }

    private static string NormalizeDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return string.Empty;

        // Remove protocol
        domain = domain.Replace("https://", "").Replace("http://", "").Replace("ws://", "").Replace("wss://", "");
        
        // Remove port
        var portIndex = domain.IndexOf(':');
        if (portIndex > 0)
            domain = domain[..portIndex];

        // Remove path
        var pathIndex = domain.IndexOf('/');
        if (pathIndex > 0)
            domain = domain[..pathIndex];

        // Remove trailing dot
        domain = domain.TrimEnd('.');

        return domain.ToLowerInvariant();
    }
}
