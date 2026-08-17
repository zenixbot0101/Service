using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  Allowlist data model (mirrors allowlist.json structure)
// ─────────────────────────────────────────────────────────────────────────────

internal sealed class AllowlistData
{
    [JsonPropertyName("trustedPublishers")]
    public List<string> TrustedPublishers { get; set; } = new();

    [JsonPropertyName("trustedExecutablePaths")]
    public List<string> TrustedExecutablePaths { get; set; } = new();

    [JsonPropertyName("trustedProcessNames")]
    public List<string> TrustedProcessNames { get; set; } = new();

    [JsonPropertyName("trustedSha256Hashes")]
    public List<string> TrustedSha256Hashes { get; set; } = new();

    [JsonPropertyName("aiFrameworks")]
    public List<string> AiFrameworks { get; set; } = new();

    [JsonPropertyName("aiScriptPatterns")]
    public List<string> AiScriptPatterns { get; set; } = new();

    [JsonPropertyName("knownMiningProcessNames")]
    public List<string> KnownMiningProcessNames { get; set; } = new();

    [JsonPropertyName("knownMiningCommandLineTokens")]
    public List<string> KnownMiningCommandLineTokens { get; set; } = new();

    [JsonPropertyName("knownMaliciousSha256Hashes")]
    public List<string> KnownMaliciousSha256Hashes { get; set; } = new();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Allowlist query result
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// The verdict produced by <see cref="AllowlistEngine"/> for a single process.
/// </summary>
public sealed class AllowlistResult
{
    /// <summary>How well this process matches trusted / known categories.</summary>
    public AllowlistVerdict Verdict { get; init; }

    /// <summary>Score modifier to apply (negative = reduce suspicion, positive = raise it).</summary>
    public int ScoreModifier { get; init; }

    /// <summary>Human-readable reason for this verdict.</summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>True if any AI-framework signal was detected in this process.</summary>
    public bool IsAiFrameworkEvidence { get; init; }

    /// <summary>True if a known mining process name was matched.</summary>
    public bool IsKnownMinerName { get; init; }

    /// <summary>True if a command-line token matched a mining pattern.</summary>
    public bool HasMiningCommandLine { get; init; }

    /// <summary>True if the hash is on the known-malicious list.</summary>
    public bool IsKnownMalicious { get; init; }
}

public enum AllowlistVerdict
{
    /// <summary>Not found in any list — no modifier applied.</summary>
    Unknown,
    /// <summary>Process is on a trusted list — score is reduced.</summary>
    Trusted,
    /// <summary>Hash matches the known-malicious list — score is raised significantly.</summary>
    KnownMalicious,
    /// <summary>Process name or command line matches known miner patterns.</summary>
    KnownMiner,
    /// <summary>Evidence of an AI/ML framework detected.</summary>
    AiFramework,
}

// ─────────────────────────────────────────────────────────────────────────────
//  AllowlistEngine
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Loads and evaluates the allowlist for every process snapshot.
///
/// Key design principles:
/// — Allowlisting by publisher or hash REDUCES score, it does NOT bypass monitoring.
/// — Even a trusted application is flagged if its hash changes, it spawns suspicious
///   children, creates suspicious persistence, or communicates with mining infrastructure.
/// — Filename alone is NOT sufficient for allowlisting (a miner can rename itself).
/// — All pattern matching is case-insensitive.
/// </summary>
public sealed class AllowlistEngine
{
    private readonly CoinShieldConfig  _cfg;
    private readonly CoinShieldLogger  _logger;
    private AllowlistData              _data = new();

    // Compiled sets for O(1) lookup after loading
    private HashSet<string>   _trustedPublishersLower   = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>   _trustedNamesLower        = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>   _trustedHashesUpper       = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>   _maliciousHashesUpper     = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>   _miningNamesLower         = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>   _aiFrameworksLower        = new(StringComparer.OrdinalIgnoreCase);

    // Glob-style path patterns compiled to regexes
    private List<Regex>       _trustedPathPatterns      = new();
    // Mining command-line tokens (lower-case for comparison)
    private List<string>      _miningCmdTokens          = new();
    // AI script name patterns (lower-case)
    private List<string>      _aiScriptPatterns         = new();

    // ── Construction ─────────────────────────────────────────────────────────

    public AllowlistEngine(CoinShieldConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Load / reload ─────────────────────────────────────────────────────────

    /// <summary>
    /// Loads the allowlist from disk.  Must be called before <see cref="Evaluate"/>.
    /// Safe to call again at runtime for hot-reload (take a lock in the caller).
    /// </summary>
    public void Load()
    {
        var path = ResolveAllowlistPath();

        if (!File.Exists(path))
        {
            _logger.Warning("Allowlist", $"Allowlist file not found at {path}; using empty defaults.");
            CompileIndexes(new AllowlistData());
            return;
        }

        try
        {
            var json = File.ReadAllText(path);
            var data = JsonSerializer.Deserialize<AllowlistData>(json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas         = true,
                    ReadCommentHandling         = JsonCommentHandling.Skip,
                }) ?? new AllowlistData();

            CompileIndexes(data);
            _logger.Info("Allowlist",
                $"Allowlist loaded: {_trustedPublishersLower.Count} publishers, " +
                $"{_trustedNamesLower.Count} names, " +
                $"{_trustedHashesUpper.Count} trusted hashes, " +
                $"{_maliciousHashesUpper.Count} malicious hashes, " +
                $"{_trustedPathPatterns.Count} path patterns, " +
                $"{_miningNamesLower.Count} known miner names, " +
                $"{_miningCmdTokens.Count} mining command tokens.");
        }
        catch (Exception ex)
        {
            _logger.Error("Allowlist", $"Failed to load allowlist: {ex.Message}");
            CompileIndexes(new AllowlistData());
        }
    }

    // ── Main evaluation ───────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates a process snapshot against the allowlist and returns a
    /// scored verdict.  Never returns a verdict that unconditionally bypasses
    /// further monitoring.
    /// </summary>
    public AllowlistResult Evaluate(ProcessSnapshot snap)
    {
        // ── 1. Known-malicious hash — highest priority ────────────────────────
        if (!string.IsNullOrWhiteSpace(snap.Sha256)
            && _maliciousHashesUpper.Contains(snap.Sha256.ToUpperInvariant()))
        {
            return new AllowlistResult
            {
                Verdict          = AllowlistVerdict.KnownMalicious,
                ScoreModifier    = 0,   // The +100 is already in the RiskScorer; don't double-add
                Reason           = $"SHA-256 {snap.Sha256[..8]}… is on the known-malicious list.",
                IsKnownMalicious = true,
            };
        }

        // ── 2. Known miner process name ───────────────────────────────────────
        var nameLower = snap.Name.ToLowerInvariant().TrimEnd('.');
        // Strip .exe suffix for comparison
        var nameStripped = nameLower.EndsWith(".exe")
            ? nameLower[..^4]
            : nameLower;

        if (_miningNamesLower.Contains(nameStripped))
        {
            return new AllowlistResult
            {
                Verdict           = AllowlistVerdict.KnownMiner,
                ScoreModifier     = 0,  // handled by ProcessAnalyzer name-match path
                Reason            = $"Process name '{snap.Name}' matches known mining software.",
                IsKnownMinerName  = true,
            };
        }

        // ── 3. Mining command-line tokens ─────────────────────────────────────
        bool hasMiningCmd = false;
        if (!string.IsNullOrWhiteSpace(snap.CommandLine))
        {
            var cmdLower = snap.CommandLine.ToLowerInvariant();
            hasMiningCmd = _miningCmdTokens.Any(t => cmdLower.Contains(t));
        }

        // ── 4. AI framework evidence ──────────────────────────────────────────
        bool isAiEvidence = DetectAiFramework(snap);

        // ── 5. Trusted hash (exact) ───────────────────────────────────────────
        bool trustedHash = !string.IsNullOrWhiteSpace(snap.Sha256)
            && _trustedHashesUpper.Contains(snap.Sha256.ToUpperInvariant());

        // ── 6. Trusted publisher ──────────────────────────────────────────────
        bool trustedPublisher = !string.IsNullOrWhiteSpace(snap.Publisher)
            && _trustedPublishersLower.Contains(snap.Publisher.Trim());

        // ── 7. Trusted process name (weak — filename alone is NOT sufficient) ─
        bool trustedName = _trustedNamesLower.Contains(nameStripped);

        // ── 8. Trusted executable path ────────────────────────────────────────
        bool trustedPath = !string.IsNullOrWhiteSpace(snap.Path)
            && MatchesTrustedPath(snap.Path);

        // ── Compose verdict ───────────────────────────────────────────────────

        // Mining command line overrides all trust signals — even a trusted
        // application should be flagged if its command line carries mining tokens.
        if (hasMiningCmd)
        {
            return new AllowlistResult
            {
                Verdict              = AllowlistVerdict.KnownMiner,
                ScoreModifier        = 0,  // handled by CommandLineScore in RiskScorer
                Reason               = "Command line contains known mining parameters.",
                HasMiningCommandLine = true,
                IsAiFrameworkEvidence = isAiEvidence,
            };
        }

        // AI framework detected
        if (isAiEvidence && !hasMiningCmd)
        {
            var aiReason = BuildAiReason(snap);
            return new AllowlistResult
            {
                Verdict               = AllowlistVerdict.AiFramework,
                ScoreModifier         = 0,  // The -40 mitigation is in RiskScorer via AiTrainingBonus
                Reason                = aiReason,
                IsAiFrameworkEvidence = true,
            };
        }

        // Trusted via hash + publisher (strongest trust signal)
        if (trustedHash && trustedPublisher)
        {
            return new AllowlistResult
            {
                Verdict       = AllowlistVerdict.Trusted,
                ScoreModifier = 0,  // RiskScorer applies TrustedApplication + TrustedPublisher bonuses
                Reason        = $"Trusted: publisher '{snap.Publisher}' + hash verified.",
            };
        }

        // Trusted via publisher alone
        if (trustedPublisher)
        {
            return new AllowlistResult
            {
                Verdict       = AllowlistVerdict.Trusted,
                ScoreModifier = 0,
                Reason        = $"Trusted publisher: '{snap.Publisher}'.",
            };
        }

        // Trusted via path + name (medium confidence)
        if (trustedPath && trustedName)
        {
            return new AllowlistResult
            {
                Verdict       = AllowlistVerdict.Trusted,
                ScoreModifier = 0,
                Reason        = $"Trusted by path pattern and process name '{snap.Name}'.",
            };
        }

        // Trusted path alone (weak — still monitor, just lower score)
        if (trustedPath)
        {
            return new AllowlistResult
            {
                Verdict       = AllowlistVerdict.Trusted,
                ScoreModifier = 0,
                Reason        = $"Executable path matches a trusted location.",
            };
        }

        // Not found in any list
        return new AllowlistResult
        {
            Verdict               = AllowlistVerdict.Unknown,
            ScoreModifier         = 0,
            Reason                = "No allowlist match.",
            IsAiFrameworkEvidence = isAiEvidence,
            HasMiningCommandLine  = hasMiningCmd,
        };
    }

    // ── AI framework detection ────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the process snapshot carries at least one signal
    /// suggesting a legitimate AI/ML workload.
    ///
    /// Does NOT blindly whitelist all Python processes — it inspects the
    /// combination of name, command line, parent and module path.
    /// </summary>
    public bool DetectAiFramework(ProcessSnapshot snap)
    {
        var cmdLower  = (snap.CommandLine ?? string.Empty).ToLowerInvariant();
        var nameLower = snap.Name.ToLowerInvariant();
        var pathLower = (snap.Path ?? string.Empty).ToLowerInvariant();

        // Direct AI framework process (e.g. python running pytorch/tf)
        bool isPythonLike = nameLower is "python" or "python3" or "python.exe" or "python3.exe"
                         or "pythonw" or "pythonw.exe"
                         or "jupyter" or "jupyter.exe"
                         or "jupyter-notebook" or "jupyter-lab"
                         or "ipython" or "ipython.exe";

        // Command line references a known AI framework module
        bool frameworkInCmd = _aiFrameworksLower.Any(f => cmdLower.Contains(f));

        // Script name matches training patterns
        bool trainingScript = _aiScriptPatterns.Any(p => cmdLower.Contains(p));

        // Parent is a known ML IDE / tool
        bool mlParent = snap.ParentName.ToLowerInvariant() is
            "code" or "code.exe"           // VS Code
            or "devenv" or "devenv.exe"    // Visual Studio
            or "jupyter" or "jupyter.exe"
            or "pycharm" or "pycharm64.exe"
            or "spyder" or "spyder.exe"
            or "anaconda" or "anaconda3";

        // Path is inside a known ML environment
        bool mlPath = pathLower.Contains("torch")
                   || pathLower.Contains("tensorflow")
                   || pathLower.Contains("anaconda")
                   || pathLower.Contains("conda")
                   || pathLower.Contains("jupyter")
                   || pathLower.Contains("cuda\\bin")
                   || pathLower.Contains("nvidia gpu computing toolkit");

        // Score each signal
        int aiSignals = 0;
        if (isPythonLike && frameworkInCmd) aiSignals += 2; // strong combination
        if (isPythonLike && trainingScript) aiSignals += 2;
        if (frameworkInCmd)                aiSignals += 1;
        if (trainingScript)                aiSignals += 1;
        if (mlParent)                      aiSignals += 1;
        if (mlPath)                        aiSignals += 1;

        // Require at least 2 AI signals to classify as AI workload evidence
        return aiSignals >= 2;
    }

    /// <summary>Returns list of AI signal descriptions found for a process.</summary>
    public List<string> GetAiSignals(ProcessSnapshot snap)
    {
        var signals   = new List<string>();
        var cmdLower  = (snap.CommandLine ?? string.Empty).ToLowerInvariant();
        var nameLower = snap.Name.ToLowerInvariant();
        var pathLower = (snap.Path ?? string.Empty).ToLowerInvariant();

        if (nameLower is "python" or "python3" or "python.exe" or "python3.exe"
                      or "pythonw" or "pythonw.exe" or "jupyter" or "jupyter.exe"
                      or "jupyter-notebook" or "jupyter-lab" or "ipython" or "ipython.exe")
            signals.Add($"Python/Jupyter process: {snap.Name}");

        foreach (var f in _aiFrameworksLower.Where(f => cmdLower.Contains(f)))
            signals.Add($"AI framework in command line: {f}");

        foreach (var p in _aiScriptPatterns.Where(p => cmdLower.Contains(p)))
            signals.Add($"Training script pattern: {p}");

        if (snap.ParentName.ToLowerInvariant() is "code" or "devenv" or "pycharm64.exe"
                                                         or "jupyter")
            signals.Add($"ML parent process: {snap.ParentName}");

        if (pathLower.Contains("anaconda") || pathLower.Contains("conda"))
            signals.Add("Conda/Anaconda environment path");

        if (pathLower.Contains("cuda\\bin") || pathLower.Contains("nvidia gpu computing toolkit"))
            signals.Add("CUDA toolkit path");

        return signals;
    }

    // ── Known miner helpers (public so other analyzers can call them) ─────────

    public bool IsKnownMinerName(string processName)
    {
        var n = processName.ToLowerInvariant().TrimEnd('.');
        if (n.EndsWith(".exe")) n = n[..^4];
        return _miningNamesLower.Contains(n);
    }

    public bool HasMiningCommandLineTokens(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        var lower = commandLine.ToLowerInvariant();
        return _miningCmdTokens.Any(t => lower.Contains(t));
    }

    public IReadOnlyList<string> GetMiningCommandLineMatches(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return Array.Empty<string>();
        var lower   = commandLine.ToLowerInvariant();
        var matches = new List<string>();
        foreach (var t in _miningCmdTokens)
            if (lower.Contains(t))
                matches.Add(t);
        return matches;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void CompileIndexes(AllowlistData data)
    {
        _data = data;

        _trustedPublishersLower = new HashSet<string>(
            data.TrustedPublishers.Select(p => p.Trim()),
            StringComparer.OrdinalIgnoreCase);

        _trustedNamesLower = new HashSet<string>(
            data.TrustedProcessNames.Select(n =>
            {
                var l = n.ToLowerInvariant().Trim();
                return l.EndsWith(".exe") ? l[..^4] : l;
            }),
            StringComparer.OrdinalIgnoreCase);

        _trustedHashesUpper = new HashSet<string>(
            data.TrustedSha256Hashes
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.Trim().ToUpperInvariant()),
            StringComparer.OrdinalIgnoreCase);

        _maliciousHashesUpper = new HashSet<string>(
            data.KnownMaliciousSha256Hashes
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.Trim().ToUpperInvariant()),
            StringComparer.OrdinalIgnoreCase);

        _miningNamesLower = new HashSet<string>(
            data.KnownMiningProcessNames.Select(n =>
            {
                var l = n.ToLowerInvariant().Trim();
                return l.EndsWith(".exe") ? l[..^4] : l;
            }),
            StringComparer.OrdinalIgnoreCase);

        _aiFrameworksLower = new HashSet<string>(
            data.AiFrameworks.Select(f => f.ToLowerInvariant().Trim()),
            StringComparer.OrdinalIgnoreCase);

        _miningCmdTokens = data.KnownMiningCommandLineTokens
            .Select(t => t.ToLowerInvariant().Trim())
            .Where(t => t.Length > 0)
            .ToList();

        _aiScriptPatterns = data.AiScriptPatterns
            .Select(p => p.ToLowerInvariant().Trim())
            .Where(p => p.Length > 0)
            .ToList();

        // Compile trusted path patterns (glob * → regex .*)
        _trustedPathPatterns = data.TrustedExecutablePaths
            .Select(p => TryCompileGlob(ExpandEnvironmentVariables(p)))
            .Where(r => r is not null)
            .Select(r => r!)
            .ToList();
    }

    private static Regex? TryCompileGlob(string glob)
    {
        try
        {
            // Convert simple glob (only * wildcard) to regex
            var escaped = Regex.Escape(glob)
                               .Replace(@"\*", ".*");
            return new Regex(
                "^" + escaped + "$",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100));
        }
        catch
        {
            return null;
        }
    }

    private bool MatchesTrustedPath(string executablePath)
    {
        var expanded = ExpandEnvironmentVariables(executablePath);
        foreach (var pattern in _trustedPathPatterns)
        {
            try
            {
                if (pattern.IsMatch(expanded)) return true;
            }
            catch (RegexMatchTimeoutException)
            {
                // Pattern timed out — skip it and continue
            }
        }
        return false;
    }

    private static string ExpandEnvironmentVariables(string path)
    {
        // Expand both %VAR% style and common known vars
        try { return Environment.ExpandEnvironmentVariables(path); }
        catch { return path; }
    }

    private string BuildAiReason(ProcessSnapshot snap)
    {
        var signals = GetAiSignals(snap);
        return signals.Count > 0
            ? $"AI/ML workload signals: {string.Join(", ", signals)}"
            : "AI/ML workload evidence detected.";
    }

    private string ResolveAllowlistPath()
    {
        var configured = _cfg.Paths.AllowlistFile;

        if (string.IsNullOrWhiteSpace(configured))
            return "allowlist.json";

        if (Path.IsPathRooted(configured))
            return configured;

        // Relative to the service executable directory
        var baseDir = AppContext.BaseDirectory;
        return Path.Combine(baseDir, configured);
    }
}
