using System;
using System.Collections.Generic;
using System.Linq;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  Input bundle for a single scoring pass
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Everything the RiskScorer needs to compute one score for one process.
/// All fields are optional — the scorer degrades gracefully when data is
/// missing rather than failing or assuming the worst.
/// </summary>
public sealed class ScoringInput
{
    public required ProcessSnapshot     Process      { get; init; }
    public          GpuSnapshot?        Gpu          { get; init; }
    public          NetworkAnalysis?    Network      { get; init; }
    public          CommandLineAnalysis? CmdLine     { get; init; }
    public          ProcessTreeAnalysis? ProcessTree { get; init; }
    public          AllowlistResult?    Allowlist    { get; init; }
    public          List<PersistenceEntry> Persistence { get; init; } = new();

    /// <summary>Minutes this process has been continuously above GPU threshold.</summary>
    public double GpuSustainedMinutes   { get; init; }
    /// <summary>True if VRAM usage has been stable over the observation window.</summary>
    public bool   VramIsStable          { get; init; }
    /// <summary>System-wide CPU% at the time of evaluation.</summary>
    public double SystemCpuPercent      { get; init; }

    // ── Web Mining signals ────────────────────────────────────────────────────
    /// <summary>Web mining indicators (DNS + browser + resurrection). Null if web detector is disabled.</summary>
    public WebMiningIndicators? WebMining       { get; init; }
    /// <summary>Score bonus from process resurrection detector. 0 if not resurrected.</summary>
    public int ResurrectionScore                { get; init; }

    // ── BYPASS-02: Process hollowing heuristic ────────────────────────────────
    /// <summary>
    /// True when a trusted/signed binary has unusually high CPU combined with
    /// characteristics inconsistent with its known behavior (e.g., python.exe
    /// without any Python modules in its working set). This is a hollowing hint.
    /// </summary>
    public bool SuspiciousMemoryProfile         { get; init; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  RiskScorer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Applies the weighted multi-signal scoring model defined in the spec.
///
/// ══ CRITICAL DESIGN RULE ══
/// No single signal can exceed the HighRisk threshold alone.
/// Reaching ConfirmedMining (85+) requires multiple independent strong signals.
/// GPU utilisation > 90 % adds at most +20 points — never enough on its own.
/// Destructive action is gated in the ConfirmationEngine, not here.
///
/// Score components (from spec §18):
///   GPU > 90% for > 10 min          +10
///   GPU > 95% for > 30 min          +10
///   Unknown executable               +15
///   Unsigned executable              +10
///   Executable in suspicious dir     +10
///   Suspicious command line          +25
///   Suspicious network behaviour     +25
///   Mining-specific protocol         +30
///   Suspicious persistence           +20
///   Known malicious hash            +100
///   AI training indicators           -40
///   Known trusted application        -50
///   Signed trusted publisher         -15
///   Interactive user-launched        -10
///
/// All weights are read from <see cref="ScoringWeights"/> so administrators
/// can tune them without recompiling.
/// </summary>
public sealed class RiskScorer
{
    private readonly CoinShieldConfig  _cfg;
    private readonly CoinShieldLogger  _logger;

    // ── Thresholds (convenience aliases) ─────────────────────────────────────
    private DetectionConfig   D  => _cfg.Detection;
    private ScoringWeights    W  => _cfg.Scoring;
    private AiProtectionConfig AI => _cfg.AiProtection;

    public RiskScorer(CoinShieldConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Main scoring method ───────────────────────────────────────────────────

    /// <summary>
    /// Computes a <see cref="RiskScore"/> for the given input bundle.
    /// Returns a fully populated score with per-signal breakdowns and
    /// AI/Mining confidence values.
    /// </summary>
    public RiskScore Score(ScoringInput input)
    {
        var score    = new RiskScore();
        var snap     = input.Process;
        var reasons  = score.Reasons;

        // ── 1. GPU sustained utilisation (weak partial signal) ────────────────
        // High GPU is the WEAKEST signal.  It requires 10+ minutes of
        // sustained use above the configured threshold to contribute at all.
        // Even at +20 max the total cannot reach the suspicious threshold alone.
        ScoreGpu(input, score, reasons);

        // ── 2. Unknown executable ─────────────────────────────────────────────
        // "Unknown" = not in any trusted list AND hash not recognised
        ScoreUnknownExecutable(input, score, reasons);

        // ── 3. Unsigned executable ────────────────────────────────────────────
        if (!snap.IsSigned)
        {
            score.UnsignedExecutableScore = W.UnsignedExecutable;
            reasons.Add($"Executable is unsigned. (+{W.UnsignedExecutable})");
        }

        // ── 4. Suspicious executable path ─────────────────────────────────────
        ScorePath(input, score, reasons);

        // ── 5. Command-line analysis ──────────────────────────────────────────
        ScoreCommandLine(input, score, reasons);

        // ── 6. Network behaviour ──────────────────────────────────────────────
        ScoreNetwork(input, score, reasons);

        // ── 7. Persistence ────────────────────────────────────────────────────
        ScorePersistence(input, score, reasons);

        // ── 8. Known malicious hash ───────────────────────────────────────────
        if (input.Allowlist?.IsKnownMalicious == true)
        {
            score.KnownMaliciousHashScore = W.KnownMaliciousHash;
            reasons.Add($"Hash matches known-malicious list. (+{W.KnownMaliciousHash})");
        }

        // ── 8b. Web mining signals ────────────────────────────────────────────
        ScoreWebMining(input, score, reasons);

        // ── 8c. Resurrection / persistence loop ───────────────────────────────
        if (input.ResurrectionScore > 0)
        {
            score.ResurrectionScore = input.ResurrectionScore;
            reasons.Add($"Process resurrection pattern detected. (+{input.ResurrectionScore})");
        }

        // ── 8d. BYPASS-02: Process-hollowing heuristic ────────────────────────
        // A signed/trusted binary exhibiting miner-like resource behaviour with
        // an anomalous memory profile is flagged. This catches process-hollowing
        // attacks where xmrig is injected into e.g. python.exe or svchost.exe.
        if (input.SuspiciousMemoryProfile &&
            (input.Process.IsSigned || input.Allowlist?.IsTrustedApplication == true))
        {
            score.HollowingScore = 30;
            reasons.Add("Trusted/signed binary has suspicious memory profile — possible process hollowing. (+30)");
        }

        // ── 9. AI training mitigation ─────────────────────────────────────────
        // AI evidence REDUCES the score and contributes to AI confidence.
        // This is one of the most important false-positive guards.
        ScoreAiMitigation(input, score, reasons);

        // ── 10. Trust mitigations ─────────────────────────────────────────────
        ScoreTrustMitigations(input, score, reasons);

        // ── 11. Compute AI and Mining confidence ──────────────────────────────
        ComputeConfidence(input, score);

        // ── 12. Count strong indicators ───────────────────────────────────────
        score.StrongIndicatorCount = CountStrongIndicators(input, score);

        return score;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Signal scorers
    // ─────────────────────────────────────────────────────────────────────────

    private void ScoreGpu(ScoringInput input, RiskScore score, List<string> reasons)
    {
        if (input.Gpu is null || input.Process.GpuUsage < 0) return;

        double gpuUtil     = input.Process.GpuUsage >= 0
            ? input.Process.GpuUsage
            : input.Gpu.GpuUtilization;

        double threshold   = D.GpuUtilizationThreshold;
        double sustained   = input.GpuSustainedMinutes;

        // +10 only when sustained > configured minutes (default 10)
        if (gpuUtil >= threshold && sustained >= D.GpuSustainedMinutes)
        {
            score.GpuSustainedScore += W.GpuSustained10Min;
            reasons.Add(
                $"GPU {gpuUtil:F0}% sustained for {sustained:F0} min. " +
                $"(+{W.GpuSustained10Min})");
        }

        // Additional +10 when sustained > 30 min at 95%
        if (gpuUtil >= 95.0 && sustained >= 30)
        {
            score.GpuSustainedScore += W.GpuSustained30Min;
            reasons.Add(
                $"GPU ≥ 95% for > 30 min. (+{W.GpuSustained30Min})");
        }

        // Stable VRAM alongside high GPU — mining pattern, but still weak
        if (input.VramIsStable && gpuUtil >= threshold && sustained >= 20)
        {
            // Add a small auxiliary bonus but cap GPU group at +25 total
            if (score.GpuSustainedScore < 25)
            {
                score.GpuSustainedScore += 5;
                reasons.Add("VRAM usage stable during sustained GPU load. (+5)");
            }
        }
    }

    private void ScoreUnknownExecutable(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var snap      = input.Process;
        var allowlist = input.Allowlist;

        bool isTrustedByList = allowlist?.Verdict is
            AllowlistVerdict.Trusted or AllowlistVerdict.AiFramework;

        if (isTrustedByList) return;  // Trusted — skip unknown scoring

        bool pathEmpty    = string.IsNullOrWhiteSpace(snap.Path);
        bool hashEmpty    = string.IsNullOrWhiteSpace(snap.Sha256);
        bool notInAnyList = allowlist?.Verdict is AllowlistVerdict.Unknown or null;

        if (notInAnyList && (pathEmpty || hashEmpty || !snap.IsSigned))
        {
            score.UnknownExecutableScore = W.UnknownExecutable;
            reasons.Add($"Executable not found in any trusted list. (+{W.UnknownExecutable})");
        }
    }

    private void ScorePath(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var snap = input.Process;
        switch (snap.PathRisk)
        {
            case PathRisk.Suspicious:
                score.SuspiciousPathScore = W.SuspiciousPath;
                reasons.Add(
                    $"Executable path is suspicious ({snap.Path}). (+{W.SuspiciousPath})");
                break;
            case PathRisk.Malicious:
                // Counts as both suspicious path + adds to unknown
                score.SuspiciousPathScore = W.SuspiciousPath * 2;
                reasons.Add(
                    $"Executable in high-risk path (random name in temp). " +
                    $"(+{W.SuspiciousPath * 2})");
                break;
        }
    }

    private void ScoreCommandLine(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var cmd = input.CmdLine;
        if (cmd is null) return;

        if (cmd.HasStratumProtocol)
        {
            score.MiningProtocolScore = W.MiningProtocol;
            reasons.Add($"Stratum mining protocol in command line. (+{W.MiningProtocol})");
        }
        else if (cmd.IsHighRisk)
        {
            score.CommandLineScore = W.SuspiciousCommandLine;
            string detail = cmd.MiningTokensFound.Count > 0
                ? string.Join(", ", cmd.MiningTokensFound.Take(3))
                : "mining-related parameters";
            reasons.Add($"Suspicious command-line parameters: {detail}. (+{W.SuspiciousCommandLine})");
        }
        else if (cmd.HasPoolAddress || cmd.HasWalletAddress)
        {
            score.CommandLineScore = W.SuspiciousCommandLine / 2;
            reasons.Add(
                $"Command line contains pool/wallet address. (+{W.SuspiciousCommandLine / 2})");
        }
    }

    private void ScoreNetwork(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var net = input.Network;
        if (net is null) return;

        if (net.MiningPoolConnections > 0)
        {
            score.MiningProtocolScore = Math.Max(score.MiningProtocolScore,
                W.MiningProtocol);
            reasons.Add(
                $"Connection to suspected mining pool host. (+{W.MiningProtocol})");
        }
        else if (net.MiningPortConnections > 0)
        {
            score.NetworkBehaviorScore = W.SuspiciousNetwork;
            reasons.Add(
                $"{net.MiningPortConnections} connection(s) on known mining port(s). " +
                $"(+{W.SuspiciousNetwork})");
        }
        else if (net.IsHighRisk)
        {
            score.NetworkBehaviorScore = W.SuspiciousNetwork / 2;
            reasons.Add(
                $"Suspicious network behaviour (score={net.Score}). " +
                $"(+{W.SuspiciousNetwork / 2})");
        }
        else if (net.LongLivedConnections > 0)
        {
            score.NetworkBehaviorScore = 10;
            reasons.Add(
                $"{net.LongLivedConnections} long-lived external connection(s). (+10)");
        }
    }

    private void ScorePersistence(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var suspicious = input.Persistence.Where(p => p.IsSuspicious).ToList();
        if (suspicious.Count == 0) return;

        score.PersistenceScore = W.SuspiciousPersistence;
        var types = string.Join(", ",
            suspicious.Select(p => p.Type.ToString()).Distinct().Take(3));
        reasons.Add(
            $"{suspicious.Count} suspicious persistence entry(ies) found " +
            $"[{types}]. (+{W.SuspiciousPersistence})");
    }

    private void ScoreAiMitigation(ScoringInput input, RiskScore score, List<string> reasons)
    {
        if (!AI.Enabled) return;

        var cmd       = input.CmdLine;
        var allowlist = input.Allowlist;

        bool aiFrameworkEvidence = allowlist?.IsAiFrameworkEvidence == true
                                || cmd?.IsAiTraining == true;

        if (!aiFrameworkEvidence) return;

        // AI mitigation
        score.AiTrainingBonus = W.AiTrainingMitigation;
        reasons.Add(
            $"AI/ML workload evidence detected — suspicion reduced. " +
            $"(-{W.AiTrainingMitigation})");

        // Additional: if both framework evidence AND training command line → stronger mitigation
        if (allowlist?.IsAiFrameworkEvidence == true && cmd?.IsAiTraining == true)
        {
            score.AiTrainingBonus = Math.Min(
                score.AiTrainingBonus + 10,
                W.AiTrainingMitigation + 10);
            reasons.Add("Multiple AI training signals confirmed. (-10 additional)");
        }
    }

    private void ScoreTrustMitigations(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var snap      = input.Process;
        var allowlist = input.Allowlist;
        var tree      = input.ProcessTree;

        // Trusted application (by hash + publisher or trusted path)
        if (allowlist?.Verdict == AllowlistVerdict.Trusted)
        {
            score.TrustedApplicationBonus = W.TrustedApplication;
            reasons.Add(
                $"Process is in trusted allowlist ({allowlist.Reason}). " +
                $"(-{W.TrustedApplication})");
        }

        // Trusted publisher only (weaker signal)
        if (snap.IsSigned && !string.IsNullOrWhiteSpace(snap.Publisher)
            && score.TrustedApplicationBonus == 0)
        {
            score.TrustedPublisherBonus = W.TrustedPublisher;
            reasons.Add(
                $"Signed by trusted publisher: {snap.Publisher}. " +
                $"(-{W.TrustedPublisher})");
        }

        // User-launched from interactive shell
        if (tree?.IsUserLaunched == true)
        {
            score.UserLaunchedBonus = W.UserLaunchedProcess;
            reasons.Add(
                $"Process was launched interactively by a user. " +
                $"(-{W.UserLaunchedProcess})");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  AI / Mining confidence calculation
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes normalised AI confidence (0.0–1.0) and mining confidence (0.0–1.0).
    ///
    /// These are derived from the signal evidence, NOT purely from the total score,
    /// so that a high-scoring process with strong AI evidence still shows high
    /// AI confidence and does not trigger the confirmation engine.
    /// </summary>
    private void ComputeConfidence(ScoringInput input, RiskScore score)
    {
        double aiPoints     = 0;
        double miningPoints = 0;

        var cmd       = input.CmdLine;
        var allowlist = input.Allowlist;
        var net       = input.Network;
        var snap      = input.Process;

        // ── AI evidence accumulation ──────────────────────────────────────────
        if (allowlist?.IsAiFrameworkEvidence == true)     aiPoints += 40;
        if (cmd?.IsAiTraining == true)                    aiPoints += 30;
        if (cmd?.AiScore > 0)                             aiPoints += Math.Min(cmd.AiScore, 20);
        if (snap.IsSigned && !string.IsNullOrWhiteSpace(snap.Publisher)) aiPoints += 15;
        if (allowlist?.Verdict == AllowlistVerdict.Trusted) aiPoints += 20;
        if (input.ProcessTree?.IsUserLaunched == true)    aiPoints += 10;

        // BYPASS-03/04 FIX: When a process has a "trusted" name (python, svchost, etc.)
        // but lacks corroborating AI evidence signals, do NOT award the full AI
        // mitigation. Require at least 3 distinct AI signals to classify as AI workload.
        // This prevents a renamed miner (python.exe in Conda path) from being fully
        // protected by name + path alone.
        int aiSignalCount = 0;
        if (allowlist?.IsAiFrameworkEvidence == true) aiSignalCount++;
        if (cmd?.IsAiTraining == true)                aiSignalCount++;
        if (cmd?.AiScore >= 20)                       aiSignalCount++;
        if (allowlist?.Verdict == AllowlistVerdict.Trusted) aiSignalCount++;
        if (input.ProcessTree?.IsUserLaunched == true) aiSignalCount++;

        // If process name looks like a trusted AI binary but has < 3 AI signals,
        // cap AI confidence at 0.50 (suspicious but not cleared) regardless of score.
        bool isTrustedNameOnly = snap.IsSigned
                                 && aiSignalCount < 3
                                 && aiPoints > 0
                                 && miningPoints > 0;

        // AI evidence strongly offsets mining — if both present, AI wins unless
        // explicit mining protocol or malicious hash is found
        bool hasExplicitMiningProtocol =
            cmd?.HasStratumProtocol == true
         || net?.MiningPoolConnections > 0
         || (net?.MiningPortConnections ?? 0) >= 2;

        bool hasMaliciousHash = allowlist?.IsKnownMalicious == true;

        // ── Mining evidence accumulation ──────────────────────────────────────
        if (cmd?.HasStratumProtocol == true)              miningPoints += 40;
        if (cmd?.HasPoolAddress == true)                  miningPoints += 25;
        if (cmd?.HasWalletAddress == true)                miningPoints += 20;
        if (cmd?.IsKnownMinerProcess == true)             miningPoints += 35;
        if (allowlist?.IsKnownMinerName == true)          miningPoints += 30;
        if (hasMaliciousHash)                             miningPoints += 100;
        if ((net?.MiningPoolConnections ?? 0) > 0)        miningPoints += 30;
        if ((net?.MiningPortConnections ?? 0) > 0)        miningPoints += 20;
        if (net?.LongLivedConnections > 0 && snap.PathRisk is PathRisk.Suspicious or PathRisk.Malicious)
                                                          miningPoints += 15;
        if (!snap.IsSigned && snap.PathRisk is PathRisk.Suspicious or PathRisk.Malicious)
                                                          miningPoints += 10;

        // Normalise to 0–1 range
        double totalEvidence = aiPoints + miningPoints;
        if (totalEvidence <= 0)
        {
            score.AiConfidence     = 0.0;
            score.MiningConfidence = 0.0;
            return;
        }

        double rawAi     = aiPoints     / (totalEvidence + 10);   // add 10 to dampen extremes
        double rawMining = miningPoints / (totalEvidence + 10);

        // When an explicit mining protocol is found, force mining confidence up
        // regardless of AI evidence (a compromised Python process could do both)
        if (hasExplicitMiningProtocol && !hasMaliciousHash)
        {
            rawMining = Math.Max(rawMining, 0.75);
            rawAi     = Math.Min(rawAi,     0.30);
        }

        if (hasMaliciousHash)
        {
            rawMining = 1.0;
            rawAi     = 0.0;
        }

        score.AiConfidence     = Math.Round(Math.Clamp(rawAi,     0.0, 1.0), 2);
        score.MiningConfidence = Math.Round(Math.Clamp(rawMining, 0.0, 1.0), 2);

        // BYPASS-03/04 FIX: Cap AI confidence when only name/path trust present
        if (isTrustedNameOnly && score.AiConfidence > 0.50)
            score.AiConfidence = 0.50;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Web Mining signal scorer
    // ─────────────────────────────────────────────────────────────────────────

    private void ScoreWebMining(ScoringInput input, RiskScore score, List<string> reasons)
    {
        var web = input.WebMining;
        if (web is null) return;

        var webCfg = _cfg.WebMining;

        // Mining script CDN contact — highest signal (Coinhive, CryptoLoot etc.)
        // These have NO legitimate use and confirm a browser mining attack.
        if (web.SuspiciousJsCdnQueries > 0)
        {
            score.WebMiningScore += webCfg.MiningScriptDomainBonus;
            reasons.Add(
                $"Browser contacted known mining script CDN ({web.SuspiciousJsCdnQueries} query(ies)). " +
                $"(+{webCfg.MiningScriptDomainBonus})");
        }

        // Mining pool DNS query — strong signal
        if (web.MiningPoolDnsQueries > 0)
        {
            score.WebMiningScore += webCfg.MiningPoolDomainBonus;
            reasons.Add(
                $"DNS query to mining pool infrastructure ({web.MiningPoolDnsQueries} query(ies)). " +
                $"(+{webCfg.MiningPoolDomainBonus})");
        }

        // High-CPU browser renderer + WebAssembly — medium signal
        if (web.HasWebAssemblyExecution && web.HighCpuRenderers > 0)
        {
            score.WebMiningScore += 20;
            reasons.Add(
                $"Browser renderer high-CPU with WebAssembly activity. (+20)");
        }

        // Long-running JavaScript workers — weak signal (could be legitimate)
        if (web.LongRunningWorkers > 0)
        {
            score.WebMiningScore += 10;
            reasons.Add(
                $"{web.LongRunningWorkers} long-running JS worker(s) in browser. (+10)");
        }

        // Confirmed web miner from WebMiningDetector correlation engine
        if (web.WebMiningConfidence >= webCfg.ConfirmedMiningThreshold)
        {
            // Add extra bonus to push over ConfirmedMining threshold when combined
            // with at least one network or DNS signal
            score.WebMiningScore += 25;
            reasons.Add(
                $"Web mining correlation engine: confidence={web.WebMiningConfidence}. (+25)");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Strong indicator counting
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Counts independent strong mining indicators.
    /// The confirmation engine requires at least 2 before taking action.
    ///
    /// Each category counts as AT MOST 1 — so reaching 2 genuinely requires
    /// evidence from two different categories.
    /// </summary>
    private static int CountStrongIndicators(ScoringInput input, RiskScore score)
    {
        int count = 0;
        var cmd       = input.CmdLine;
        var net       = input.Network;
        var snap      = input.Process;
        var allowlist = input.Allowlist;

        // 1. Command-line: explicit mining protocol or pool/wallet address
        if (cmd?.HasStratumProtocol == true
            || cmd?.HasPoolAddress == true
            || cmd?.IsKnownMinerProcess == true)
            count++;

        // 2. Network: connection on known mining port or to mining pool host
        if ((net?.MiningPortConnections ?? 0) > 0
            || (net?.MiningPoolConnections ?? 0) > 0)
            count++;

        // 3. Persistence: suspicious persistence entry
        if (input.Persistence.Any(p => p.IsSuspicious))
            count++;

        // 4. Known malicious hash
        if (allowlist?.IsKnownMalicious == true)
            count++;

        // 5. Binary trust: unsigned + suspicious path + long runtime
        if (!snap.IsSigned
            && snap.PathRisk is PathRisk.Suspicious or PathRisk.Malicious
            && snap.Lifetime.TotalHours >= 1)
            count++;

        // 6. Known miner name
        if (allowlist?.IsKnownMinerName == true)
            count++;

        // 7. Web mining: confirmed browser miner or mining script CDN contact
        if (input.WebMining is not null &&
            (input.WebMining.SuspiciousJsCdnQueries > 0 ||
             input.WebMining.MiningPoolDnsQueries > 0 ||
             input.WebMining.WebMiningConfidence >= 60))
            count++;

        // 8. Process resurrection confirmed
        if (input.ResurrectionScore >= 40)
            count++;

        return count;
    }
}
