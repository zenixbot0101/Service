using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>
/// The weighted multi-signal risk score for a single process at one evaluation cycle.
/// Each contributing signal is recorded so results are fully explainable.
/// </summary>
public sealed class RiskScore
{
    // ── Raw components (additive) ─────────────────────────────────────────────
    public int GpuSustainedScore         { get; set; }   // +10 / +10
    public int UnknownExecutableScore    { get; set; }   // +15
    public int UnsignedExecutableScore   { get; set; }   // +10
    public int SuspiciousPathScore       { get; set; }   // +10
    public int CommandLineScore          { get; set; }   // +25
    public int NetworkBehaviorScore      { get; set; }   // +25
    public int MiningProtocolScore       { get; set; }   // +30
    public int PersistenceScore          { get; set; }   // +20
    public int KnownMaliciousHashScore   { get; set; }   // +100
    public int WebMiningScore            { get; set; }   // +0..+120 (DNS+browser+WASM)
    public int ResurrectionScore         { get; set; }   // +0..+80  (A→B→A patterns)
    public int HollowingScore            { get; set; }   // +0..+30  (BYPASS-02: hollowing heuristic)

    // ── Mitigating components (subtractive) ───────────────────────────────────
    public int AiTrainingBonus           { get; set; }   // -40
    public int TrustedApplicationBonus  { get; set; }   // -50
    public int TrustedPublisherBonus     { get; set; }   // -15
    public int UserLaunchedBonus         { get; set; }   // -10

    // ── Total ─────────────────────────────────────────────────────────────────
    /// <summary>Clamped to [0, ∞).  Negative scores resolve to 0 (process is safe).</summary>
    public int Total =>
        Math.Max(0,
            GpuSustainedScore
          + UnknownExecutableScore
          + UnsignedExecutableScore
          + SuspiciousPathScore
          + CommandLineScore
          + NetworkBehaviorScore
          + MiningProtocolScore
          + PersistenceScore
          + KnownMaliciousHashScore
          + WebMiningScore
          + ResurrectionScore
          + HollowingScore
          - AiTrainingBonus
          - TrustedApplicationBonus
          - TrustedPublisherBonus
          - UserLaunchedBonus);

    // ── AI / Mining confidence ────────────────────────────────────────────────
    /// <summary>0.0–1.0 probability that this workload is legitimate AI/ML.</summary>
    public double AiConfidence      { get; set; }
    /// <summary>0.0–1.0 probability that this workload is a cryptominer.</summary>
    public double MiningConfidence  { get; set; }

    // ── Strong indicator count ────────────────────────────────────────────────
    /// <summary>
    /// Number of independent strong mining signals present.
    /// A minimum count is required before any destructive action.
    /// </summary>
    public int StrongIndicatorCount { get; set; }

    /// <summary>Human-readable explanations for each contributing signal.</summary>
    public List<string> Reasons { get; set; } = new();

    // ── Derived risk level ────────────────────────────────────────────────────
    public RiskLevel Level => Total switch
    {
        < 30  => RiskLevel.Safe,
        < 60  => RiskLevel.Suspicious,
        < 85  => RiskLevel.HighRisk,
        _     => RiskLevel.ConfirmedMining,
    };

    public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>Four-tier risk classification used throughout the detection pipeline.</summary>
public enum RiskLevel
{
    /// <summary>Score 0–29.  No action.</summary>
    Safe           = 0,
    /// <summary>Score 30–59.  Increase monitoring, collect telemetry.</summary>
    Suspicious     = 1,
    /// <summary>Score 60–84.  Deep analysis, re-evaluate AI classification.</summary>
    HighRisk       = 2,
    /// <summary>Score 85+.  Subject to confirmation engine before any response.</summary>
    ConfirmedMining = 3,
}
