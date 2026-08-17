using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>All states a process can be in as it moves through the detection pipeline.</summary>
public enum DetectionState
{
    /// <summary>Baseline — process is not raising suspicion.</summary>
    Normal,
    /// <summary>Initial signals detected; monitoring increased.</summary>
    Suspicious,
    /// <summary>Deep analysis in progress; evidence being collected.</summary>
    Analyzing,
    /// <summary>Classified as a legitimate AI/ML workload.</summary>
    AiWorkload,
    /// <summary>Strong risk signals; confirmation window running.</summary>
    HighRisk,
    /// <summary>Confirmation window completed and all criteria met.</summary>
    ConfirmedMining,
    /// <summary>Response has been executed (process terminated / shutdown initiated).</summary>
    ActionTaken,
}

/// <summary>
/// The full result produced by one evaluation pass of the detection engine
/// for a single process.
/// </summary>
public sealed class DetectionResult
{
    // ── Subject ───────────────────────────────────────────────────────────────
    public int    Pid         { get; init; }
    public string ProcessName { get; init; } = string.Empty;

    // ── Scores ────────────────────────────────────────────────────────────────
    public RiskScore Score    { get; init; } = new();

    // ── State machine ─────────────────────────────────────────────────────────
    public DetectionState State          { get; set; } = DetectionState.Normal;
    public DetectionState PreviousState  { get; set; } = DetectionState.Normal;

    // ── Confirmation tracking ─────────────────────────────────────────────────
    /// <summary>When this process first entered Suspicious or higher.</summary>
    public DateTime? SuspicionStartTime  { get; set; }
    /// <summary>True once the configured confirmation window has elapsed.</summary>
    public bool ConfirmationWindowPassed { get; set; }

    // ── Evidence ──────────────────────────────────────────────────────────────
    /// <summary>Ordered list of evidence items that led to this result.</summary>
    public List<string> Evidence  { get; init; } = new();

    /// <summary>Network connections that contributed to the score.</summary>
    public List<NetworkConnectionInfo> SuspiciousConnections { get; init; } = new();

    /// <summary>Persistence entries found for this process.</summary>
    public List<string> PersistenceEntries { get; init; } = new();

    // ── Snapshot references ───────────────────────────────────────────────────
    public ProcessSnapshot?  ProcessSnapshot  { get; set; }
    public GpuSnapshot?      GpuSnapshot      { get; set; }

    // ── Metadata ──────────────────────────────────────────────────────────────
    public DateTime EvaluatedAt { get; init; } = DateTime.UtcNow;

    // ── Convenience ───────────────────────────────────────────────────────────
    public bool IsActionable =>
        State == DetectionState.ConfirmedMining && ConfirmationWindowPassed;
}

/// <summary>
/// Serialisable incident evidence bundle written to disk before any response action.
/// File name: incident-YYYYMMDD-HHmmss.json
/// </summary>
public sealed class IncidentEvidence
{
    public string IncidentId  { get; init; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    public ProcessInfo  Process { get; init; } = new();
    public SystemInfo   System  { get; init; } = new();

    public List<NetworkConnectionInfo> Network { get; init; } = new();
    public List<string> PersistenceEntries     { get; init; } = new();

    public ScoreInfo  Scores   { get; init; } = new();
    public string     Decision { get; init; } = string.Empty;
    public string     Action   { get; init; } = string.Empty;

    public List<string> Evidence { get; init; } = new();

    public sealed class ProcessInfo
    {
        public int    Pid          { get; init; }
        public string Name         { get; init; } = string.Empty;
        public string Path         { get; init; } = string.Empty;
        public string CommandLine  { get; init; } = string.Empty;
        public string Parent       { get; init; } = string.Empty;
        public string Sha256       { get; init; } = string.Empty;
        public string Publisher    { get; init; } = string.Empty;
        public string Username     { get; init; } = string.Empty;
        public double LifetimeMinutes { get; init; }
    }

    public sealed class SystemInfo
    {
        public double CpuPercent   { get; init; }
        public double GpuPercent   { get; init; }
        public double VramPercent  { get; init; }
        public double MemoryMb     { get; init; }
    }

    public sealed class ScoreInfo
    {
        public int    MiningScore    { get; init; }
        public double AiConfidence   { get; init; }
        public int    StrongIndicators { get; init; }
        public string RiskLevel      { get; init; } = string.Empty;
    }
}
