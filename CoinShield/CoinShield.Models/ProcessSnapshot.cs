using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>
/// A point-in-time snapshot of a monitored process and all observable attributes
/// used by the detection engine for scoring.
/// </summary>
public sealed class ProcessSnapshot
{
    // ── Identity ──────────────────────────────────────────────────────────────
    public int    Pid          { get; set; }
    public string Name         { get; set; } = string.Empty;
    public string Path         { get; set; } = string.Empty;
    public string CommandLine  { get; set; } = string.Empty;

    // ── Lineage ───────────────────────────────────────────────────────────────
    public int    ParentPid          { get; set; }
    public string ParentName         { get; set; } = string.Empty;
    public string ParentPath         { get; set; } = string.Empty;
    public string GrandparentName    { get; set; } = string.Empty;
    public List<int> ChildPids       { get; set; } = new();

    // ── Ownership ─────────────────────────────────────────────────────────────
    public string Username { get; set; } = string.Empty;

    // ── Resource usage ────────────────────────────────────────────────────────
    /// <summary>CPU utilisation 0–100 %.</summary>
    public double CpuPercent  { get; set; }
    /// <summary>Working-set RAM in megabytes.</summary>
    public double MemoryMb    { get; set; }

    // ── Lifetime ──────────────────────────────────────────────────────────────
    public DateTime StartTime { get; set; }
    public TimeSpan Lifetime  => DateTime.UtcNow - StartTime;

    // ── Trust signals ─────────────────────────────────────────────────────────
    public bool   IsSigned    { get; set; }
    public string Publisher   { get; set; } = string.Empty;
    public string Sha256      { get; set; } = string.Empty;

    // ── GPU correlation ───────────────────────────────────────────────────────
    /// <summary>GPU utilisation attributed to this process (0–100), or -1 if unknown.</summary>
    public double GpuUsage    { get; set; } = -1;
    /// <summary>VRAM used by this process in MB, or -1 if unknown.</summary>
    public double VramUsageMb { get; set; } = -1;

    // ── Network ───────────────────────────────────────────────────────────────
    public int NetworkConnectionCount { get; set; }

    // ── Computed path classification ──────────────────────────────────────────
    public PathRisk PathRisk     { get; set; } = PathRisk.Unknown;
    public bool     IsInTempDir  { get; set; }
    public bool     IsInAppData  { get; set; }
    public bool     IsSystemPath { get; set; }

    // ── Metadata ──────────────────────────────────────────────────────────────
    public DateTime SnapshotTime { get; set; } = DateTime.UtcNow;
}

/// <summary>Rough classification of the executable's filesystem location.</summary>
public enum PathRisk
{
    Unknown,
    /// <summary>Well-known system directory (System32, Program Files, etc.).</summary>
    SystemTrusted,
    /// <summary>Known developer / user application path (e.g. AppData\Local\Programs).</summary>
    UserTrusted,
    /// <summary>Writable/temp user directory.</summary>
    Suspicious,
    /// <summary>Explicitly flagged malicious location.</summary>
    Malicious
}
