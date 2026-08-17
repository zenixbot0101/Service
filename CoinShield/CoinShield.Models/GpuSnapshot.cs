using System;
using System.Collections.Generic;

namespace CoinShield.Models;

/// <summary>
/// System-wide GPU telemetry captured at a single point in time.
/// Multiple adapters are represented as separate snapshots in the list returned
/// by GpuAnalyzer.
/// </summary>
public sealed class GpuSnapshot
{
    // ── Adapter identity ──────────────────────────────────────────────────────
    public int    AdapterIndex { get; set; }
    public string AdapterName  { get; set; } = string.Empty;

    // ── Utilisation ───────────────────────────────────────────────────────────
    /// <summary>Overall GPU engine utilisation 0–100 %.</summary>
    public double GpuUtilization  { get; set; } = -1;
    /// <summary>Video-decode engine utilisation 0–100 %, or -1 if unavailable.</summary>
    public double DecodeUtilization { get; set; } = -1;
    /// <summary>Video-encode engine utilisation 0–100 %, or -1 if unavailable.</summary>
    public double EncodeUtilization { get; set; } = -1;
    /// <summary>Compute / CUDA engine utilisation 0–100 %, or -1 if unavailable.</summary>
    public double ComputeUtilization { get; set; } = -1;

    // ── Memory ────────────────────────────────────────────────────────────────
    /// <summary>Total VRAM in MB.</summary>
    public double VramTotalMb   { get; set; }
    /// <summary>VRAM currently in use across all processes, in MB.</summary>
    public double VramUsedMb    { get; set; }
    /// <summary>VRAM utilisation 0–100 %.</summary>
    public double VramPercent   => VramTotalMb > 0 ? (VramUsedMb / VramTotalMb) * 100.0 : -1;

    // ── Per-process attribution ───────────────────────────────────────────────
    /// <summary>Map of PID → estimated GPU utilisation % for processes using this adapter.</summary>
    public Dictionary<int, double> ProcessGpuUsage  { get; set; } = new();
    /// <summary>Map of PID → VRAM usage in MB for processes using this adapter.</summary>
    public Dictionary<int, double> ProcessVramUsage { get; set; } = new();

    // ── CUDA ──────────────────────────────────────────────────────────────────
    public bool   CudaAvailable { get; set; }
    /// <summary>Number of CUDA-active processes detected.</summary>
    public int    CudaActiveProcessCount { get; set; }

    // ── Metadata ──────────────────────────────────────────────────────────────
    public DateTime SnapshotTime { get; set; } = DateTime.UtcNow;

    // ── Derived helpers ───────────────────────────────────────────────────────
    /// <summary>True when GPU utilisation is sustained above a threshold for scoring use only —
    /// never use this alone as a shutdown trigger.</summary>
    public bool IsHighUtilization(double threshold = 90.0) =>
        GpuUtilization >= threshold;

    public bool IsHighVram(double threshold = 85.0) =>
        VramPercent >= threshold;
}
