using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  GPU history entry
// ─────────────────────────────────────────────────────────────────────────────

internal sealed class GpuSample
{
    public DateTime Timestamp      { get; init; }
    public double   GpuUtilization { get; init; }
    public double   VramPercent    { get; init; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  GpuAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Collects GPU utilisation and VRAM statistics using Windows Performance
/// Counters (GPU Engine / GPU Adapter Memory counters available on
/// Windows 10 1709+ via the WDDM 2.0 driver model) with a WMI fallback
/// for systems where the newer counters are unavailable.
///
/// IMPORTANT DESIGN PRINCIPLE:
/// High GPU utilisation is NOT treated as evidence of mining by this class.
/// Raw numbers are forwarded to the RiskScorer, which correlates GPU data
/// with all other signals before computing a score.  GPU alone can NEVER
/// trigger any destructive action.
///
/// Per-process GPU attribution is performed by correlating the
/// "GPU Engine" performance counter process names with the live process list.
/// </summary>
public sealed class GpuAnalyzer : IDisposable
{
    // ── Dependencies ──────────────────────────────────────────────────────────
    private readonly MonitoringConfig _cfg;
    private readonly CoinShieldLogger _logger;

    // ── Performance counter state ─────────────────────────────────────────────
    // System-wide 3D/Compute engine counters: adapter index → counter
    private readonly Dictionary<int, PerformanceCounter> _gpuEngineCounters  = new();
    private readonly Dictionary<int, PerformanceCounter> _vramUsedCounters   = new();
    private readonly Dictionary<int, PerformanceCounter> _vramTotalCounters  = new();

    // Per-process GPU engine counters: "pid_engineType" → counter
    // We collect all "GPU Engine" counter instances and group by PID
    private PerformanceCounterCategory? _gpuEngineCategory;
    private bool                         _countersInitialised;
    private bool                         _useWmiFallback;

    // ── History ───────────────────────────────────────────────────────────────
    // Rolling history per adapter index (capped at MaxSamples)
    private readonly ConcurrentDictionary<int, Queue<GpuSample>> _history = new();
    private const int MaxSamples = 180;  // 3 minutes at 1 s interval

    // ── Last snapshot cache ───────────────────────────────────────────────────
    private List<GpuSnapshot> _lastSnapshots = new();

    private bool _disposed;

    // ── Construction ─────────────────────────────────────────────────────────

    public GpuAnalyzer(MonitoringConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        TryInitCounters();
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    private void TryInitCounters()
    {
        // Windows 10 1709+ exposes "GPU Engine" and "GPU Adapter Memory" categories
        try
        {
            if (PerformanceCounterCategory.Exists("GPU Engine"))
            {
                _gpuEngineCategory   = new PerformanceCounterCategory("GPU Engine");
                _countersInitialised = true;
                _logger.Debug("GpuAnalyzer", "GPU Engine performance counters available.");
            }

            // Try "GPU Adapter Memory" for VRAM
            if (PerformanceCounterCategory.Exists("GPU Adapter Memory"))
            {
                TryAddAdapterMemoryCounters();
            }

            if (!_countersInitialised)
            {
                _logger.Info("GpuAnalyzer",
                    "GPU Engine perf counters not found. Falling back to WMI.");
                _useWmiFallback = true;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("GpuAnalyzer",
                $"GPU counter initialisation failed: {ex.Message}. Using WMI fallback.");
            _useWmiFallback = true;
        }
    }

    private void TryAddAdapterMemoryCounters()
    {
        try
        {
            var cat       = new PerformanceCounterCategory("GPU Adapter Memory");
            var instances = cat.GetInstanceNames();

            // Instances are named like "luid_0x00000000_0x0000XXXX_phys_0"
            int adapterIdx = 0;
            foreach (var inst in instances.Where(i => i.Contains("_phys_")))
            {
                _vramUsedCounters[adapterIdx]  = new PerformanceCounter(
                    "GPU Adapter Memory", "Dedicated Usage", inst, readOnly: true);
                _vramTotalCounters[adapterIdx] = new PerformanceCounter(
                    "GPU Adapter Memory", "Total Committed", inst, readOnly: true);

                // Prime
                _ = _vramUsedCounters[adapterIdx].NextValue();
                _ = _vramTotalCounters[adapterIdx].NextValue();
                adapterIdx++;
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("GpuAnalyzer", $"VRAM counter init failed: {ex.Message}");
        }
    }

    // ── Main sample method ────────────────────────────────────────────────────

    /// <summary>
    /// Samples all available GPU adapters and returns a list of
    /// <see cref="GpuSnapshot"/> — one per physical adapter.
    /// Returns empty list if no GPU telemetry is available.
    /// </summary>
    public List<GpuSnapshot> Sample()
    {
        var snapshots = _countersInitialised
            ? SampleViaPerformanceCounters()
            : _useWmiFallback
                ? SampleViaWmi()
                : new List<GpuSnapshot>();

        // Record history
        foreach (var snap in snapshots)
            RecordHistory(snap);

        _lastSnapshots = snapshots;
        return snapshots;
    }

    /// <summary>Returns the most recent snapshots without issuing a new sample.</summary>
    public IReadOnlyList<GpuSnapshot> LastSnapshots => _lastSnapshots.AsReadOnly();

    // ── Performance counter path ──────────────────────────────────────────────

    private List<GpuSnapshot> SampleViaPerformanceCounters()
    {
        var snapshots = new List<GpuSnapshot>();

        try
        {
            if (_gpuEngineCategory is null) return snapshots;

            var instances = _gpuEngineCategory.GetInstanceNames();

            var adapterUtil    = new Dictionary<int, double>();
            var adapterPidUtil = new Dictionary<int, Dictionary<int, double>>();
            var adapterPidVram = new Dictionary<int, Dictionary<int, double>>();
            var adapterNames   = new Dictionary<int, string>();

            // BUG-09 FIX: Collect all relevant instances and their counters first,
            // prime them ALL, sleep ONCE, then read them all.
            // Old code: new counter + sleep(16ms) inside the foreach = O(N * 16ms) blocked time.
            var counterBatch = new List<(int adapterIdx, int pid, PerformanceCounter counter)>();

            foreach (var inst in instances)
            {
                if (!inst.Contains("engtype_3D",          StringComparison.OrdinalIgnoreCase) &&
                    !inst.Contains("engtype_Compute",      StringComparison.OrdinalIgnoreCase) &&
                    !inst.Contains("engtype_VideoDecode",  StringComparison.OrdinalIgnoreCase))
                    continue;

                int pid        = ExtractPidFromInstance(inst);
                int adapterIdx = ExtractAdapterIndex(inst);

                if (!adapterUtil.ContainsKey(adapterIdx))
                {
                    adapterUtil[adapterIdx]    = 0;
                    adapterPidUtil[adapterIdx] = new Dictionary<int, double>();
                    adapterPidVram[adapterIdx] = new Dictionary<int, double>();
                    adapterNames[adapterIdx]   = $"GPU {adapterIdx}";
                }

                try
                {
                    var counter = new PerformanceCounter(
                        "GPU Engine", "Utilization Percentage", inst, readOnly: true);
                    _ = counter.NextValue(); // prime (does NOT block)
                    counterBatch.Add((adapterIdx, pid, counter));
                }
                catch
                {
                    // Counter unavailable — skip
                }
            }

            // Single sleep after all counters are primed
            if (counterBatch.Count > 0)
                System.Threading.Thread.Sleep(50);

            // Read all primed counters
            foreach (var (adapterIdx, pid, counter) in counterBatch)
            {
                try
                {
                    double util = Math.Min(100.0, counter.NextValue());
                    adapterUtil[adapterIdx] = Math.Max(adapterUtil[adapterIdx], util);

                    if (pid > 0)
                    {
                        if (!adapterPidUtil[adapterIdx].ContainsKey(pid))
                            adapterPidUtil[adapterIdx][pid] = 0;
                        adapterPidUtil[adapterIdx][pid] =
                            Math.Max(adapterPidUtil[adapterIdx][pid], util);
                    }
                }
                catch { }
                finally
                {
                    counter.Dispose();
                }
            }

            // Build snapshots
            foreach (var adapterIdx in adapterUtil.Keys)
            {
                double vramUsed  = 0;
                double vramTotal = 0;

                if (_vramUsedCounters.TryGetValue(adapterIdx, out var usedCtr))
                    try { vramUsed  = usedCtr.NextValue()  / (1024.0 * 1024.0); } catch { }
                if (_vramTotalCounters.TryGetValue(adapterIdx, out var totalCtr))
                    try { vramTotal = totalCtr.NextValue() / (1024.0 * 1024.0); } catch { }

                var snap = new GpuSnapshot
                {
                    AdapterIndex   = adapterIdx,
                    AdapterName    = adapterNames.GetValueOrDefault(adapterIdx, $"GPU {adapterIdx}"),
                    GpuUtilization = adapterUtil[adapterIdx],
                    VramUsedMb     = vramUsed,
                    VramTotalMb    = vramTotal,
                    SnapshotTime   = DateTime.UtcNow,
                };

                if (adapterPidUtil.TryGetValue(adapterIdx, out var pidUtil))
                    foreach (var kv in pidUtil)
                        snap.ProcessGpuUsage[kv.Key] = kv.Value;

                snapshots.Add(snap);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("GpuAnalyzer", $"Performance counter GPU sample failed: {ex.Message}");
        }

        return snapshots;
    }

    // ── WMI fallback ──────────────────────────────────────────────────────────

    private List<GpuSnapshot> SampleViaWmi()
    {
        var snapshots = new List<GpuSnapshot>();

        try
        {
            // Win32_VideoController gives model name and VRAM size
            // It does NOT give live utilisation — that requires perf counters.
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_VideoController");

            int adapterIdx = 0;
            foreach (ManagementObject obj in searcher.Get())
            {
                var name      = obj["Name"]?.ToString() ?? $"GPU {adapterIdx}";
                var vramBytes = Convert.ToDouble(obj["AdapterRAM"] ?? 0);

                var snap = new GpuSnapshot
                {
                    AdapterIndex   = adapterIdx,
                    AdapterName    = name,
                    // WMI cannot provide live utilisation — mark as unavailable
                    GpuUtilization = -1,
                    VramTotalMb    = vramBytes / (1024.0 * 1024.0),
                    VramUsedMb     = -1,
                    SnapshotTime   = DateTime.UtcNow,
                };

                snapshots.Add(snap);
                adapterIdx++;
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("GpuAnalyzer", $"WMI GPU sample failed: {ex.Message}");
        }

        return snapshots;
    }

    // ── History & sustained-use helpers ──────────────────────────────────────

    /// <summary>
    /// Returns the average GPU utilisation for the given adapter over the
    /// last <paramref name="minutes"/> minutes, or -1 if insufficient data.
    /// </summary>
    public double AverageGpuUtilization(int adapterIndex = 0, int minutes = 10)
    {
        if (!_history.TryGetValue(adapterIndex, out var q)) return -1;
        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        lock (q)
        {
            var recent = q.Where(s => s.Timestamp >= cutoff).ToList();
            return recent.Count < 3 ? -1 : recent.Average(s => s.GpuUtilization);
        }
    }

    /// <summary>
    /// True if the adapter has been above <paramref name="threshold"/>% for
    /// at least <paramref name="minutes"/> continuous minutes.
    ///
    /// This is one PARTIAL signal used by the RiskScorer, not a decision point.
    /// </summary>
    public bool IsSustainedHighUtilization(
        int adapterIndex = 0,
        double threshold = 90.0,
        int minutes      = 10)
    {
        if (!_history.TryGetValue(adapterIndex, out var q)) return false;
        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        lock (q)
        {
            var window = q.Where(s => s.Timestamp >= cutoff).ToList();
            if (window.Count < 5) return false;
            // Require 85% of samples in window to exceed threshold
            double highCount = window.Count(s => s.GpuUtilization >= threshold);
            return highCount / window.Count >= 0.85;
        }
    }

    /// <summary>
    /// Returns how many minutes the adapter has been sustained above threshold.
    /// Returns 0 if not sustained.
    /// </summary>
    public double SustainedMinutes(
        int adapterIndex = 0,
        double threshold = 90.0)
    {
        if (!_history.TryGetValue(adapterIndex, out var q)) return 0;
        lock (q)
        {
            // Walk backwards through history to find the earliest contiguous
            // block where utilisation was above threshold
            var ordered = q.OrderByDescending(s => s.Timestamp).ToList();
            if (ordered.Count == 0) return 0;

            DateTime? windowStart = null;
            foreach (var sample in ordered)
            {
                if (sample.GpuUtilization >= threshold)
                    windowStart = sample.Timestamp;
                else
                    break;  // contiguous block broken
            }

            return windowStart.HasValue
                ? (DateTime.UtcNow - windowStart.Value).TotalMinutes
                : 0;
        }
    }

    /// <summary>
    /// Returns the GPU utilisation attributed to a specific PID across all
    /// known adapters, taking the maximum value.  Returns -1 if unavailable.
    /// </summary>
    public double GetProcessGpuUsage(int pid)
    {
        double max = -1;
        foreach (var snap in _lastSnapshots)
        {
            if (snap.ProcessGpuUsage.TryGetValue(pid, out var usage))
                max = Math.Max(max, usage);
        }
        return max;
    }

    /// <summary>
    /// Returns the VRAM usage in MB attributed to a specific PID.
    /// Returns -1 if unavailable.
    /// </summary>
    public double GetProcessVramUsage(int pid)
    {
        double total = 0;
        bool   found = false;
        foreach (var snap in _lastSnapshots)
        {
            if (snap.ProcessVramUsage.TryGetValue(pid, out var usage))
            {
                total += usage;
                found  = true;
            }
        }
        return found ? total : -1;
    }

    /// <summary>
    /// Returns the combined system-wide GPU utilisation across all adapters
    /// (maximum value if multiple adapters present).
    /// </summary>
    public double GetSystemGpuUtilization()
    {
        if (_lastSnapshots.Count == 0) return -1;
        return _lastSnapshots.Max(s => s.GpuUtilization);
    }

    // ── VRAM stability analysis ───────────────────────────────────────────────

    /// <summary>
    /// Returns true when VRAM usage has been very stable (low variance) over
    /// the observation window.  Miners tend to show stable VRAM usage while
    /// AI training may show more variation between epochs/batches.
    ///
    /// This is a weak signal — used only in combination with other indicators.
    /// </summary>
    public bool IsVramStable(int adapterIndex = 0, int minutes = 10)
    {
        if (!_history.TryGetValue(adapterIndex, out var q)) return false;
        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        lock (q)
        {
            var window = q.Where(s => s.Timestamp >= cutoff && s.VramPercent >= 0).ToList();
            if (window.Count < 10) return false;

            var values   = window.Select(s => s.VramPercent).ToList();
            var mean     = values.Average();
            var variance = values.Average(v => Math.Pow(v - mean, 2));
            var stdDev   = Math.Sqrt(variance);

            // Low standard deviation (<= 3%) indicates very stable VRAM use
            return stdDev <= 3.0;
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void RecordHistory(GpuSnapshot snap)
    {
        var q = _history.GetOrAdd(snap.AdapterIndex, _ => new Queue<GpuSample>());
        lock (q)
        {
            q.Enqueue(new GpuSample
            {
                Timestamp      = snap.SnapshotTime,
                GpuUtilization = snap.GpuUtilization,
                VramPercent    = snap.VramPercent,
            });
            while (q.Count > MaxSamples)
                q.Dequeue();
        }
    }

    // Instance name format: "pid_<pid>_luid_<luid>_phys_<n>_eng_<n>_engtype_<type>"
    private static int ExtractPidFromInstance(string inst)
    {
        try
        {
            const string prefix = "pid_";
            int start = inst.IndexOf(prefix, StringComparison.Ordinal);
            if (start < 0) return -1;
            start += prefix.Length;
            int end = inst.IndexOf('_', start);
            if (end < 0) return -1;
            return int.TryParse(inst[start..end], out int pid) ? pid : -1;
        }
        catch { return -1; }
    }

    private static int ExtractAdapterIndex(string inst)
    {
        try
        {
            // Use "phys_<n>" as the adapter index
            const string marker = "phys_";
            int start = inst.IndexOf(marker, StringComparison.Ordinal);
            if (start < 0) return 0;
            start += marker.Length;
            int end = inst.IndexOf('_', start);
            var segment = end < 0 ? inst[start..] : inst[start..end];
            return int.TryParse(segment, out int idx) ? idx : 0;
        }
        catch { return 0; }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (var c in _gpuEngineCounters.Values)  c.Dispose();
        foreach (var c in _vramUsedCounters.Values)   c.Dispose();
        foreach (var c in _vramTotalCounters.Values)  c.Dispose();
    }
}
