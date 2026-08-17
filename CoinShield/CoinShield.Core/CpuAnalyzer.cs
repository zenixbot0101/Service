using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using CoinShield.Configuration;
using CoinShield.Logging;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-process CPU history entry
// ─────────────────────────────────────────────────────────────────────────────

internal sealed class ProcessCpuSample
{
    public DateTime Timestamp   { get; init; }
    public double   CpuPercent  { get; init; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CpuAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Measures system-wide CPU utilisation and per-process CPU usage.
///
/// Uses <see cref="PerformanceCounter"/> for system-wide tracking and
/// <see cref="Process.TotalProcessorTime"/> deltas for per-process attribution.
///
/// Design note — CPU usage alone is NEVER a shutdown trigger.  This class
/// supplies raw values to the RiskScorer only.  High CPU is a weak signal
/// that must be correlated with other indicators before any action.
/// </summary>
public sealed class CpuAnalyzer : IDisposable
{
    // ── Configuration / dependencies ─────────────────────────────────────────
    private readonly MonitoringConfig _cfg;
    private readonly CoinShieldLogger _logger;

    // ── System-wide CPU counter ───────────────────────────────────────────────
    private PerformanceCounter? _systemCpuCounter;

    // ── Per-process state ─────────────────────────────────────────────────────
    // Key = PID; Value = (last total processor time, last sample time)
    private readonly ConcurrentDictionary<int, (TimeSpan lastCpu, DateTime lastTime)>
        _processCpuState = new();

    // Rolling history: last N samples per PID (capped at MaxHistorySamples)
    private readonly ConcurrentDictionary<int, Queue<ProcessCpuSample>>
        _processHistory = new();

    private const int MaxHistorySamples = 120; // 2 minutes at 1 s interval

    // ── System-wide rolling history ───────────────────────────────────────────
    private readonly Queue<(DateTime t, double cpu)> _systemHistory = new();
    private const int MaxSystemSamples = 300;  // 5 minutes

    private double _lastSystemCpu;
    private bool   _disposed;

    // ── Construction ─────────────────────────────────────────────────────────

    public CpuAnalyzer(MonitoringConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        TryInitSystemCounter();
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    private void TryInitSystemCounter()
    {
        try
        {
            _systemCpuCounter = new PerformanceCounter(
                "Processor Information", "% Processor Utility", "_Total", readOnly: true);
            // Prime the counter — first call always returns 0
            _ = _systemCpuCounter.NextValue();
        }
        catch (Exception ex)
        {
            _logger.Warning("CpuAnalyzer",
                $"Could not initialise system CPU counter: {ex.Message}. " +
                "Will fall back to process-based estimation.");
            _systemCpuCounter = null;
        }
    }

    // ── System-wide CPU ───────────────────────────────────────────────────────

    /// <summary>
    /// Samples the current system-wide CPU utilisation (0–100 %).
    /// Returns the last cached value on failure.
    /// </summary>
    public double SampleSystemCpu()
    {
        double value = 0.0;

        if (_systemCpuCounter is not null)
        {
            try
            {
                value = Math.Min(100.0, _systemCpuCounter.NextValue());
            }
            catch (Exception ex)
            {
                _logger.Debug("CpuAnalyzer", $"System CPU sample failed: {ex.Message}");
                value = _lastSystemCpu;
            }
        }
        else
        {
            // Fallback: estimate from all running processes
            value = EstimateSystemCpuFromProcesses();
        }

        _lastSystemCpu = value;

        lock (_systemHistory)
        {
            _systemHistory.Enqueue((DateTime.UtcNow, value));
            while (_systemHistory.Count > MaxSystemSamples)
                _systemHistory.Dequeue();
        }

        return value;
    }

    /// <summary>
    /// Returns the average system CPU over the last <paramref name="minutes"/> minutes.
    /// Returns -1 if insufficient history is available.
    /// </summary>
    public double AverageSystemCpu(int minutes = 5)
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        lock (_systemHistory)
        {
            var recent = _systemHistory.Where(s => s.t >= cutoff).ToList();
            return recent.Count < 3 ? -1 : recent.Average(s => s.cpu);
        }
    }

    // ── Per-process CPU ───────────────────────────────────────────────────────

    /// <summary>
    /// Calculates the CPU utilisation % for the given process since the last
    /// call for that PID.  Returns -1 if the process is inaccessible or no
    /// previous sample exists (first call always returns -1).
    /// </summary>
    public double SampleProcessCpu(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var now         = DateTime.UtcNow;
            var totalCpu    = proc.TotalProcessorTime;

            if (_processCpuState.TryGetValue(pid, out var prev))
            {
                var cpuDelta  = (totalCpu - prev.lastCpu).TotalMilliseconds;
                var timeDelta = (now - prev.lastTime).TotalMilliseconds;

                if (timeDelta > 0)
                {
                    // Normalise across all logical CPUs
                    var cores   = Math.Max(1, Environment.ProcessorCount);
                    var percent = (cpuDelta / timeDelta / cores) * 100.0;
                    percent     = Math.Clamp(percent, 0.0, 100.0);

                    _processCpuState[pid] = (totalCpu, now);
                    RecordProcessSample(pid, percent);
                    return percent;
                }
            }

            // First sample — store baseline
            _processCpuState[pid] = (totalCpu, now);
            return -1;
        }
        catch (ArgumentException)
        {
            // Process exited
            _processCpuState.TryRemove(pid, out _);
            _processHistory.TryRemove(pid, out _);
            return -1;
        }
        catch (Exception ex)
        {
            _logger.Debug("CpuAnalyzer", $"Process CPU sample PID={pid}: {ex.Message}");
            return -1;
        }
    }

    /// <summary>
    /// Returns the average CPU utilisation for a process over the last
    /// <paramref name="minutes"/> minutes, or -1 if insufficient history.
    /// </summary>
    public double AverageProcessCpu(int pid, int minutes = 5)
    {
        if (!_processHistory.TryGetValue(pid, out var history)) return -1;

        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        lock (history)
        {
            var recent = history.Where(s => s.Timestamp >= cutoff).ToList();
            return recent.Count < 2 ? -1 : recent.Average(s => s.CpuPercent);
        }
    }

    /// <summary>
    /// Returns the sustained CPU % over a window. Useful for scoring:
    /// only counts as elevated if it has been high for a meaningful period.
    /// </summary>
    public double PeakSustainedProcessCpu(int pid, int windowMinutes = 10)
    {
        if (!_processHistory.TryGetValue(pid, out var history)) return -1;

        var cutoff = DateTime.UtcNow.AddMinutes(-windowMinutes);
        lock (history)
        {
            var window = history.Where(s => s.Timestamp >= cutoff).ToList();
            if (window.Count < 5) return -1;

            // 90th percentile as the "sustained" peak
            var sorted = window.Select(s => s.CpuPercent).OrderBy(v => v).ToList();
            var idx    = (int)(sorted.Count * 0.90);
            return sorted[Math.Min(idx, sorted.Count - 1)];
        }
    }

    // ── Eviction of dead processes ────────────────────────────────────────────

    /// <summary>
    /// Removes tracking state for PIDs that are no longer running.
    /// Call periodically (e.g. every 60 seconds) to avoid memory growth.
    /// </summary>
    public void PruneDeadProcesses(IEnumerable<int> activePids)
    {
        var active = new HashSet<int>(activePids);

        foreach (var pid in _processCpuState.Keys.ToList())
        {
            if (!active.Contains(pid))
            {
                _processCpuState.TryRemove(pid, out _);
                _processHistory.TryRemove(pid, out _);
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void RecordProcessSample(int pid, double percent)
    {
        var queue = _processHistory.GetOrAdd(pid, _ => new Queue<ProcessCpuSample>());
        lock (queue)
        {
            queue.Enqueue(new ProcessCpuSample
            {
                Timestamp  = DateTime.UtcNow,
                CpuPercent = percent,
            });
            while (queue.Count > MaxHistorySamples)
                queue.Dequeue();
        }
    }

    private static double EstimateSystemCpuFromProcesses()
    {
        // Very rough fallback: sum of all accessible process CPU times is not
        // straightforward without deltas, so return -1 to indicate unavailable.
        return -1;
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _systemCpuCounter?.Dispose();
    }
}
