using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  ProcessResurrectionDetector
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Detects miner resurrection / persistence patterns:
///
///   Pattern A — Direct resurrection:
///     Process A killed  →  Process A starts again (< 60 s)
///     Score boost: +25
///
///   Pattern B — Watchdog resurrection:
///     Process A killed  →  Process B starts  →  B launches A
///     A → B → A cycle
///     Score boost: +40 (persistence mechanism confirmed)
///
///   Pattern C — Scheduled-task resurrection:
///     Process killed  →  reappears at regular intervals
///     (detected via time-interval pattern)
///     Score boost: +35
///
/// This detector does NOT make kill decisions.  It feeds resurrection scores
/// into the RiskScorer via ResurrectionResult events.
/// </summary>
public sealed class ProcessResurrectionDetector
{
    private readonly CoinShieldLogger _logger;

    // Recently terminated processes: name → kill record
    private readonly ConcurrentDictionary<string, KillRecord> _killed = new(StringComparer.OrdinalIgnoreCase);

    // Process resurrection history: name → list of resurrection records
    // THREAD-01 FIX: Use a dedicated lock per-list via a wrapper, or use a single
    // class-level lock when accessing inner lists. We use _historyLock for all
    // _history inner-list mutations to prevent concurrent List<T>.Add() races.
    private readonly ConcurrentDictionary<string, List<ResurrectionEvent>> _history
        = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _historyLock = new();

    // Currently tracked processes: pid → tracking info
    private readonly ConcurrentDictionary<int, ProcessTracking> _active = new();

    // Known resurrection pairs (watchdog pattern): watcher-name → target-name
    private readonly ConcurrentDictionary<string, string> _watchdogPairs
        = new(StringComparer.OrdinalIgnoreCase);

    // ── Configuration constants ───────────────────────────────────────────────
    private static readonly TimeSpan ResurrectionWindow   = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan KillRecordExpiry     = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PatternWindow        = TimeSpan.FromMinutes(30);
    private const int MaxResurrectionHistory              = 20;
    private const int CycleDetectionMinCount              = 3;   // A→B→A needs 3+ events

    // ── Events ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Raised when a resurrection pattern is detected.
    /// Subscribers should add the AdditionalScore to the process's risk score.
    /// </summary>
    public event Action<ResurrectionResult>? ResurrectionDetected;

    public ProcessResurrectionDetector(CoinShieldLogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Called by ResponseEngine BEFORE a process is killed.
    /// Records that we intentionally terminated this process so we can detect
    /// if it comes back.
    /// </summary>
    public void RecordKill(int pid, string name, string path)
    {
        _killed[name] = new KillRecord
        {
            Pid       = pid,
            Name      = name,
            Path      = path,
            KilledAt  = DateTime.UtcNow
        };

        _logger.Debug("ResurrectionDetector",
            $"Kill recorded: PID={pid} Name={name}");
    }

    /// <summary>
    /// Called every process-scan cycle with the full current process list.
    /// Detects newly appeared processes that match killed entries.
    /// </summary>
    public void UpdateProcessList(IEnumerable<(int Pid, string Name, string Path, int ParentPid)> processes)
    {
        var now = DateTime.UtcNow;

        // Purge expired kill records
        foreach (var key in _killed.Keys.ToList())
        {
            if (_killed.TryGetValue(key, out var rec) &&
                now - rec.KilledAt > KillRecordExpiry)
            {
                _killed.TryRemove(key, out _);
            }
        }

        var processList = processes.ToList();

        // Update active tracking
        var currentPids = new HashSet<int>(processList.Select(p => p.Pid));
        foreach (var gone in _active.Keys.Except(currentPids).ToList())
            _active.TryRemove(gone, out _);

        foreach (var (pid, name, path, parentPid) in processList)
        {
            if (_active.ContainsKey(pid)) continue;   // Already tracking

            _active[pid] = new ProcessTracking
            {
                Pid       = pid,
                Name      = name,
                Path      = path,
                ParentPid = parentPid,
                FirstSeen = now
            };

            // Check if this new process matches a recently killed one
            CheckForResurrection(pid, name, path, parentPid, now, processList);
        }
    }

    /// <summary>
    /// Returns the resurrection score bonus for a given process name.
    /// 0 if no resurrection history; higher if repeated resurrections detected.
    /// </summary>
    public int GetResurrectionScore(string processName)
    {
        List<ResurrectionEvent> snapshot;
        lock (_historyLock)
        {
            if (!_history.TryGetValue(processName, out var list)) return 0;
            snapshot = new List<ResurrectionEvent>(list);
        }

        var recent = snapshot.Where(e => DateTime.UtcNow - e.DetectedAt <= PatternWindow).ToList();
        if (recent.Count == 0) return 0;

        int score = 0;
        foreach (var ev in recent)
        {
            score += ev.Pattern switch
            {
                ResurrectionPattern.DirectResurrection   => 25,
                ResurrectionPattern.WatchdogLoop         => 40,
                ResurrectionPattern.ScheduledTaskRestart => 35,
                _                                        => 10
            };
        }
        return Math.Min(score, 80);
    }

    public bool IsResurrected(string processName)
    {
        lock (_historyLock)
        {
            if (!_history.TryGetValue(processName, out var list)) return false;
            return list.Any(e => DateTime.UtcNow - e.DetectedAt <= PatternWindow);
        }
    }

    public ProcessResurrectionRecord? GetRecord(string processName)
    {
        List<ResurrectionEvent> recent;
        lock (_historyLock)
        {
            if (!_history.TryGetValue(processName, out var list)) return null;
            recent = list.Where(e => DateTime.UtcNow - e.DetectedAt <= PatternWindow).ToList();
        }
        if (recent.Count == 0) return null;
        if (!_killed.TryGetValue(processName, out var kill)) return null;

        string? watchdog = _watchdogPairs.TryGetValue(processName, out var wd) ? wd : null;
        string pattern = recent.First().Pattern switch
        {
            ResurrectionPattern.DirectResurrection   => "direct-restart",
            ResurrectionPattern.WatchdogLoop         => $"watchdog-loop({watchdog}→{processName})",
            ResurrectionPattern.ScheduledTaskRestart => "scheduled-task",
            _                                        => "unknown"
        };

        return new ProcessResurrectionRecord
        {
            ProcessId             = kill.Pid,
            ProcessName           = processName,
            ProcessPath           = kill.Path,
            KillCount             = recent.Count,
            ResurrectionCount     = recent.Count,
            LastKillTime          = kill.KilledAt,
            LastResurrectionTime  = recent.Max(e => e.DetectedAt),
            ResurrectorProcessId  = recent.FirstOrDefault()?.ResurrectorPid,
            ResurrectionPattern   = pattern,
            IsConfirmedPersistence= recent.Count >= 2
        };
    }

    // ── Private detection logic ───────────────────────────────────────────────

    private void CheckForResurrection(
        int    newPid,
        string name,
        string path,
        int    parentPid,
        DateTime now,
        List<(int Pid, string Name, string Path, int ParentPid)> allProcesses)
    {
        // Pattern A: direct resurrection (same name reappears after kill)
        if (_killed.TryGetValue(name, out var killRec))
        {
            var timeSinceKill = now - killRec.KilledAt;
            if (timeSinceKill <= ResurrectionWindow)
            {
                RecordResurrectionEvent(name, newPid, parentPid, path,
                    ResurrectionPattern.DirectResurrection, timeSinceKill, now);

                _logger.Warning("ResurrectionDetector",
                    $"RESURRECTION: PID={newPid} Name={name} " +
                    $"killed {timeSinceKill.TotalSeconds:F0}s ago, now alive again. " +
                    $"ParentPID={parentPid}");
            }
        }

        // Pattern B: watchdog loop — check if this process's parent launched a
        // known-killed process. Requires the NEW process name to match a killed name.
        // BUG-08 FIX: Old code checked any process whose parent had resurrection history,
        // regardless of whether the new process name matched the killed target.
        if (parentPid > 0 && _killed.ContainsKey(name))
        {
            if (_active.TryGetValue(parentPid, out var parent))
            {
                // Parent is alive AND the newly appearing process matches a killed name.
                // This is the A→B→A pattern: parent (B) relaunched killed target (A).
                bool parentHasHistory;
                lock (_historyLock)
                {
                    parentHasHistory = _history.ContainsKey(parent.Name);
                }

                if (parentHasHistory || _killed.ContainsKey(parent.Name))
                {
                    RecordWatchdogPair(parent.Name, name);

                    _logger.Warning("ResurrectionDetector",
                        $"WATCHDOG_LOOP: Parent={parent.Name}(PID={parentPid}) " +
                        $"relaunched killed process {name}(PID={newPid})");
                }
            }
        }
    }

    private void CheckABACycle(
        string killedName,
        int    parentPid,
        int    newPid,
        DateTime now,
        List<(int Pid, string Name, string Path, int ParentPid)> allProcesses)
    {
        var parent = allProcesses.FirstOrDefault(p => p.Pid == parentPid);
        if (parent == default) return;

        List<ResurrectionEvent> recentByParentType;
        lock (_historyLock)
        {
            if (!_history.TryGetValue(killedName, out var hist)) return;
            recentByParentType = hist.Where(e =>
                e.DetectedAt >= now - PatternWindow &&
                e.Pattern == ResurrectionPattern.DirectResurrection).ToList();
        }

        if (recentByParentType.Count >= 1)
        {
            RecordWatchdogPair(parent.Name, killedName);
            RecordResurrectionEvent(killedName, newPid, parentPid, parent.Path,
                ResurrectionPattern.WatchdogLoop, TimeSpan.Zero, now);

            _logger.Warning("ResurrectionDetector",
                $"A→B→A CYCLE CONFIRMED: {killedName}→{parent.Name}→{killedName} " +
                $"(PID={newPid}, ParentPID={parentPid})");
        }

        CheckScheduledPattern(killedName, now, newPid, parentPid);
    }

    private void CheckScheduledPattern(string name, DateTime now, int newPid, int parentPid)
    {
        List<ResurrectionEvent> recent;
        lock (_historyLock)
        {
            if (!_history.TryGetValue(name, out var hist)) return;
            recent = hist
                .Where(e => e.DetectedAt >= now - PatternWindow)
                .OrderBy(e => e.DetectedAt)
                .ToList();
        }

        if (recent.Count < CycleDetectionMinCount) return;

        // Calculate intervals between resurrections
        var intervals = new List<double>();
        for (int i = 1; i < recent.Count; i++)
        {
            intervals.Add((recent[i].DetectedAt - recent[i - 1].DetectedAt).TotalSeconds);
        }

        if (intervals.Count < 2) return;

        double avg = intervals.Average();
        double stdDev = Math.Sqrt(intervals.Select(x => Math.Pow(x - avg, 2)).Average());

        // Low variance = scheduled pattern (std dev < 15% of mean)
        bool isScheduled = stdDev < avg * 0.15 && avg < 600; // Within 10 min

        if (isScheduled)
        {
            RecordResurrectionEvent(name, newPid, parentPid, string.Empty,
                ResurrectionPattern.ScheduledTaskRestart, TimeSpan.Zero, now);

            _logger.Warning("ResurrectionDetector",
                $"SCHEDULED_RESURRECTION: {name} reappears every ~{avg:F0}s " +
                $"(stddev={stdDev:F1}s). Likely scheduled task or service.");
        }
    }

    private void RecordResurrectionEvent(
        string     name,
        int        newPid,
        int        parentPid,
        string     path,
        ResurrectionPattern pattern,
        TimeSpan   elapsed,
        DateTime   now)
    {
        var ev = new ResurrectionEvent
        {
            ProcessName      = name,
            NewPid           = newPid,
            ResurrectorPid   = parentPid,
            Pattern          = pattern,
            ElapsedSinceKill = elapsed,
            DetectedAt       = now
        };

        // THREAD-01 FIX: All inner List<ResurrectionEvent> mutations under _historyLock
        int count;
        lock (_historyLock)
        {
            if (!_history.TryGetValue(name, out var list))
            {
                list = new List<ResurrectionEvent>();
                _history[name] = list;
            }
            list.Add(ev);
            if (list.Count > MaxResurrectionHistory)
                list.RemoveAt(0);
            count = list.Count;
        }

        int score = GetResurrectionScore(name);

        var result = new ResurrectionResult
        {
            ProcessName     = name,
            NewPid          = newPid,
            Pattern         = pattern,
            AdditionalScore = score,
            IsConfirmed     = count >= 2
        };

        ResurrectionDetected?.Invoke(result);
    }

    private void RecordWatchdogPair(string watcher, string target)
    {
        _watchdogPairs[target] = watcher;
    }

    // ── Private types ─────────────────────────────────────────────────────────

    private sealed class KillRecord
    {
        public int      Pid      { get; init; }
        public string   Name     { get; init; } = string.Empty;
        public string   Path     { get; init; } = string.Empty;
        public DateTime KilledAt { get; init; }
    }

    private sealed class ProcessTracking
    {
        public int      Pid       { get; init; }
        public string   Name      { get; init; } = string.Empty;
        public string   Path      { get; init; } = string.Empty;
        public int      ParentPid { get; init; }
        public DateTime FirstSeen { get; init; }
    }

    private sealed class ResurrectionEvent
    {
        public string              ProcessName      { get; init; } = string.Empty;
        public int                 NewPid           { get; init; }
        public int                 ResurrectorPid   { get; init; }
        public ResurrectionPattern Pattern          { get; init; }
        public TimeSpan            ElapsedSinceKill { get; init; }
        public DateTime            DetectedAt       { get; init; }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Result types
// ─────────────────────────────────────────────────────────────────────────────

public enum ResurrectionPattern
{
    Unknown = 0,
    DirectResurrection,    // Process A killed → A starts again
    WatchdogLoop,          // A → B → A cycle
    ScheduledTaskRestart   // A reappears at regular intervals
}

public sealed class ResurrectionResult
{
    public string              ProcessName     { get; init; } = string.Empty;
    public int                 NewPid          { get; init; }
    public ResurrectionPattern Pattern         { get; init; }
    public int                 AdditionalScore { get; init; }
    public bool                IsConfirmed     { get; init; }
}
