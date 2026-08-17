using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  Per-process tracking state
// ─────────────────────────────────────────────────────────────────────────────

internal sealed class ProcessTrackingState
{
    public int             Pid                   { get; init; }
    public string          Name                  { get; init; } = string.Empty;
    public DetectionState  State                 { get; set; }  = DetectionState.Normal;
    public DateTime?       SuspicionStartTime    { get; set; }
    public DateTime?       HighRiskStartTime     { get; set; }
    public DateTime        LastEvaluated         { get; set; }  = DateTime.UtcNow;
    public RiskScore?      LastScore             { get; set; }
    public int             ConsecutiveHighScores { get; set; }

    // LOGIC-01 FIX: Track when this process FIRST became suspicious.
    // Unlike SuspicionStartTime (which resets to null when score drops below threshold),
    // FirstSuspicionTime is set once and never cleared. This prevents an oscillating
    // miner (score bouncing across the threshold every ~59 seconds) from permanently
    // resetting the confirmation window and evading confirmation indefinitely.
    public DateTime? FirstSuspicionTime   { get; set; }

    /// <summary>
    /// True once the confirmation window has elapsed from FIRST suspicion.
    /// Uses FirstSuspicionTime (set once) rather than SuspicionStartTime (resets on oscillation).
    /// </summary>
    public bool ConfirmationWindowPassed(int seconds) =>
        FirstSuspicionTime.HasValue
        && (DateTime.UtcNow - FirstSuspicionTime.Value).TotalSeconds >= seconds;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CorrelationEngine
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Tracks the detection state for every monitored process across multiple
/// evaluation cycles and enforces the confirmation window before escalating
/// to ConfirmedMining.
///
/// State machine:
///   Normal → Suspicious → Analyzing → AiWorkload / Normal / HighRisk → ConfirmedMining → ActionTaken
///
/// The confirmation window prevents short GPU spikes or transient network
/// events from triggering the response engine.
///
/// IMPORTANT: The CorrelationEngine decides WHEN to escalate a state.
/// The ResponseEngine decides WHAT to do.  These responsibilities are
/// intentionally separated.
/// </summary>
public sealed class CorrelationEngine
{
    private readonly CoinShieldConfig _cfg;
    private readonly CoinShieldLogger _logger;

    // Per-process tracking: PID → state
    private readonly ConcurrentDictionary<int, ProcessTrackingState>
        _states = new();

    private DetectionConfig  D  => _cfg.Detection;
    private AiProtectionConfig AI => _cfg.AiProtection;

    public CorrelationEngine(CoinShieldConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Main evaluation ───────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates a fresh <see cref="RiskScore"/> for the given process and
    /// advances the state machine accordingly.
    ///
    /// Returns an updated <see cref="DetectionResult"/> capturing the new
    /// state, confirmation status, and evidence.
    /// </summary>
    public DetectionResult Evaluate(
        int        pid,
        string     processName,
        RiskScore  score,
        ProcessSnapshot?  processSnap = null,
        GpuSnapshot?      gpuSnap     = null,
        NetworkAnalysis?  network     = null,
        List<PersistenceEntry>? persistence = null)
    {
        var tracking = _states.GetOrAdd(pid, p => new ProcessTrackingState
        {
            Pid  = p,
            Name = processName,
        });

        tracking.LastEvaluated = DateTime.UtcNow;
        tracking.Name          = processName; // keep name fresh

        var prevState = tracking.State;
        AdvanceStateMachine(tracking, score);

        // Confirmation window tracking
        if (tracking.State >= DetectionState.Suspicious
            && !tracking.SuspicionStartTime.HasValue)
        {
            tracking.SuspicionStartTime = DateTime.UtcNow;
        }

        // LOGIC-01 FIX: FirstSuspicionTime is set once on first elevation
        // and NEVER cleared, even if the score drops back to Normal temporarily.
        if (tracking.State >= DetectionState.Suspicious
            && !tracking.FirstSuspicionTime.HasValue)
        {
            tracking.FirstSuspicionTime = DateTime.UtcNow;
        }

        // Reset suspicion timer if process drops back to Normal
        if (tracking.State == DetectionState.Normal)
        {
            tracking.SuspicionStartTime    = null;
            tracking.HighRiskStartTime     = null;
            tracking.ConsecutiveHighScores = 0;
            // NOTE: FirstSuspicionTime is intentionally NOT reset here.
        }

        bool confirmationPassed = tracking.ConfirmationWindowPassed(D.ConfirmationSeconds);

        // Build result
        var result = new DetectionResult
        {
            Pid                      = pid,
            ProcessName              = processName,
            Score                    = score,
            State                    = tracking.State,
            PreviousState            = prevState,
            SuspicionStartTime       = tracking.SuspicionStartTime,
            ConfirmationWindowPassed = confirmationPassed,
            ProcessSnapshot          = processSnap,
            GpuSnapshot              = gpuSnap,
            EvaluatedAt              = DateTime.UtcNow,
        };

        // Copy network suspicious connections
        if (network?.SuspiciousConnections is { Count: > 0 })
            result.SuspiciousConnections.AddRange(network.SuspiciousConnections);

        // Copy persistence entries
        if (persistence is { Count: > 0 })
            result.PersistenceEntries.AddRange(
                persistence.Where(p => p.IsSuspicious).Select(p => p.Reason));

        // Assemble evidence narrative
        BuildEvidence(result, score, network, persistence);

        tracking.LastScore = score;
        return result;
    }

    // ── State machine ─────────────────────────────────────────────────────────

    private void AdvanceStateMachine(ProcessTrackingState tracking, RiskScore score)
    {
        int total = score.Total;

        switch (tracking.State)
        {
            // ── From Normal ───────────────────────────────────────────────────
            case DetectionState.Normal:
                if (total >= D.HighRiskThreshold)
                {
                    // Jump straight to HighRisk if score is very high
                    tracking.State = DetectionState.HighRisk;
                    tracking.HighRiskStartTime = DateTime.UtcNow;
                }
                else if (total >= D.SuspiciousThreshold)
                {
                    tracking.State = DetectionState.Suspicious;
                }
                break;

            // ── From Suspicious ───────────────────────────────────────────────
            case DetectionState.Suspicious:
                if (total < D.SuspiciousThreshold)
                {
                    // Score dropped — return to normal
                    tracking.State              = DetectionState.Normal;
                    tracking.SuspicionStartTime = null;
                }
                else if (total >= D.HighRiskThreshold)
                {
                    tracking.State             = DetectionState.Analyzing;
                    tracking.HighRiskStartTime = DateTime.UtcNow;
                }
                break;

            // ── From Analyzing ────────────────────────────────────────────────
            case DetectionState.Analyzing:
                if (total < D.SuspiciousThreshold)
                {
                    tracking.State = DetectionState.Normal;
                    break;
                }

                // AI workload — keep monitoring but de-escalate
                if (AI.Enabled && score.AiConfidence >= AI.MinimumConfidence)
                {
                    tracking.State = DetectionState.AiWorkload;
                    _logger.Info("CorrelationEngine",
                        $"PID={tracking.Pid} classified as AI_WORKLOAD " +
                        $"(AIConf={score.AiConfidence:F2}, Score={total})");
                    break;
                }

                if (total >= D.HighRiskThreshold)
                {
                    tracking.State = DetectionState.HighRisk;
                    tracking.ConsecutiveHighScores++;
                }
                break;

            // ── From AiWorkload ───────────────────────────────────────────────
            // Continue monitoring — do not escalate unless explicit mining
            // protocol evidence arrives (at which point AI confidence drops)
            case DetectionState.AiWorkload:
                if (score.AiConfidence < AI.MinimumConfidence
                    && score.MiningConfidence > 0.75
                    && total >= D.HighRiskThreshold)
                {
                    _logger.Warning("CorrelationEngine",
                        $"PID={tracking.Pid} AI workload classification revoked: " +
                        $"AIConf={score.AiConfidence:F2} MiningConf={score.MiningConfidence:F2}");
                    tracking.State = DetectionState.HighRisk;
                }
                // Stay in AiWorkload — keep monitoring, never action
                break;

            // ── From HighRisk ─────────────────────────────────────────────────
            case DetectionState.HighRisk:
                if (total < D.SuspiciousThreshold)
                {
                    tracking.State             = DetectionState.Normal;
                    tracking.HighRiskStartTime = null;
                    break;
                }

                tracking.ConsecutiveHighScores++;

                // AI workload protection — even in HighRisk, if AI confidence is
                // sufficiently high, do NOT escalate to ConfirmedMining
                if (AI.Enabled && score.AiConfidence >= AI.MinimumConfidence)
                {
                    tracking.State = DetectionState.AiWorkload;
                    _logger.Info("CorrelationEngine",
                        $"PID={tracking.Pid} HIGH_RISK → AI_WORKLOAD " +
                        $"(AIConf={score.AiConfidence:F2})");
                    break;
                }

                // Gate: need all four criteria satisfied simultaneously
                bool scoreGate         = total >= D.ConfirmedMiningThreshold;
                bool indicatorGate     = score.StrongIndicatorCount >= D.MinimumStrongIndicators;
                bool aiGate            = !AI.Enabled || score.AiConfidence < AI.MinimumConfidence;
                bool windowGate        = tracking.ConfirmationWindowPassed(D.ConfirmationSeconds);

                if (scoreGate && indicatorGate && aiGate && windowGate)
                {
                    tracking.State = DetectionState.ConfirmedMining;
                    _logger.Warning("CorrelationEngine",
                        $"PID={tracking.Pid} → CONFIRMED_MINING " +
                        $"Score={total} Indicators={score.StrongIndicatorCount} " +
                        $"AIConf={score.AiConfidence:F2} Window={D.ConfirmationSeconds}s");
                }
                break;

            // ── ConfirmedMining / ActionTaken — terminal ──────────────────────
            case DetectionState.ConfirmedMining:
            case DetectionState.ActionTaken:
                // State is held until process exits or is explicitly cleared
                break;
        }
    }

    // ── Evidence builder ──────────────────────────────────────────────────────

    private static void BuildEvidence(
        DetectionResult        result,
        RiskScore              score,
        NetworkAnalysis?       network,
        List<PersistenceEntry>? persistence)
    {
        result.Evidence.AddRange(score.Reasons);

        if (network?.SuspiciousConnections is { Count: > 0 })
        {
            foreach (var conn in network.SuspiciousConnections.Take(5))
                result.Evidence.Add(
                    $"Network: {conn.RemoteAddress}:{conn.RemotePort} " +
                    $"({conn.RemoteHostname}) for {conn.Duration.TotalMinutes:F0} min.");
        }

        if (persistence is not null)
        {
            foreach (var p in persistence.Where(x => x.IsSuspicious).Take(3))
                result.Evidence.Add($"Persistence: [{p.Type}] {p.Location} → {p.Reason}");
        }

        result.Evidence.Add(
            $"Score={score.Total} " +
            $"AI={score.AiConfidence:F2} " +
            $"Mining={score.MiningConfidence:F2} " +
            $"StrongIndicators={score.StrongIndicatorCount}");
    }

    // ── Process eviction ──────────────────────────────────────────────────────

    /// <summary>Removes tracking entries for processes no longer running.</summary>
    public void PruneDeadProcesses(IEnumerable<int> activePids)
    {
        var active = new HashSet<int>(activePids);
        foreach (var pid in _states.Keys.ToList())
            if (!active.Contains(pid))
                _states.TryRemove(pid, out _);
    }

    /// <summary>
    /// Marks a process as ActionTaken after the response engine has acted.
    /// </summary>
    public void MarkActionTaken(int pid)
    {
        if (_states.TryGetValue(pid, out var state))
            state.State = DetectionState.ActionTaken;
    }

    /// <summary>Returns the current detection state for a PID, or Normal if not tracked.</summary>
    public DetectionState GetState(int pid) =>
        _states.TryGetValue(pid, out var s) ? s.State : DetectionState.Normal;

    /// <summary>All currently tracked states (read-only snapshot).</summary>
    public IReadOnlyList<(int pid, DetectionState state, RiskScore? score)> GetAllStates() =>
        _states.Values
               .Select(s => (s.Pid, s.State, s.LastScore))
               .ToList();
}
