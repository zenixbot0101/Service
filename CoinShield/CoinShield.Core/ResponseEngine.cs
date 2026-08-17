using System;
using System.Diagnostics;
using System.Threading;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  ResponseEngine
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// The ONLY component permitted to request process termination or machine
/// shutdown.  All other components feed data upwards; only ResponseEngine
/// acts downwards.
///
/// Before any destructive action ResponseEngine verifies EVERY gate condition
/// one final time:
///   1. Risk score ≥ configured threshold
///   2. Strong indicators ≥ minimum
///   3. AI confidence &lt; AI protection threshold
///   4. Confirmation window has elapsed
///   5. Operating mode permits the action
///
/// A false positive that shuts down an AI training machine is considered a
/// detection failure.  Therefore the default mode is Monitor (no action).
///
/// Flow:
///   DetectionEngine ──MiningConfirmed──► ResponseEngine.Handle()
///                                               │
///                              ┌────────────────┘
///                              ▼
///                      WriteIncidentEvidence
///                              │
///                    ┌─────────┴─────────┐
///                    ▼                   ▼
///             TerminateProcess?   EmergencyShutdown?
///          (Enforcement mode)    (Emergency mode only)
/// </summary>
public sealed class ResponseEngine
{
    private readonly CoinShieldConfig  _cfg;
    private readonly CoinShieldLogger  _logger;
    private readonly CorrelationEngine _correlator;
    private readonly ProcessResurrectionDetector _resurrectionDetector;

    // Guard against acting on the same PID twice in quick succession.
    // Key for process PIDs: the PID itself (positive int).
    // Key for web mining: a string key stored in a separate dictionary.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DateTime>
        _actedOn = new();
    // BUG-06 FIX: Web mining cooldown uses a string key (processId.ToString() + ":web")
    // instead of integer arithmetic that could overflow for large PIDs.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime>
        _webActedOn = new();

    private static readonly TimeSpan ActionCooldown = TimeSpan.FromMinutes(5);

    private DetectionConfig   D  => _cfg.Detection;
    private AiProtectionConfig AI => _cfg.AiProtection;
    private ResponseConfig     R  => _cfg.Response;

    public ResponseEngine(
        CoinShieldConfig  cfg,
        CoinShieldLogger  logger,
        CorrelationEngine correlator,
        ProcessResurrectionDetector resurrectionDetector)
    {
        _cfg                  = cfg                  ?? throw new ArgumentNullException(nameof(cfg));
        _logger               = logger               ?? throw new ArgumentNullException(nameof(logger));
        _correlator           = correlator           ?? throw new ArgumentNullException(nameof(correlator));
        _resurrectionDetector = resurrectionDetector ?? throw new ArgumentNullException(nameof(resurrectionDetector));
    }

    // ── Main handler (called by DetectionEngine.MiningConfirmed event) ────────

    /// <summary>
    /// Handles a confirmed-mining detection result.
    /// All gate conditions are re-verified here independently of the scorer.
    /// </summary>
    public void Handle(DetectionResult result)
    {
        if (result is null) return;

        // ── Cooldown guard ────────────────────────────────────────────────────
        if (_actedOn.TryGetValue(result.Pid, out var lastAction)
            && (DateTime.UtcNow - lastAction) < ActionCooldown)
        {
            _logger.Debug("ResponseEngine",
                $"PID={result.Pid} within action cooldown — skipping.");
            return;
        }

        // ── Final gate verification ───────────────────────────────────────────
        if (!VerifyAllGates(result))
        {
            _logger.Warning("ResponseEngine",
                $"PID={result.Pid} failed final gate verification — no action taken. " +
                $"Score={result.Score.Total} AI={result.Score.AiConfidence:F2} " +
                $"Indicators={result.Score.StrongIndicatorCount} " +
                $"Window={result.ConfirmationWindowPassed}");
            return;
        }

        // ── Step 1: Log incident ──────────────────────────────────────────────
        LogIncident(result);

        // ── Step 2: Record evidence to disk ──────────────────────────────────
        string incidentPath = WriteEvidence(result);
        _logger.Info("ResponseEngine",
            $"Incident evidence written to: {incidentPath}");

        // ── Step 3: Terminate process (Enforcement or Emergency mode) ─────────
        if (R.TerminateMiningProcess && D.Mode != OperatingMode.Monitor)
        {
            // Record kill BEFORE terminating so ResurrectionDetector tracks it
            _resurrectionDetector.RecordKill(result.Pid, result.ProcessName,
                result.ProcessSnapshot?.Path ?? string.Empty);

            TryTerminateProcess(result);
        }
        else
        {
            _logger.Info("ResponseEngine",
                $"Monitor mode — process NOT terminated. PID={result.Pid}");
        }

        // ── Step 4: Emergency shutdown (Emergency mode only) ──────────────────
        if (R.EmergencyShutdown && D.Mode == OperatingMode.Emergency)
        {
            InitiateShutdown(result);
        }

        _correlator.MarkActionTaken(result.Pid);
        _actedOn[result.Pid] = DateTime.UtcNow;
    }

    // ── Gate verification ─────────────────────────────────────────────────────

    /// <summary>
    /// Independently re-verifies ALL four gate conditions.
    /// This prevents a race condition where a process's score drops between
    /// the CorrelationEngine's decision and the ResponseEngine's action.
    /// </summary>
    private bool VerifyAllGates(DetectionResult result)
    {
        var score = result.Score;

        // Gate 1: score threshold
        if (score.Total < D.ConfirmedMiningThreshold)
        {
            _logger.Debug("ResponseEngine",
                $"Gate 1 failed: score {score.Total} < threshold {D.ConfirmedMiningThreshold}");
            return false;
        }

        // Gate 2: minimum strong indicators
        if (score.StrongIndicatorCount < D.MinimumStrongIndicators)
        {
            _logger.Debug("ResponseEngine",
                $"Gate 2 failed: indicators {score.StrongIndicatorCount} " +
                $"< required {D.MinimumStrongIndicators}");
            return false;
        }

        // Gate 3: AI confidence must be BELOW the protection threshold
        if (AI.Enabled && score.AiConfidence >= AI.MinimumConfidence)
        {
            _logger.Warning("ResponseEngine",
                $"Gate 3 failed — AI protection active: " +
                $"AIConf={score.AiConfidence:F2} >= {AI.MinimumConfidence:F2}. " +
                "Process classified as legitimate AI workload. NO ACTION.");
            return false;
        }

        // Gate 4: confirmation window must have elapsed
        if (!result.ConfirmationWindowPassed)
        {
            _logger.Debug("ResponseEngine",
                "Gate 4 failed: confirmation window not yet elapsed.");
            return false;
        }

        return true;
    }

    // ── Web mining response ───────────────────────────────────────────────────

    /// <summary>
    /// Handles a confirmed browser-based mining detection.
    /// Called by WebMiningDetector.WebMiningConfirmed event.
    ///
    /// Priority of actions:
    ///   1. BlockDomain  — block the mining domain via hosts file
    ///   2. TerminateTab — kill only the specific renderer/tab process
    ///   3. TerminateRenderer — kill the renderer process group
    ///   4. Alert/log   — in Monitor mode, always just log
    ///
    /// NOTE: TerminateBrowser (killing the entire browser) is only used as
    /// a last resort and is NOT the default action, to avoid user session loss.
    /// Windows is NEVER shut down for a web mining event alone.
    /// </summary>
    public void HandleWebMining(WebMiningCorrelation correlation)
    {
        if (correlation is null) return;

        // BUG-06 FIX: Use string key — eliminates integer overflow for large PIDs
        var cooldownKey = $"{correlation.ProcessId}:web";
        if (_webActedOn.TryGetValue(cooldownKey, out var last) &&
            (DateTime.UtcNow - last) < ActionCooldown)
        {
            _logger.Debug("ResponseEngine",
                $"WebMining PID={correlation.ProcessId} within cooldown — skipping.");
            return;
        }

        _logger.Warning("ResponseEngine",
            $"WEB_MINING_RESPONSE: PID={correlation.ProcessId} " +
            $"Name={correlation.ProcessName} " +
            $"Confidence={correlation.Confidence} " +
            $"Action={correlation.RecommendedAction} " +
            $"Domain={correlation.MiningDomain} " +
            $"TabPID={correlation.TabProcessId}");

        switch (correlation.RecommendedAction)
        {
            case WebMiningAction.Alert:
                // Log only — no action
                _logger.Info("ResponseEngine",
                    $"Web mining alert (monitor mode): {correlation.Evidence}");
                break;

            case WebMiningAction.BlockDomain:
                if (!string.IsNullOrWhiteSpace(correlation.MiningDomain))
                {
                    TryBlockWebMiningDomain(correlation.MiningDomain, correlation.Evidence);
                }
                break;

            case WebMiningAction.TerminateTab when D.Mode != OperatingMode.Monitor:
                // Kill just the tab renderer — preserves user's other browser tabs
                if (correlation.TabProcessId.HasValue)
                {
                    TryTerminateBrowserRenderer(
                        correlation.TabProcessId.Value,
                        correlation.ProcessName,
                        "browser tab renderer (web miner)");
                }
                // Also block domain if we have one
                if (!string.IsNullOrWhiteSpace(correlation.MiningDomain))
                    TryBlockWebMiningDomain(correlation.MiningDomain, correlation.Evidence);
                break;

            case WebMiningAction.TerminateRenderer when D.Mode != OperatingMode.Monitor:
                // Kill the renderer process — a bit broader than just tab
                if (correlation.TabProcessId.HasValue)
                {
                    TryTerminateBrowserRenderer(
                        correlation.TabProcessId.Value,
                        correlation.ProcessName,
                        "browser renderer process (web miner)");
                }
                if (!string.IsNullOrWhiteSpace(correlation.MiningDomain))
                    TryBlockWebMiningDomain(correlation.MiningDomain, correlation.Evidence);
                break;

            case WebMiningAction.TerminateBrowser when D.Mode == OperatingMode.Emergency:
                // Last resort: kill entire browser (only in Emergency mode)
                _logger.Warning("ResponseEngine",
                    $"Emergency mode: terminating entire browser PID={correlation.ProcessId}");
                TryTerminateBrowserRenderer(
                    correlation.ProcessId,
                    correlation.ProcessName,
                    "browser (last resort — web miner)");
                break;

            case WebMiningAction.BlockConnection:
                // Log that a block is needed; full firewall API integration is future work
                _logger.Warning("ResponseEngine",
                    $"CONNECTION_BLOCK_REQUESTED: PID={correlation.ProcessId} " +
                    $"Domain={correlation.MiningDomain}");
                break;
        }

        _webActedOn[cooldownKey] = DateTime.UtcNow;
    }

    private void TryBlockWebMiningDomain(string domain, string evidence)
    {
        try
        {
            var hostsPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"drivers\etc\hosts");

            // Avoid duplicate entries
            var existing = System.IO.File.ReadAllText(hostsPath);
            if (existing.Contains(domain, StringComparison.OrdinalIgnoreCase))
            {
                _logger.Debug("ResponseEngine", $"Domain already blocked: {domain}");
                return;
            }

            var entry = $"\n# CoinShield [{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] web mining blocked\n0.0.0.0 {domain}\n";
            System.IO.File.AppendAllText(hostsPath, entry);

            _logger.Warning("ResponseEngine",
                $"DOMAIN_BLOCKED: {domain} | Evidence: {evidence}");
        }
        catch (Exception ex)
        {
            _logger.Error("ResponseEngine",
                $"Failed to block domain {domain}: {ex.Message}");
        }
    }

    private void TryTerminateBrowserRenderer(int pid, string processName, string description)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);

            if (proc.HasExited)
            {
                _logger.Debug("ResponseEngine",
                    $"Browser renderer PID={pid} already exited.");
                return;
            }

            // Kill only the specific renderer, NOT the process tree
            // This preserves the main browser and other tabs
            proc.Kill(entireProcessTree: false);

            _logger.Warning("ResponseEngine",
                $"BROWSER_RENDERER_TERMINATED: PID={pid} Name={processName} " +
                $"Description={description}");
        }
        catch (ArgumentException)
        {
            _logger.Debug("ResponseEngine", $"Renderer PID={pid} not found — already exited.");
        }
        catch (Exception ex)
        {
            _logger.Error("ResponseEngine",
                $"Failed to terminate renderer PID={pid}: {ex.Message}");
        }
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    private void TryTerminateProcess(DetectionResult result)
    {
        try
        {
            using var proc = Process.GetProcessById(result.Pid);

            // Final sanity check: process is still running
            if (proc.HasExited)
            {
                _logger.Info("ResponseEngine",
                    $"PID={result.Pid} already exited — no termination needed.");
                return;
            }

            proc.Kill(entireProcessTree: false);
            _logger.ProcessTerminated(result.Pid, result.ProcessName);

            _logger.Info("ResponseEngine",
                $"Mining process terminated: PID={result.Pid} Name={result.ProcessName}");
        }
        catch (ArgumentException)
        {
            _logger.Info("ResponseEngine",
                $"PID={result.Pid} not found — may have already exited.");
        }
        catch (Exception ex)
        {
            _logger.Error("ResponseEngine",
                $"Failed to terminate PID={result.Pid}: {ex.Message}");
        }
    }

    private void InitiateShutdown(DetectionResult result)
    {
        _logger.ShutdownInitiated(result);

        int graceSecs = Math.Max(0, R.ShutdownGraceSeconds);
        _logger.Warning("ResponseEngine",
            $"EMERGENCY SHUTDOWN in {graceSecs} seconds. " +
            $"Mining confirmed: PID={result.Pid} Score={result.Score.Total}");

        // Grace period — give Event Log a moment to flush
        if (graceSecs > 0)
            Thread.Sleep(TimeSpan.FromSeconds(Math.Min(graceSecs, 60)));

        try
        {
            // /f = force, /t = timeout (0 = immediate), /c = comment in event log
            var psi = new ProcessStartInfo("shutdown.exe",
                $"/s /f /t 0 /c \"CoinShield: Cryptocurrency mining detected\"")
            {
                CreateNoWindow         = true,
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };

            using var shutdownProc = Process.Start(psi);
            shutdownProc?.WaitForExit(5000);
        }
        catch (Exception ex)
        {
            _logger.Error("ResponseEngine",
                $"Shutdown command failed: {ex.Message}");
        }
    }

    private void LogIncident(DetectionResult result)
    {
        var snap = result.ProcessSnapshot;
        _logger.Error("ResponseEngine",
            $"CONFIRMED MINING — INCIDENT RECORDED\n" +
            $"PID={result.Pid}  Name={result.ProcessName}\n" +
            $"Path={snap?.Path}\n" +
            $"MiningScore={result.Score.Total}  " +
            $"AIConfidence={result.Score.AiConfidence:F2}  " +
            $"StrongIndicators={result.Score.StrongIndicatorCount}\n" +
            $"Mode={D.Mode}  Terminate={R.TerminateMiningProcess}  " +
            $"EmergencyShutdown={R.EmergencyShutdown}");
    }

    private string WriteEvidence(DetectionResult result)
    {
        var snap = result.ProcessSnapshot;
        var gpu  = result.GpuSnapshot;

        var evidence = new IncidentEvidence
        {
            Timestamp = DateTime.UtcNow,
            Process   = new IncidentEvidence.ProcessInfo
            {
                Pid             = result.Pid,
                Name            = result.ProcessName,
                Path            = snap?.Path ?? string.Empty,
                CommandLine     = snap?.CommandLine ?? string.Empty,
                Parent          = snap?.ParentName ?? string.Empty,
                Sha256          = snap?.Sha256 ?? string.Empty,
                Publisher       = snap?.Publisher ?? string.Empty,
                Username        = snap?.Username ?? string.Empty,
                LifetimeMinutes = snap?.Lifetime.TotalMinutes ?? 0,
            },
            System    = new IncidentEvidence.SystemInfo
            {
                CpuPercent  = snap?.CpuPercent ?? 0,
                GpuPercent  = snap?.GpuUsage   ?? 0,
                VramPercent = gpu?.VramPercent  ?? 0,
                MemoryMb    = snap?.MemoryMb    ?? 0,
            },
            Scores    = new IncidentEvidence.ScoreInfo
            {
                MiningScore      = result.Score.Total,
                AiConfidence     = result.Score.AiConfidence,
                StrongIndicators = result.Score.StrongIndicatorCount,
                RiskLevel        = result.Score.Level.ToString(),
            },
            Decision  = result.State.ToString(),
            Action    = DetermineActionString(),
        };

        evidence.Network.AddRange(result.SuspiciousConnections);
        evidence.PersistenceEntries.AddRange(result.PersistenceEntries);
        evidence.Evidence.AddRange(result.Evidence);

        return _logger.WriteIncident(evidence);
    }

    private string DetermineActionString()
    {
        if (D.Mode == OperatingMode.Monitor)           return "MONITOR_ONLY";
        if (R.EmergencyShutdown)                       return "SHUTDOWN";
        if (R.TerminateMiningProcess)                  return "TERMINATE";
        return "LOGGED";
    }
}
