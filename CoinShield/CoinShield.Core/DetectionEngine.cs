using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CoinShield.Configuration;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  DetectionEngine
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Top-level orchestrator for the CoinShield detection pipeline.
///
/// Coordinates all analyzers according to their configured intervals,
/// passes data through the RiskScorer and CorrelationEngine, and raises
/// events for the ResponseEngine via the <see cref="MiningConfirmed"/> callback.
///
/// Monitoring loop intervals:
///   CPU:            1 s  (fast, lightweight perf counter)
///   GPU:            1 s  (perf counter, slightly heavier)
///   Processes:      2 s  (WMI enumeration)
///   Network+CmdLine:5 s  (P/Invoke + WMI)
///   Persistence:   30 s  (registry + filesystem)
///
/// Deep analysis (hash, full command-line re-check) is triggered only when
/// a process reaches the Suspicious state to keep idle CPU below 1%.
/// </summary>
public sealed class DetectionEngine : IDisposable
{
    // ── Dependencies ──────────────────────────────────────────────────────────
    private readonly CoinShieldConfig    _cfg;
    private readonly CoinShieldLogger    _logger;
    private readonly ProcessAnalyzer     _processAnalyzer;
    private readonly CpuAnalyzer         _cpuAnalyzer;
    private readonly GpuAnalyzer         _gpuAnalyzer;
    private readonly NetworkAnalyzer     _networkAnalyzer;
    private readonly PersistenceAnalyzer _persistenceAnalyzer;
    private readonly AllowlistEngine     _allowlist;
    private readonly RiskScorer          _scorer;
    private readonly CorrelationEngine   _correlator;
    private readonly WebMiningDetector   _webMiningDetector;
    private readonly ProcessResurrectionDetector _resurrectionDetector;

    // ── Timing state ──────────────────────────────────────────────────────────
    private DateTime _lastProcessScan       = DateTime.MinValue;
    private DateTime _lastNetworkScan       = DateTime.MinValue;
    private DateTime _lastPersistenceScan   = DateTime.MinValue;
    private DateTime _lastCachePrune        = DateTime.MinValue;

    // Last persistence scan results (reused between deep analyses)
    private List<PersistenceEntry> _lastPersistenceEntries = new();

    // Last process snapshots (keyed by PID)
    private Dictionary<int, ProcessSnapshot> _lastSnapshots = new();

    // ── Callbacks ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Raised when a process reaches the ConfirmedMining state with all
    /// criteria satisfied.  Subscribers (the ResponseEngine) must not call
    /// back into DetectionEngine from this handler.
    /// </summary>
    public event Action<DetectionResult>? MiningConfirmed;

    /// <summary>
    /// Raised when a process transitions to AiWorkload state.
    /// Informational only — no action is taken.
    /// </summary>
    public event Action<DetectionResult>? AiWorkloadIdentified;

    /// <summary>
    /// Raised when any process changes state (for logging/monitoring dashboards).
    /// </summary>
    public event Action<DetectionResult>? StateChanged;

    private bool _disposed;

    // ── Construction ─────────────────────────────────────────────────────────

    public DetectionEngine(
        CoinShieldConfig    cfg,
        CoinShieldLogger    logger,
        ProcessAnalyzer     processAnalyzer,
        CpuAnalyzer         cpuAnalyzer,
        GpuAnalyzer         gpuAnalyzer,
        NetworkAnalyzer     networkAnalyzer,
        PersistenceAnalyzer persistenceAnalyzer,
        AllowlistEngine     allowlist,
        RiskScorer          scorer,
        CorrelationEngine   correlator,
        WebMiningDetector   webMiningDetector,
        ProcessResurrectionDetector resurrectionDetector)
    {
        _cfg                  = cfg                  ?? throw new ArgumentNullException(nameof(cfg));
        _logger               = logger               ?? throw new ArgumentNullException(nameof(logger));
        _processAnalyzer      = processAnalyzer      ?? throw new ArgumentNullException(nameof(processAnalyzer));
        _cpuAnalyzer          = cpuAnalyzer          ?? throw new ArgumentNullException(nameof(cpuAnalyzer));
        _gpuAnalyzer          = gpuAnalyzer          ?? throw new ArgumentNullException(nameof(gpuAnalyzer));
        _networkAnalyzer      = networkAnalyzer      ?? throw new ArgumentNullException(nameof(networkAnalyzer));
        _persistenceAnalyzer  = persistenceAnalyzer  ?? throw new ArgumentNullException(nameof(persistenceAnalyzer));
        _allowlist            = allowlist            ?? throw new ArgumentNullException(nameof(allowlist));
        _scorer               = scorer               ?? throw new ArgumentNullException(nameof(scorer));
        _correlator           = correlator           ?? throw new ArgumentNullException(nameof(correlator));
        _webMiningDetector    = webMiningDetector    ?? throw new ArgumentNullException(nameof(webMiningDetector));
        _resurrectionDetector = resurrectionDetector ?? throw new ArgumentNullException(nameof(resurrectionDetector));
    }

    /// <summary>
    /// Called by the Worker every second (the base tick interval).
    /// Each analyzer runs at its own sub-interval.
    /// </summary>
    public void Tick(CancellationToken ct)
    {
        if (_disposed || ct.IsCancellationRequested) return;

        var now = DateTime.UtcNow;

        // ── 1. CPU sample (every 1 s) ─────────────────────────────────────────
        double systemCpu = 0;
        try { systemCpu = _cpuAnalyzer.SampleSystemCpu(); }
        catch (Exception ex) { _logger.Debug("DetectionEngine", $"CPU sample: {ex.Message}"); }

        // ── 2. GPU sample (every 1 s) ─────────────────────────────────────────
        List<GpuSnapshot> gpuSnapshots = new();
        try { gpuSnapshots = _gpuAnalyzer.Sample(); }
        catch (Exception ex) { _logger.Debug("DetectionEngine", $"GPU sample: {ex.Message}"); }

        var primaryGpu = gpuSnapshots.FirstOrDefault();

        // ── 3. Process enumeration (every processIntervalSeconds) ─────────────
        bool processTime = (now - _lastProcessScan).TotalSeconds
                         >= _cfg.Monitoring.ProcessIntervalSeconds;

        if (processTime)
        {
            _lastProcessScan = now;
            try { RunProcessScan(systemCpu, primaryGpu, ct); }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                _logger.Error("DetectionEngine", $"Process scan error: {ex.Message}", ex);
            }
        }

        // ── 4. Web mining detection tick (every networkIntervalSeconds) ────────
        bool webTime = (now - _lastNetworkScan).TotalSeconds
                      >= _cfg.Monitoring.NetworkIntervalSeconds;
        if (webTime)
        {
            try { _webMiningDetector.Tick(ct); }
            catch (Exception ex)
            {
                _logger.Debug("DetectionEngine", $"WebMining tick: {ex.Message}");
            }
        }

        // ── 4. Periodic cache pruning (every 60 s) ────────────────────────────
        if ((now - _lastCachePrune).TotalSeconds >= 60)
        {
            _lastCachePrune = now;
            try
            {
                var activePids = _lastSnapshots.Keys;
                _cpuAnalyzer.PruneDeadProcesses(activePids);
                _correlator.PruneDeadProcesses(activePids);
                var activePaths = _lastSnapshots.Values.Select(s => s.Path);
                _processAnalyzer.PruneCaches(activePaths);
                _networkAnalyzer.PruneDnsCache();
                _logger.JsonLogger.PurgeOldLogs();
            }
            catch (Exception ex)
            {
                _logger.Debug("DetectionEngine", $"Cache prune: {ex.Message}");
            }
        }
    }

    // ── Process scan ─────────────────────────────────────────────────────────

    private void RunProcessScan(
        double       systemCpu,
        GpuSnapshot? primaryGpu,
        CancellationToken ct)
    {
        var now       = DateTime.UtcNow;
        var snapshots = _processAnalyzer.EnumerateAll();
        _lastSnapshots = snapshots.ToDictionary(s => s.Pid);

        // Feed resurrection detector with current process list
        if (_cfg.WebMining.EnableResurrectionDetection)
        {
            try
            {
                var procList = snapshots.Select(s => (s.Pid, s.Name, s.Path, s.ParentPid));
                _resurrectionDetector.UpdateProcessList(procList);
            }
            catch (Exception ex)
            {
                _logger.Debug("DetectionEngine", $"Resurrection update: {ex.Message}");
            }
        }

        // Network scan (every networkIntervalSeconds)
        NetworkSnapshot? networkSnapshot = null;
        bool networkTime = (now - _lastNetworkScan).TotalSeconds
                         >= _cfg.Monitoring.NetworkIntervalSeconds;
        if (networkTime)
        {
            _lastNetworkScan = now;
            try { networkSnapshot = _networkAnalyzer.Sample(); }
            catch (Exception ex)
            {
                _logger.Debug("DetectionEngine", $"Network scan: {ex.Message}");
            }
        }

        // Persistence scan (every persistenceScanIntervalSeconds)
        bool persistenceTime = (now - _lastPersistenceScan).TotalSeconds
                             >= _cfg.Monitoring.PersistenceScanIntervalSeconds;
        if (persistenceTime)
        {
            _lastPersistenceScan = now;
            try { _lastPersistenceEntries = _persistenceAnalyzer.ScanAll(); }
            catch (Exception ex)
            {
                _logger.Debug("DetectionEngine", $"Persistence scan: {ex.Message}");
            }
        }

        foreach (var snap in snapshots)
        {
            if (ct.IsCancellationRequested) return;
            EvaluateProcess(snap, primaryGpu, networkSnapshot, systemCpu);
        }
    }

    // ── Per-process evaluation ────────────────────────────────────────────────

    private void EvaluateProcess(
        ProcessSnapshot snap,
        GpuSnapshot?    gpuSnap,
        NetworkSnapshot? networkSnap,
        double          systemCpu)
    {
        try
        {
            // Sample per-process CPU
            snap.CpuPercent = _cpuAnalyzer.SampleProcessCpu(snap.Pid);

            // Attach GPU attribution
            snap.GpuUsage    = _gpuAnalyzer.GetProcessGpuUsage(snap.Pid);
            snap.VramUsageMb = _gpuAnalyzer.GetProcessVramUsage(snap.Pid);

            // Current correlation state to decide analysis depth
            var currentState = _correlator.GetState(snap.Pid);
            bool deepMode    = currentState >= DetectionState.Suspicious
                            || snap.Lifetime.TotalSeconds
                               >= _cfg.Monitoring.DeepAnalysisMinLifetimeSeconds;

            // Hash computation (expensive — only for suspicious or long-running processes)
            if (deepMode && string.IsNullOrWhiteSpace(snap.Sha256) && !string.IsNullOrWhiteSpace(snap.Path))
            {
                try { snap.Sha256 = _processAnalyzer.ComputeHash(snap.Path); }
                catch { /* non-fatal */ }
            }

            // Allowlist check
            var allowlistResult = _allowlist.Evaluate(snap);

            // Command-line analysis (every networkIntervalSeconds when suspicious)
            CommandLineAnalysis? cmdAnalysis = null;
            if (deepMode || currentState >= DetectionState.Suspicious)
            {
                cmdAnalysis = _processAnalyzer.AnalyseCommandLine(snap.CommandLine, snap.Name);
            }

            // Process tree analysis
            var treeAnalysis = _processAnalyzer.AnalyseProcessTree(snap);

            // Network analysis for this process
            NetworkAnalysis? netAnalysis = null;
            if (networkSnap is not null)
            {
                snap.NetworkConnectionCount = networkSnap.ForProcess(snap.Pid).Count();
                if (deepMode || snap.NetworkConnectionCount > 0)
                    netAnalysis = _networkAnalyzer.AnalyseProcess(snap.Pid, networkSnap);
            }

            // GPU sustained minutes
            double gpuSustained = _gpuAnalyzer.SustainedMinutes(0, _cfg.Detection.GpuUtilizationThreshold);
            bool   vramStable   = _gpuAnalyzer.IsVramStable();

            // Persistence entries for this process
            var processPersistence = deepMode
                ? _persistenceAnalyzer.FindEntriesForProcess(snap.Path, snap.Name)
                : _lastPersistenceEntries.Where(p => p.IsSuspicious
                    && p.Value.Contains(snap.Name, StringComparison.OrdinalIgnoreCase)).ToList();

            // ── Score ─────────────────────────────────────────────────────────
            var input = new ScoringInput
            {
                Process              = snap,
                Gpu                  = gpuSnap,
                Network              = netAnalysis,
                CmdLine              = cmdAnalysis,
                ProcessTree          = treeAnalysis,
                Allowlist            = allowlistResult,
                Persistence          = processPersistence,
                GpuSustainedMinutes  = gpuSustained,
                VramIsStable         = vramStable,
                SystemCpuPercent     = systemCpu,
                ResurrectionScore    = _cfg.WebMining.EnableResurrectionDetection
                    ? _resurrectionDetector.GetResurrectionScore(snap.Name)
                    : 0,
            };

            var score = _scorer.Score(input);

            // ── Correlate ─────────────────────────────────────────────────────
            var result = _correlator.Evaluate(
                snap.Pid, snap.Name, score,
                snap, gpuSnap, netAnalysis, processPersistence);

            // ── Dispatch events ───────────────────────────────────────────────
            if (result.State != result.PreviousState)
            {
                StateChanged?.Invoke(result);
                HandleStateTransition(result);
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("DetectionEngine",
                $"EvaluateProcess PID={snap.Pid} Name={snap.Name}: {ex.Message}");
        }
    }

    // ── State transition handler ──────────────────────────────────────────────

    private void HandleStateTransition(DetectionResult result)
    {
        switch (result.State)
        {
            case DetectionState.Suspicious:
                _logger.SuspiciousActivity(result);
                break;

            case DetectionState.AiWorkload:
                _logger.AiWorkloadDetected(result);
                AiWorkloadIdentified?.Invoke(result);
                break;

            case DetectionState.HighRisk:
                _logger.Warning("Detection",
                    $"HIGH_RISK: PID={result.Pid} Name={result.ProcessName} " +
                    $"Score={result.Score.Total} AI={result.Score.AiConfidence:F2}");
                break;

            case DetectionState.ConfirmedMining:
                if (!result.ConfirmationWindowPassed)
                {
                    // Safety net: should not happen, but log and skip
                    _logger.Warning("Detection",
                        $"ConfirmedMining state without window — holding. PID={result.Pid}");
                    return;
                }
                _logger.MiningDetected(result);
                MiningConfirmed?.Invoke(result);
                break;
        }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _processAnalyzer.Dispose();
        _cpuAnalyzer.Dispose();
        _gpuAnalyzer.Dispose();
        _networkAnalyzer.Dispose();
        _webMiningDetector.Dispose();
    }
}
