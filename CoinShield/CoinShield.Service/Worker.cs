using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using CoinShield.Configuration;
using CoinShield.Core;
using CoinShield.Logging;
using CoinShield.Models;

namespace CoinShield.Service;

/// <summary>
/// The .NET Worker that drives the detection loop.
/// Implements <see cref="BackgroundService"/> so the runtime manages its
/// lifetime as a Windows Service.
///
/// v1.1 additions:
///   - Accepts optional <see cref="CloudEnvironment"/> to log instance metadata
///     at startup (GCP project/zone/machine, Server 2022/2025, Server Core flag).
///   - On Server Core with HeadlessOnly mode, browser-related log messages are
///     suppressed (no browsers run on Server Core).
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly CoinShieldConfig    _cfg;
    private readonly CoinShieldLogger    _logger;
    private readonly AllowlistEngine     _allowlist;
    private readonly DetectionEngine     _engine;
    private readonly ResponseEngine      _response;
    private readonly WebMiningDetector   _webMining;
    private readonly INetworkDnsWiring   _networkDnsWiring;
    // Optional — null when CloudEnvironment not registered (e.g. unit tests)
    private readonly CloudEnvironment?   _cloud;

    // Degraded-mode tracking
    private int      _consecutiveFailures;
    private const int MaxConsecutiveFailures = 10;
    private bool     _degraded;

    // Base tick interval — 1 second
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(1);

    // ── Construction ─────────────────────────────────────────────────────────

    public Worker(
        CoinShieldConfig   cfg,
        CoinShieldLogger   logger,
        AllowlistEngine    allowlist,
        DetectionEngine    engine,
        ResponseEngine     response,
        WebMiningDetector  webMining,
        INetworkDnsWiring  networkDnsWiring,
        CloudEnvironment?  cloud = null)
    {
        _cfg              = cfg              ?? throw new ArgumentNullException(nameof(cfg));
        _logger           = logger           ?? throw new ArgumentNullException(nameof(logger));
        _allowlist        = allowlist        ?? throw new ArgumentNullException(nameof(allowlist));
        _engine           = engine           ?? throw new ArgumentNullException(nameof(engine));
        _response         = response         ?? throw new ArgumentNullException(nameof(response));
        _webMining        = webMining        ?? throw new ArgumentNullException(nameof(webMining));
        _networkDnsWiring = networkDnsWiring ?? throw new ArgumentNullException(nameof(networkDnsWiring));
        _cloud            = cloud; // optional — null is acceptable
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// <summary>Called when the Windows Service starts.</summary>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        // Write startup banner with OS / GCP metadata info
        ServiceHost.WriteStartupBanner(_logger, _cfg, _cloud);

        // Log environment summary separately so it's easy to find in Event Viewer
        if (_cloud != null && _cfg.Cloud.LogInstanceMetadataAtStartup)
        {
            _logger.Info("Worker", $"Environment: {_cloud.GetSummary()}");

            if (_cloud.IsServerCore)
                _logger.Info("Worker",
                    "Running on Windows Server Core — browser detection disabled, " +
                    "process/network/persistence detection active.");

            if (_cloud.IsGcp && _cloud.GcpMetadata is { } meta)
                _logger.Info("Worker",
                    $"GCP instance: project={meta.ProjectId} " +
                    $"name={meta.InstanceName} zone={meta.Zone} type={meta.MachineType}" +
                    (meta.CoinShieldMode != null
                        ? $" [mode override: {meta.CoinShieldMode}]"
                        : string.Empty));
        }

        _logger.ServiceStarted(_cfg.Detection.Mode);

        // Load allowlist before the first tick
        try
        {
            _allowlist.Load();
        }
        catch (Exception ex)
        {
            _logger.Error("Worker", $"Allowlist load failed: {ex.Message}");
        }

        // Wire response engine to detection events
        _engine.MiningConfirmed      += OnMiningConfirmed;
        _engine.AiWorkloadIdentified += OnAiWorkloadIdentified;
        _engine.StateChanged         += OnStateChanged;

        // Wire web mining events (skip on Server Core HeadlessOnly — no browsers)
        bool enableWebMiningEvents = !(_cloud?.IsServerCore == true &&
            _cfg.Cloud.ServerCoreMode.Equals("HeadlessOnly", StringComparison.OrdinalIgnoreCase));

        if (enableWebMiningEvents)
        {
            _webMining.WebMiningConfirmed  += OnWebMiningConfirmed;
            _webMining.WebMiningSuspicious += OnWebMiningSuspicious;
        }

        await base.StartAsync(cancellationToken);
    }

    /// <summary>Called when the Windows Service stops (shutdown, stop command, crash).</summary>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.ServiceStopped();

        // Detach events before shutdown
        _engine.MiningConfirmed      -= OnMiningConfirmed;
        _engine.AiWorkloadIdentified -= OnAiWorkloadIdentified;
        _engine.StateChanged         -= OnStateChanged;

        _webMining.WebMiningConfirmed  -= OnWebMiningConfirmed;
        _webMining.WebMiningSuspicious -= OnWebMiningSuspicious;

        await base.StopAsync(cancellationToken);
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.Info("Worker", "Detection loop started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            var tickStart = DateTime.UtcNow;

            if (_degraded)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken)
                          .ConfigureAwait(false);
                continue;
            }

            try
            {
                // BUG-10 FIX: Run the synchronous tick on the thread pool so
                // long WMI/SHA-256/GPU-counter operations don't block the async
                // loop and delay CancellationToken polling.
                await Task.Run(() => _engine.Tick(stoppingToken), stoppingToken)
                          .ConfigureAwait(false);

                _consecutiveFailures = 0;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _consecutiveFailures++;
                _logger.Error("Worker",
                    $"Detection tick failed ({_consecutiveFailures}/{MaxConsecutiveFailures}): " +
                    $"{ex.GetType().Name}: {ex.Message}");

                if (_consecutiveFailures >= MaxConsecutiveFailures)
                {
                    _degraded = true;
                    _logger.EventLogger.ServiceDegraded(
                        $"Too many consecutive tick failures ({_consecutiveFailures}). " +
                        "Detection paused — manual inspection required.");
                }
            }

            // Sleep for the remainder of the 1-second tick period
            var elapsed   = DateTime.UtcNow - tickStart;
            var remaining = TickInterval - elapsed;
            if (remaining > TimeSpan.Zero)
            {
                try
                {
                    await Task.Delay(remaining, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        _logger.Info("Worker", "Detection loop stopped.");
    }

    // ── Event handlers ────────────────────────────────────────────────────────

    private void OnMiningConfirmed(DetectionResult result)
    {
        try
        {
            // ResponseEngine re-verifies all gates independently before acting
            _response.Handle(result);
        }
        catch (Exception ex)
        {
            _logger.Error("Worker",
                $"ResponseEngine.Handle threw for PID={result.Pid}: {ex.Message}");
        }
    }

    private void OnAiWorkloadIdentified(DetectionResult result)
    {
        _logger.AiWorkloadDetected(result);
    }

    private void OnStateChanged(DetectionResult result)
    {
        // Log significant state transitions at appropriate verbosity
        switch (result.State)
        {
            case DetectionState.Suspicious:
                _logger.SuspiciousActivity(result);
                break;

            case DetectionState.HighRisk:
                _logger.Warning("StateChanged",
                    $"HIGH_RISK: PID={result.Pid} Name={result.ProcessName} " +
                    $"Score={result.Score.Total} " +
                    $"AI={result.Score.AiConfidence:F2} " +
                    $"StrongIndicators={result.Score.StrongIndicatorCount}");
                break;

            case DetectionState.Normal when result.PreviousState >= DetectionState.Suspicious:
                _logger.Info("StateChanged",
                    $"Process PID={result.Pid} returned to NORMAL from {result.PreviousState}.");
                break;
        }
    }

    private void OnWebMiningConfirmed(WebMiningCorrelation correlation)
    {
        try
        {
            _response.HandleWebMining(correlation);
        }
        catch (Exception ex)
        {
            _logger.Error("Worker",
                $"ResponseEngine.HandleWebMining threw for PID={correlation.ProcessId}: {ex.Message}");
        }
    }

    private void OnWebMiningSuspicious(WebMiningCorrelation correlation)
    {
        _logger.Warning("Worker",
            $"WEB_MINER_SUSPICIOUS: PID={correlation.ProcessId} " +
            $"Name={correlation.ProcessName} " +
            $"Confidence={correlation.Confidence} " +
            $"Evidence={correlation.Evidence}");
    }
}
