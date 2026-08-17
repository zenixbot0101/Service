using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CoinShield.Watchdog;

// ─────────────────────────────────────────────────────────────────────────────
//  WatchdogWorker
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Monitors the health of the CoinShield Windows Service.
///
/// IMPORTANT DESIGN CONSTRAINT (spec §34):
/// The watchdog performs ONE function: check if CoinShield.Service is running.
/// It does NOT:
///   ✗ Make any mining detection decisions
///   ✗ Access process lists independently
///   ✗ Trigger shutdowns
///   ✗ Duplicate the detection engine
///
/// If the main service is stopped or in an unexpected state, the watchdog
/// logs the condition to the Windows Event Log and optionally attempts to
/// restart it via the Service Control Manager.
///
/// Recovery is delegated to the SCM (configured in install.ps1) where
/// possible.  The watchdog acts only as a secondary alerting mechanism.
/// </summary>
public sealed class WatchdogWorker : BackgroundService
{
    private const string TargetServiceName = "CoinShield";

    private readonly ILogger<WatchdogWorker> _logger;

    // Check interval — 30 seconds is sufficient; we don't need sub-second precision
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

    // Suppress repeated alerts for the same condition
    private ServiceControllerStatus? _lastKnownStatus;
    private int _alertCount;
    private const int MaxAlertsPerIncident = 3;

    public WatchdogWorker(ILogger<WatchdogWorker> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "CoinShield Watchdog started. Monitoring service: {ServiceName}",
            TargetServiceName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                CheckService();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Watchdog check failed.");
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("CoinShield Watchdog stopped.");
    }

    // ── Service health check ──────────────────────────────────────────────────

    private void CheckService()
    {
        ServiceControllerStatus status;
        bool serviceExists = true;

        try
        {
            using var sc = new ServiceController(TargetServiceName);
            status = sc.Status;
        }
        catch (InvalidOperationException)
        {
            // Service not installed
            serviceExists = false;
            status        = ServiceControllerStatus.Stopped;
        }

        if (!serviceExists)
        {
            if (_lastKnownStatus != ServiceControllerStatus.Stopped)
            {
                _logger.LogError(
                    "CoinShield service '{ServiceName}' is NOT installed. " +
                    "Mining protection is inactive.",
                    TargetServiceName);
                _lastKnownStatus = ServiceControllerStatus.Stopped;
                _alertCount      = 1;
            }
            return;
        }

        // Service is healthy — reset alert counter
        if (status == ServiceControllerStatus.Running)
        {
            if (_lastKnownStatus != ServiceControllerStatus.Running)
            {
                _logger.LogInformation(
                    "CoinShield service '{ServiceName}' is running. Protection is active.",
                    TargetServiceName);
                _alertCount = 0;
            }
            _lastKnownStatus = ServiceControllerStatus.Running;
            return;
        }

        // Service is not running — alert (but don't flood the Event Log)
        if (_alertCount < MaxAlertsPerIncident || status != _lastKnownStatus)
        {
            _logger.LogWarning(
                "CoinShield service '{ServiceName}' is in unexpected state: {Status}. " +
                "Mining protection may be inactive. The SCM will attempt restart if configured.",
                TargetServiceName, status);

            _alertCount++;
        }

        _lastKnownStatus = status;
    }
}
