using System;
using System.Diagnostics;
using CoinShield.Configuration;
using CoinShield.Models;

namespace CoinShield.Logging;

// ─────────────────────────────────────────────────────────────────────────────
//  Windows Event Log categories
// ─────────────────────────────────────────────────────────────────────────────

public enum CoinShieldEventId
{
    ServiceStarted        = 1000,
    ServiceStopped        = 1001,
    ServiceError          = 1002,
    ServiceDegraded       = 1003,

    ProcessDetected       = 2000,
    SuspiciousActivity    = 2001,
    AiWorkloadDetected    = 2002,
    MiningDetected        = 2003,

    ActionTaken           = 3000,
    ProcessTerminated     = 3001,
    ShutdownInitiated     = 3002,

    ConfigLoaded          = 4000,
    ConfigError           = 4001,
    AllowlistLoaded       = 4002,

    DetectionError        = 5000,
}

// ─────────────────────────────────────────────────────────────────────────────
//  EventLogger — writes to the Windows Application Event Log
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Writes structured entries to the Windows Event Log under the "CoinShield" source.
/// All output is headless — no console, no UI.
/// </summary>
public sealed class EventLogger : IDisposable
{
    private const string SourceName = "CoinShield";
    private const string LogName    = "Application";

    private readonly LoggingConfig _cfg;
    private EventLog?              _log;
    private bool                   _disposed;

    public EventLogger(LoggingConfig cfg)
    {
        _cfg = cfg ?? throw new ArgumentNullException(nameof(cfg));
        TryInitialise();
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    private void TryInitialise()
    {
        if (!_cfg.EventLog) return;

        try
        {
            if (!EventLog.SourceExists(SourceName))
                EventLog.CreateEventSource(SourceName, LogName);

            _log = new EventLog(LogName)
            {
                Source = SourceName
            };
        }
        catch (Exception ex)
        {
            // If the service doesn't have rights to create the source yet,
            // the installer should have pre-created it.  Log nothing and
            // continue — the JsonLogger will capture everything.
            Debug.WriteLine($"[CoinShield] EventLog init failed: {ex.Message}");
        }
    }

    // ── Public write methods ──────────────────────────────────────────────────

    public void ServiceStarted(OperatingMode mode)
    {
        Write(EventLogEntryType.Information, CoinShieldEventId.ServiceStarted,
            $"CoinShield service started successfully.\r\n" +
            $"Protection mode: ACTIVE\r\n" +
            $"Detection engine: BEHAVIORAL\r\n" +
            $"Operating mode: {mode}");
    }

    public void ServiceStopped()
    {
        Write(EventLogEntryType.Information, CoinShieldEventId.ServiceStopped,
            "CoinShield service stopped.");
    }

    public void ServiceError(string message, Exception? ex = null)
    {
        var text = ex is null ? message : $"{message}\r\n{ex}";
        Write(EventLogEntryType.Error, CoinShieldEventId.ServiceError, text);
    }

    public void ServiceDegraded(string reason)
    {
        Write(EventLogEntryType.Warning, CoinShieldEventId.ServiceDegraded,
            $"CoinShield entered degraded mode.\r\nReason: {reason}");
    }

    public void SuspiciousActivity(DetectionResult result)
    {
        var snap = result.ProcessSnapshot;
        Write(EventLogEntryType.Warning, CoinShieldEventId.SuspiciousActivity,
            $"Suspicious compute workload detected.\r\n" +
            $"PID={result.Pid}  Name={result.ProcessName}\r\n" +
            $"GPU={snap?.GpuUsage:F0}%  CPU={snap?.CpuPercent:F0}%\r\n" +
            $"Risk={result.Score.Total}  State={result.State}\r\n" +
            $"Reasons: {string.Join("; ", result.Score.Reasons)}");
    }

    public void AiWorkloadDetected(DetectionResult result)
    {
        var snap = result.ProcessSnapshot;
        Write(EventLogEntryType.Information, CoinShieldEventId.AiWorkloadDetected,
            $"Legitimate AI/ML workload identified — no action taken.\r\n" +
            $"PID={result.Pid}  Name={result.ProcessName}\r\n" +
            $"AIConfidence={result.Score.AiConfidence:P0}  " +
            $"GPU={snap?.GpuUsage:F0}%");
    }

    public void MiningDetected(DetectionResult result)
    {
        Write(EventLogEntryType.Error, CoinShieldEventId.MiningDetected,
            $"Cryptocurrency mining behavior confirmed.\r\n" +
            $"PID={result.Pid}  Name={result.ProcessName}\r\n" +
            $"MiningScore={result.Score.Total}  " +
            $"AIConfidence={result.Score.AiConfidence:F2}  " +
            $"StrongIndicators={result.Score.StrongIndicatorCount}\r\n" +
            $"Evidence: {string.Join("; ", result.Evidence)}");
    }

    public void ProcessTerminated(int pid, string name)
    {
        Write(EventLogEntryType.Warning, CoinShieldEventId.ProcessTerminated,
            $"Mining process terminated.\r\nPID={pid}  Name={name}");
    }

    public void ShutdownInitiated(DetectionResult result)
    {
        Write(EventLogEntryType.Error, CoinShieldEventId.ShutdownInitiated,
            $"EMERGENCY: Machine shutdown initiated by CoinShield.\r\n" +
            $"PID={result.Pid}  Name={result.ProcessName}\r\n" +
            $"MiningScore={result.Score.Total}  " +
            $"AIConfidence={result.Score.AiConfidence:F2}  " +
            $"StrongIndicators={result.Score.StrongIndicatorCount}");
    }

    public void ConfigLoaded(string filePath)
    {
        Write(EventLogEntryType.Information, CoinShieldEventId.ConfigLoaded,
            $"Configuration loaded successfully from: {filePath}");
    }

    public void ConfigError(string message)
    {
        Write(EventLogEntryType.Error, CoinShieldEventId.ConfigError,
            $"Configuration error: {message}");
    }

    public void DetectionError(string message, Exception? ex = null)
    {
        var text = ex is null ? message : $"{message}\r\nException: {ex.GetType().Name}: {ex.Message}";
        Write(EventLogEntryType.Warning, CoinShieldEventId.DetectionError, text);
    }

    // ── Generic entry point ───────────────────────────────────────────────────

    // ── Generic entry point (BUG-13 FIX: use correct event IDs) ─────────────
    public void Info(string message)    => Write(EventLogEntryType.Information, CoinShieldEventId.ProcessDetected,    message);
    public void Warning(string message) => Write(EventLogEntryType.Warning,     CoinShieldEventId.DetectionError,     message);
    public void Error(string message)   => Write(EventLogEntryType.Error,        CoinShieldEventId.ServiceError,       message);

    // ── Core write ────────────────────────────────────────────────────────────

    private void Write(EventLogEntryType type, CoinShieldEventId id, string message)
    {
        if (!_cfg.EventLog || _log is null) return;

        // Respect verbosity setting
        if (type == EventLogEntryType.Information && _cfg.Verbosity < 2) return;
        if (type == EventLogEntryType.Warning      && _cfg.Verbosity < 1) return;

        try
        {
            // EventLog messages are capped at ~32 KB; truncate gracefully.
            const int maxLen = 31000;
            if (message.Length > maxLen)
                message = message[..maxLen] + "\r\n[truncated]";

            _log.WriteEntry(message, type, (int)id);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[CoinShield] EventLog write failed: {ex.Message}");
        }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _log?.Dispose();
    }
}
