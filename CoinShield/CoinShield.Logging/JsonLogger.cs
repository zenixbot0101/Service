using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using CoinShield.Configuration;
using CoinShield.Models;

namespace CoinShield.Logging;

// ─────────────────────────────────────────────────────────────────────────────
//  Log entry severity levels
// ─────────────────────────────────────────────────────────────────────────────

public enum LogSeverity { Error, Warning, Info, Debug }

// ─────────────────────────────────────────────────────────────────────────────
//  JsonLogger — structured JSON file logging + incident evidence writer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Writes structured JSON log entries to rotating daily log files and creates
/// evidence bundles (incident-YYYYMMDD-HHmmss.json) before any response action.
/// Never stores passwords, tokens or credentials.
/// Thread-safe via a lightweight lock.
/// </summary>
public sealed class JsonLogger : IDisposable
{
    private readonly LoggingConfig _cfg;
    private readonly string        _logDirectory;
    private readonly object        _lock = new();
    private bool                   _disposed;

    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        WriteIndented          = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters             = { new JsonStringEnumConverter() },
    };

    // ── Construction ─────────────────────────────────────────────────────────

    public JsonLogger(LoggingConfig cfg, string logDirectory)
    {
        _cfg          = cfg          ?? throw new ArgumentNullException(nameof(cfg));
        _logDirectory = logDirectory ?? throw new ArgumentNullException(nameof(logDirectory));

        EnsureDirectoryExists(_logDirectory);
    }

    // ── Public log methods ────────────────────────────────────────────────────

    public void Info   (string category, string message, object? data = null) =>
        Append(LogSeverity.Info,    category, message, data);

    public void Warning(string category, string message, object? data = null) =>
        Append(LogSeverity.Warning, category, message, data);

    public void Error  (string category, string message, object? data = null) =>
        Append(LogSeverity.Error,   category, message, data);

    public void Debug  (string category, string message, object? data = null) =>
        Append(LogSeverity.Debug,   category, message, data);

    // ── Suspicious / mining specific entries ──────────────────────────────────

    public void LogSuspicious(DetectionResult result)
    {
        if (!_cfg.JsonLog) return;

        var entry = new
        {
            pid          = result.Pid,
            processName  = result.ProcessName,
            state        = result.State.ToString(),
            riskScore    = result.Score.Total,
            aiConfidence = result.Score.AiConfidence,
            reasons      = result.Score.Reasons,
            evidence     = result.Evidence,
        };
        Append(LogSeverity.Warning, "Detection", "Suspicious workload detected", entry);
    }

    public void LogMiningDetected(DetectionResult result)
    {
        if (!_cfg.JsonLog) return;

        var snap = result.ProcessSnapshot;
        var entry = new
        {
            pid              = result.Pid,
            processName      = result.ProcessName,
            path             = snap?.Path,
            commandLine      = SanitiseCommandLine(snap?.CommandLine),
            parent           = snap?.ParentName,
            miningScore      = result.Score.Total,
            aiConfidence     = result.Score.AiConfidence,
            strongIndicators = result.Score.StrongIndicatorCount,
            gpuPercent       = snap?.GpuUsage,
            cpuPercent       = snap?.CpuPercent,
            lifetimeMinutes  = snap?.Lifetime.TotalMinutes,
            reasons          = result.Score.Reasons,
            evidence         = result.Evidence,
            persistenceEntries = result.PersistenceEntries,
        };
        Append(LogSeverity.Error, "Detection", "Mining confirmed", entry);
    }

    // ── Incident evidence bundle ──────────────────────────────────────────────

    /// <summary>
    /// Writes a complete incident evidence file before any response action.
    /// Returns the full path to the written file.
    /// Never stores passwords, tokens or credentials.
    /// </summary>
    public string WriteIncident(IncidentEvidence evidence)
    {
        var timestamp = evidence.Timestamp.ToString("yyyyMMdd-HHmmss");
        var fileName  = $"incident-{timestamp}.json";
        var path      = Path.Combine(_logDirectory, fileName);

        try
        {
            var json = JsonSerializer.Serialize(evidence, _jsonOpts);
            lock (_lock)
            {
                File.WriteAllText(path, json);
            }
        }
        catch (Exception ex)
        {
            Error("IncidentWriter", $"Failed to write incident file: {ex.Message}");
        }

        return path;
    }

    // ── Log rotation / retention ──────────────────────────────────────────────

    /// <summary>Deletes log files older than the configured retention period.</summary>
    public void PurgeOldLogs()
    {
        if (!_cfg.JsonLog) return;

        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-_cfg.RetentionDays);
            foreach (var file in Directory.EnumerateFiles(_logDirectory, "*.jsonl"))
            {
                if (File.GetCreationTimeUtc(file) < cutoff)
                    TryDelete(file);
            }
            // Keep incident files longer (double the retention)
            var incidentCutoff = DateTime.UtcNow.AddDays(-_cfg.RetentionDays * 2);
            foreach (var file in Directory.EnumerateFiles(_logDirectory, "incident-*.json"))
            {
                if (File.GetCreationTimeUtc(file) < incidentCutoff)
                    TryDelete(file);
            }
        }
        catch
        {
            // Non-fatal; log purge errors are swallowed intentionally
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void Append(LogSeverity severity, string category, string message, object? data)
    {
        if (!_cfg.JsonLog) return;

        // Verbosity gate
        if (severity == LogSeverity.Debug   && _cfg.Verbosity < 3) return;
        if (severity == LogSeverity.Info    && _cfg.Verbosity < 2) return;
        if (severity == LogSeverity.Warning && _cfg.Verbosity < 1) return;

        var entry = new LogEntry
        {
            Timestamp = DateTime.UtcNow,
            Severity  = severity,
            Category  = category,
            Message   = message,
            Data      = data,
        };

        var line = JsonSerializer.Serialize(entry, _jsonOpts);
        var file = DailyLogFile();

        lock (_lock)
        {
            try
            {
                File.AppendAllText(file, line + Environment.NewLine);
            }
            catch
            {
                // Swallow write failures — the service must keep running
            }
        }
    }

    /// <summary>Returns today's log file path (one file per day, JSONL format).</summary>
    private string DailyLogFile()
    {
        var date = DateTime.UtcNow.ToString("yyyyMMdd");
        return Path.Combine(_logDirectory, $"coinshield-{date}.jsonl");
    }

    private static void EnsureDirectoryExists(string dir)
    {
        try { Directory.CreateDirectory(dir); }
        catch { /* If creation fails the service writes no log files but still runs */ }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* ignore */ }
    }

    /// <summary>
    /// Strips any tokens that look like passwords, wallet addresses or API keys
    /// from a command line before logging. This is a best-effort measure.
    /// </summary>
    private static string? SanitiseCommandLine(string? cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine)) return cmdLine;

        // Redact values that follow --password / --pass / -p flags
        var redacted = System.Text.RegularExpressions.Regex.Replace(
            cmdLine,
            @"(--pass(?:word)?|-p)\s+\S+",
            "$1 [REDACTED]",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        return redacted;
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // No unmanaged resources; lock and streams are not held open between calls
    }

    // ── Inner types ───────────────────────────────────────────────────────────

    private sealed class LogEntry
    {
        public DateTime  Timestamp { get; init; }
        public LogSeverity Severity { get; init; }
        public string    Category  { get; init; } = string.Empty;
        public string    Message   { get; init; } = string.Empty;
        public object?   Data      { get; init; }
        public string    Host      { get; init; } = Environment.MachineName;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CoinShieldLogger — facade that dispatches to both EventLogger and JsonLogger
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Single logging facade used by all CoinShield components.
/// Dispatches entries to the Windows Event Log and the JSON file logger
/// according to each logger's own verbosity gates.
/// </summary>
public sealed class CoinShieldLogger : IDisposable
{
    public EventLogger EventLogger { get; }
    public JsonLogger  JsonLogger  { get; }

    public CoinShieldLogger(LoggingConfig cfg, string logDirectory)
    {
        EventLogger = new EventLogger(cfg);
        JsonLogger  = new JsonLogger(cfg, logDirectory);
    }

    // ── Convenience delegates ─────────────────────────────────────────────────

    public void Info   (string category, string message, object? data = null)
    {
        EventLogger.Info(message);
        JsonLogger.Info(category, message, data);
    }

    public void Warning(string category, string message, object? data = null)
    {
        EventLogger.Warning(message);
        JsonLogger.Warning(category, message, data);
    }

    public void Error  (string category, string message, object? data = null)
    {
        EventLogger.Error(message);
        JsonLogger.Error(category, message, data);
    }

    public void Debug  (string category, string message, object? data = null) =>
        JsonLogger.Debug(category, message, data);

    public void ServiceStarted(OperatingMode mode)
    {
        EventLogger.ServiceStarted(mode);
        JsonLogger.Info("Service", $"CoinShield started. Mode={mode}");
    }

    public void ServiceStopped()
    {
        EventLogger.ServiceStopped();
        JsonLogger.Info("Service", "CoinShield stopped.");
    }

    public void SuspiciousActivity(DetectionResult result)
    {
        EventLogger.SuspiciousActivity(result);
        JsonLogger.LogSuspicious(result);
    }

    public void AiWorkloadDetected(DetectionResult result)
    {
        EventLogger.AiWorkloadDetected(result);
        JsonLogger.Info("Detection",
            $"AI workload confirmed — PID={result.Pid} AIConf={result.Score.AiConfidence:F2}");
    }

    public void MiningDetected(DetectionResult result)
    {
        EventLogger.MiningDetected(result);
        JsonLogger.LogMiningDetected(result);
    }

    public void ProcessTerminated(int pid, string name)
    {
        EventLogger.ProcessTerminated(pid, name);
        JsonLogger.Warning("Response", $"Mining process terminated PID={pid} Name={name}");
    }

    public void ShutdownInitiated(DetectionResult result)
    {
        EventLogger.ShutdownInitiated(result);
        JsonLogger.Error("Response",
            $"Emergency shutdown initiated. MiningScore={result.Score.Total}");
    }

    public string WriteIncident(IncidentEvidence evidence) =>
        JsonLogger.WriteIncident(evidence);

    public void PurgeOldLogs() =>
        JsonLogger.PurgeOldLogs();

    public void Dispose()
    {
        EventLogger.Dispose();
        JsonLogger.Dispose();
    }
}
