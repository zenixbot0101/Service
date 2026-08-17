using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using CoinShield.Configuration;
using CoinShield.Core;
using CoinShield.Logging;

namespace CoinShield.Service;

// ─────────────────────────────────────────────────────────────────────────────
//  ServiceHost — Windows Service metadata and recovery configuration helpers
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Provides constants and helper utilities related to the Windows Service
/// registration of CoinShield.
///
/// Now includes:
///   - Windows Server 2022 / 2025 edition detection
///   - Server Core (headless) detection
///   - GCP instance metadata exposure in startup banner
/// </summary>
public static class ServiceHost
{
    // ── Service identity constants ────────────────────────────────────────────

    public const string ServiceName    = "CoinShield";
    public const string DisplayName    = "CoinShield Anti-Mining Service";
    public const string Description    =
        "Monitors system behaviour to detect and optionally terminate " +
        "unauthorized cryptocurrency mining workloads. " +
        "Uses behavioral multi-signal analysis; does not rely on GPU usage alone.";
    public const string ExecutableName = "CoinShield.Service.exe";

    // ── Runtime status helpers ────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the current process is running inside a Windows Service
    /// context (i.e. not an interactive user session).
    /// </summary>
    public static bool IsRunningAsService()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        try
        {
            using var current = Process.GetCurrentProcess();
            return !Environment.UserInteractive;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the current status of the CoinShield Windows Service.
    /// Returns null if the service is not installed or the query fails.
    /// </summary>
    public static ServiceControllerStatus? QueryServiceStatus()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return null;

        try
        {
            using var sc = new ServiceController(ServiceName);
            return sc.Status;
        }
        catch
        {
            return null;
        }
    }

    // ── Startup banner (written to Event Log, never to console) ──────────────

    /// <summary>
    /// Writes the startup banner to the Windows Event Log.
    /// Includes OS edition, Server Core flag, and GCP instance info when running
    /// on Google Cloud Platform.
    /// Called from Worker.StartAsync after the logger is ready.
    /// </summary>
    public static void WriteStartupBanner(
        CoinShieldLogger  logger,
        CoinShieldConfig  cfg,
        CloudEnvironment? cloud = null)
    {
        var envSummary = cloud?.GetSummary()
            ?? RuntimeInformation.OSDescription;

        // Build GCP block only when relevant
        var gcpBlock = string.Empty;
        if (cloud?.IsGcp == true && cloud.GcpMetadata is { } meta)
        {
            gcpBlock =
                $"\r\nGCP Project:      {meta.ProjectId}" +
                $"\r\nGCP Instance:     {meta.InstanceName} ({meta.InstanceId})" +
                $"\r\nGCP Zone:         {meta.Zone}" +
                $"\r\nGCP Machine:      {meta.MachineType}" +
                (meta.CoinShieldMode != null
                    ? $"\r\nGCP Mode Override: {meta.CoinShieldMode}"
                    : string.Empty);
        }

        var serverCoreNote = cloud?.IsServerCore == true
            ? "\r\nServer Core:      YES (headless — Event Log only, no GUI)"
            : string.Empty;

        logger.EventLogger.Info(
            $"CoinShield Anti-Mining Service started.\r\n" +
            $"Version:           1.1.0\r\n" +
            $"Environment:       {envSummary}" +
            serverCoreNote +
            gcpBlock +
            $"\r\nProtection mode:   ACTIVE" +
            $"\r\nDetection engine:  BEHAVIORAL" +
            $"\r\nOperating mode:    {cfg.Detection.Mode}" +
            $"\r\nAI protection:     {(cfg.AiProtection.Enabled ? "ENABLED" : "DISABLED")}" +
            $"\r\nEmergency shutdown:{cfg.Response.EmergencyShutdown}" +
            $"\r\nTerminate miner:   {cfg.Response.TerminateMiningProcess}" +
            $"\r\nLog directory:     {cfg.Paths.LogDirectory}" +
            $"\r\nUI:                NONE (headless service)");
    }

    // ── sc.exe helper strings (used by install.ps1) ───────────────────────────

    /// <summary>
    /// Returns the sc.exe command arguments needed to configure service recovery.
    /// Spec §33: Restart after 10 s on first, second, and subsequent failures.
    /// </summary>
    public static string GetScFailureArgs() =>
        $"failure {ServiceName} reset= 86400 actions= restart/10000/restart/10000/restart/10000";
}

// ─────────────────────────────────────────────────────────────────────────────
//  ServiceHost — Windows Service metadata and recovery configuration helpers
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Provides constants and helper utilities related to the Windows Service
/// registration of CoinShield.
///
/// The actual hosting is done by Microsoft.Extensions.Hosting.WindowsServices
/// (via UseWindowsService() in Program.cs).  This class exists to centralise
/// service metadata and to provide programmatic helpers used by the installer
/// script (install.ps1 calls these values through the executable's --info flag).
///
/// Service metadata (spec §4):
///   Service name:  CoinShield
///   Display name:  CoinShield Anti-Mining Service
///   Startup type:  Automatic (Delayed Start)
///   Run account:   LocalSystem (or a dedicated low-privilege service account)
///   Recovery:      Restart after 10 s on first/second/subsequent failures
/// </summary>
public static class ServiceHost
{
    // ── Service identity constants ────────────────────────────────────────────

    public const string ServiceName    = "CoinShield";
    public const string DisplayName    = "CoinShield Anti-Mining Service";
    public const string Description    =
        "Monitors system behaviour to detect and optionally terminate " +
        "unauthorized cryptocurrency mining workloads. " +
        "Uses behavioral multi-signal analysis; does not rely on GPU usage alone.";
    public const string ExecutableName = "CoinShield.Service.exe";

    // ── Runtime status helpers ────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the current process is running inside a Windows Service
    /// context (i.e. not an interactive user session).
    /// </summary>
    public static bool IsRunningAsService()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        try
        {
            // HasExited check on parent: when parent is services.exe, we're a service
            using var current = Process.GetCurrentProcess();
            // A simpler and reliable approach: check if there is no interactive session
            return !Environment.UserInteractive;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the current status of the CoinShield Windows Service.
    /// Returns null if the service is not installed or the query fails.
    /// </summary>
    public static ServiceControllerStatus? QueryServiceStatus()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return null;

        try
        {
            using var sc = new ServiceController(ServiceName);
            return sc.Status;
        }
        catch
        {
            return null;
        }
    }

    // ── Startup banner (written to Event Log, never to console) ──────────────

    /// <summary>
    /// Writes the startup banner to the Windows Event Log.
    /// Called from Worker.StartAsync after the logger is ready.
    /// </summary>
    public static void WriteStartupBanner(CoinShieldLogger logger, CoinShieldConfig cfg)
    {
        logger.EventLogger.Info(
            $"CoinShield Anti-Mining Service started.\r\n" +
            $"Version:          1.0\r\n" +
            $"Protection mode:  ACTIVE\r\n" +
            $"Detection engine: BEHAVIORAL\r\n" +
            $"Operating mode:   {cfg.Detection.Mode}\r\n" +
            $"AI protection:    {(cfg.AiProtection.Enabled ? "ENABLED" : "DISABLED")}\r\n" +
            $"Emergency shutdown: {cfg.Response.EmergencyShutdown}\r\n" +
            $"Terminate miner:  {cfg.Response.TerminateMiningProcess}\r\n" +
            $"Log directory:    {cfg.Paths.LogDirectory}\r\n" +
            $"UI:               NONE (headless service)");
    }

    // ── sc.exe helper strings (used by install.ps1) ───────────────────────────

    /// <summary>
    /// Returns the sc.exe command arguments needed to configure service recovery.
    /// Spec §33: Restart after 10 s on first, second, and subsequent failures.
    /// </summary>
    public static string GetScFailureArgs() =>
        $"failure {ServiceName} reset= 86400 actions= restart/10000/restart/10000/restart/10000";
}
