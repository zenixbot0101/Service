using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using CoinShield.Configuration;
using CoinShield.Core;
using CoinShield.Service;

// ─────────────────────────────────────────────────────────────────────────────
//  CoinShield.Service — entry point
//
//  Headless Windows Service.  No console, no GUI, no tray icon.
//  Status communicated exclusively through:
//    ✓ Windows Event Log  (source: "CoinShield")
//    ✓ JSON log files     (%ProgramData%\CoinShield\Logs)
//
//  New in v1.1:
//    ✓ Windows Server 2022 / 2025 compatible
//    ✓ Server Core (headless install) compatible
//    ✓ Google Cloud Platform VM: reads instance metadata at startup
//    ✓ GCP metadata key "coinshield-mode" overrides config.json mode
// ─────────────────────────────────────────────────────────────────────────────

var baseDir    = AppContext.BaseDirectory;
var configPath = Path.Combine(baseDir, "config.json");

// ── Step 1: Detect cloud environment and Windows Server edition ───────────────
// This runs before config load so GCP metadata can override the mode setting.
var cloud = new CloudEnvironment();
using var initCts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(10));
try
{
    await cloud.InitializeAsync(initCts.Token);
}
catch
{
    // Metadata probe timed out or failed — continue with on-premises defaults.
}

// ── Step 2: Load and validate configuration ───────────────────────────────────
CoinShieldConfig config;
try
{
    config = CoinShieldConfig.Load(configPath);
}
catch (ConfigurationException ex)
{
    Console.Error.WriteLine($"[CoinShield] FATAL: Configuration error: {ex.Message}");
    cloud.Dispose();
    return 1;
}

// Resolve default log directory
if (string.IsNullOrWhiteSpace(config.Paths.LogDirectory))
{
    config.Paths.LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CoinShield", "Logs");
}

// ── Step 3: Apply GCP metadata overrides ─────────────────────────────────────
// Operator can set per-VM operating mode via GCP instance metadata without
// editing config.json:
//   gcloud compute instances add-metadata <VM> --metadata coinshield-mode=Enforcement
if (cloud.IsGcp && cloud.GcpMetadata?.CoinShieldMode is { } gcpMode)
{
    if (Enum.TryParse<OperatingMode>(gcpMode, ignoreCase: true, out var parsedMode))
    {
        config.Detection.Mode = parsedMode;
        // Also enable termination automatically when Enforcement/Emergency set via GCP
        if (parsedMode is OperatingMode.Enforcement or OperatingMode.Emergency)
            config.Response.TerminateMiningProcess = true;
        if (parsedMode == OperatingMode.Emergency)
            config.Response.EmergencyShutdown = true;
    }
}

// Apply cloud environment settings from config
if (config.Cloud.Enabled)
{
    // On GCP, use structured JSON logging preferred over colorised console
    config.Logging.JsonLog = true;

    // Increase persistence scan interval on cloud VMs to reduce WMI overhead
    if (cloud.IsCloud && config.Cloud.ReduceWmiOverheadOnCloud)
    {
        config.Monitoring.PersistenceScanIntervalSeconds =
            Math.Max(config.Monitoring.PersistenceScanIntervalSeconds, 60);
    }
}

// ── Step 4: Build and run the generic host ─────────────────────────────────────
try
{
    var builder = Host.CreateDefaultBuilder(args);

    // Run as a Windows Service — no console window
    builder.UseWindowsService(options =>
    {
        options.ServiceName = ServiceHost.ServiceName;
    });

    builder.ConfigureLogging((_, logging) =>
    {
        logging.ClearProviders();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows Event Log: always enabled, Warning+ level
            // Works on Server Core, Server 2022, Server 2025 identically.
            logging.AddEventLog(new EventLogSettings
            {
                SourceName = ServiceHost.ServiceName,
                LogName    = "Application",
                Filter     = (_, level) => level >= LogLevel.Warning,
            });
        }

#if DEBUG
        // Debug console only in non-Server-Core debug builds
        if (!cloud.IsServerCore)
            logging.AddDebug();
#endif
    });

    builder.ConfigureServices((_, services) =>
    {
        // Register CloudEnvironment as singleton so Worker and analyzers can use it
        services.AddSingleton(cloud);
        services.AddCoinShield(config);
    });

    await builder.Build().RunAsync();
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[CoinShield] FATAL: Host terminated unexpectedly: {ex}");
    cloud.Dispose();
    return 2;
}
