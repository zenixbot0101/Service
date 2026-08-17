using System;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using CoinShield.Watchdog;

// ─────────────────────────────────────────────────────────────────────────────
//  CoinShield.Watchdog — entry point
//
//  The watchdog monitors ONLY whether CoinShield.Service is alive.
//  It does NOT make any mining detection decisions.
//  It does NOT independently trigger any shutdown.
//
//  Architecture (spec §34):
//    Windows
//     ├── CoinShield.Service   (detection + response)
//     └── CoinShield.Watchdog  (service health monitor only)
// ─────────────────────────────────────────────────────────────────────────────

await Host.CreateDefaultBuilder(args)

    .UseWindowsService(options =>
    {
        options.ServiceName = "CoinShieldWatchdog";
    })

    .ConfigureLogging((_, logging) =>
    {
        logging.ClearProviders();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            logging.AddEventLog(new EventLogSettings
            {
                SourceName = "CoinShieldWatchdog",
                LogName    = "Application",
                Filter     = (_, level) => level >= LogLevel.Warning,
            });
        }

#if DEBUG
        logging.AddDebug();
#endif
    })

    .ConfigureServices((_, services) =>
    {
        services.AddHostedService<WatchdogWorker>();
    })

    .Build()
    .RunAsync();
