using System;
using Microsoft.Extensions.DependencyInjection;
using CoinShield.Configuration;
using CoinShield.Core;
using CoinShield.Logging;

namespace CoinShield.Service;

/// <summary>
/// Extension method that registers the full CoinShield dependency graph.
/// Extracted from Program.cs so it can be reused in integration tests.
///
/// v1.1:
///   - CloudEnvironment registered as singleton from Program.cs before this call.
///   - On Windows Server Core with HeadlessOnly mode, browser correlation is
///     disabled (no browsers run on Server Core).
///   - GCP metadata-driven mode override applied before DI wiring.
/// </summary>
internal static class ServiceRegistration
{
    internal static IServiceCollection AddCoinShield(
        this IServiceCollection services,
        CoinShieldConfig config)
    {
        // ── Shared config ─────────────────────────────────────────────────────
        services.AddSingleton(config);

        // ── Logging facade ────────────────────────────────────────────────────
        services.AddSingleton(sp => new CoinShieldLogger(
            config.Logging,
            config.Paths.LogDirectory));

        // ── Allowlist ─────────────────────────────────────────────────────────
        services.AddSingleton(sp => new AllowlistEngine(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>()));

        // ── Analyzers ─────────────────────────────────────────────────────────
        services.AddSingleton(sp => new CpuAnalyzer(
            sp.GetRequiredService<CoinShieldConfig>().Monitoring,
            sp.GetRequiredService<CoinShieldLogger>()));

        services.AddSingleton(sp => new GpuAnalyzer(
            sp.GetRequiredService<CoinShieldConfig>().Monitoring,
            sp.GetRequiredService<CoinShieldLogger>()));

        services.AddSingleton(sp => new ProcessAnalyzer(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>(),
            sp.GetRequiredService<AllowlistEngine>()));

        services.AddSingleton(sp => new NetworkAnalyzer(
            sp.GetRequiredService<CoinShieldConfig>().Monitoring,
            sp.GetRequiredService<CoinShieldLogger>()));

        services.AddSingleton(sp => new PersistenceAnalyzer(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>()));

        // ── Web Mining subsystem ──────────────────────────────────────────────
        // Load mining-domains.json from assembly directory (resolved at runtime)
        services.AddSingleton(sp =>
        {
            var cfg        = sp.GetRequiredService<CoinShieldConfig>();
            var domainFile = System.IO.Path.IsPathRooted(cfg.WebMining.MiningDomainsFile)
                ? cfg.WebMining.MiningDomainsFile
                : System.IO.Path.Combine(
                    System.IO.Path.GetDirectoryName(
                        System.Reflection.Assembly.GetExecutingAssembly().Location) ?? string.Empty,
                    cfg.WebMining.MiningDomainsFile);
            return new DomainReputationEngine(domainFile);
        });

        services.AddSingleton(sp => new DnsAnalyzer(
            sp.GetRequiredService<DomainReputationEngine>()));

        // BrowserAnalyzer: always registered; disabled at tick level on Server Core
        services.AddSingleton(sp => new BrowserAnalyzer());

        services.AddSingleton(sp => new ProcessResurrectionDetector(
            sp.GetRequiredService<CoinShieldLogger>()));

        services.AddSingleton(sp =>
        {
            var cloud = sp.GetService<CloudEnvironment>();
            var cfg   = sp.GetRequiredService<CoinShieldConfig>();

            // Disable browser correlation on Server Core HeadlessOnly —
            // no browsers are present on Windows Server Core installations.
            if (cloud?.IsServerCore == true &&
                cfg.Cloud.ServerCoreMode.Equals("HeadlessOnly",
                    StringComparison.OrdinalIgnoreCase))
            {
                cfg.WebMining.EnableBrowserCorrelation = false;
            }

            return new WebMiningDetector(
                cfg,
                sp.GetRequiredService<CoinShieldLogger>(),
                sp.GetRequiredService<DnsAnalyzer>(),
                sp.GetRequiredService<BrowserAnalyzer>(),
                sp.GetRequiredService<DomainReputationEngine>());
        });

        // ── Scoring / correlation / response ──────────────────────────────────
        services.AddSingleton(sp => new RiskScorer(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>()));

        services.AddSingleton(sp => new CorrelationEngine(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>()));

        services.AddSingleton(sp => new ResponseEngine(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>(),
            sp.GetRequiredService<CorrelationEngine>(),
            sp.GetRequiredService<ProcessResurrectionDetector>()));

        // ── Detection engine ──────────────────────────────────────────────────
        services.AddSingleton(sp => new DetectionEngine(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>(),
            sp.GetRequiredService<ProcessAnalyzer>(),
            sp.GetRequiredService<CpuAnalyzer>(),
            sp.GetRequiredService<GpuAnalyzer>(),
            sp.GetRequiredService<NetworkAnalyzer>(),
            sp.GetRequiredService<PersistenceAnalyzer>(),
            sp.GetRequiredService<AllowlistEngine>(),
            sp.GetRequiredService<RiskScorer>(),
            sp.GetRequiredService<CorrelationEngine>(),
            sp.GetRequiredService<WebMiningDetector>(),
            sp.GetRequiredService<ProcessResurrectionDetector>()));

        // BYPASS-01: Wire NetworkAnalyzer → DnsAnalyzer so TCP connections feed
        // loopback-proxy and DoH detection layers.
        services.AddSingleton<INetworkDnsWiring>(sp =>
        {
            sp.GetRequiredService<NetworkAnalyzer>()
              .SetDnsAnalyzer(sp.GetRequiredService<DnsAnalyzer>());
            return new NetworkDnsWiringNoop();
        });

        // ── Hosted worker ─────────────────────────────────────────────────────
        services.AddHostedService(sp => new Worker(
            sp.GetRequiredService<CoinShieldConfig>(),
            sp.GetRequiredService<CoinShieldLogger>(),
            sp.GetRequiredService<AllowlistEngine>(),
            sp.GetRequiredService<DetectionEngine>(),
            sp.GetRequiredService<ResponseEngine>(),
            sp.GetRequiredService<WebMiningDetector>(),
            sp.GetRequiredService<INetworkDnsWiring>(),
            sp.GetService<CloudEnvironment>())); // optional — null in unit tests

        return services;
    }
}

// Marker to trigger the DnsAnalyzer→NetworkAnalyzer wiring via DI resolution
internal interface INetworkDnsWiring { }
internal sealed class NetworkDnsWiringNoop : INetworkDnsWiring { }
