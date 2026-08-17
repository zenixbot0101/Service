using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  WindowsServerEdition
// ─────────────────────────────────────────────────────────────────────────────

public enum WindowsServerEdition
{
    NotServer,
    Server2016,
    Server2019,
    Server2022,
    Server2025,
    ServerOther,
    ServerCore,   // any edition running without Desktop Experience
}

// ─────────────────────────────────────────────────────────────────────────────
//  CloudProvider
// ─────────────────────────────────────────────────────────────────────────────

public enum CloudProvider
{
    Unknown,
    GoogleCloud,
    Azure,
    Aws,
    OnPremises,
}

// ─────────────────────────────────────────────────────────────────────────────
//  GcpInstanceMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>Subset of GCP instance metadata relevant to CoinShield.</summary>
public sealed class GcpInstanceMetadata
{
    public string ProjectId    { get; init; } = string.Empty;
    public string InstanceId   { get; init; } = string.Empty;
    public string InstanceName { get; init; } = string.Empty;
    public string Zone         { get; init; } = string.Empty;
    public string MachineType  { get; init; } = string.Empty;
    public string ServiceAccount { get; init; } = string.Empty;
    /// <summary>
    /// Custom metadata key "coinshield-mode" set on the GCP VM.
    /// Allows per-VM operating mode override without editing config.json.
    /// E.g.: gcloud compute instances add-metadata VM --metadata coinshield-mode=Enforcement
    /// </summary>
    public string? CoinShieldMode    { get; init; }
    /// <summary>
    /// Custom metadata key "coinshield-config-gcs" — GCS URL of a config.json override.
    /// E.g.: gs://my-bucket/coinshield/config.json
    /// </summary>
    public string? CoinShieldConfigGcs { get; init; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CloudEnvironment
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Detects the cloud environment and Windows Server edition the service is
/// running in. Results are cached after the first call.
///
/// Key responsibilities:
///   - Identify GCP, Azure, or AWS via metadata server probes
///   - Read GCP instance metadata (project, zone, custom metadata)
///   - Detect Windows Server 2022 / 2025 vs Desktop
///   - Detect Server Core (no Desktop Experience) vs Full GUI
///   - Expose environment flags consumed by Program.cs, Worker.cs,
///     and the installer
///
/// Thread-safe: all public members are safe to call from multiple threads
/// after InitializeAsync() completes.
/// </summary>
public sealed class CloudEnvironment : IDisposable
{
    // ── GCP metadata server ───────────────────────────────────────────────────
    // The metadata server is only reachable from within a GCP VM.
    // It requires the "Metadata-Flavor: Google" header on every request.
    private const string GcpMetadataBase    = "http://metadata.google.internal/computeMetadata/v1";
    private const string GcpMetadataFlavor  = "Metadata-Flavor";
    private const string GcpMetadataValue   = "Google";
    private const int    MetadataTimeoutMs  = 2000; // stay well under GCP's 5 s default

    // ── Azure / AWS identity endpoints ────────────────────────────────────────
    private const string AzureImdsUrl  = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
    private const string AwsImdsUrl    = "http://169.254.169.254/latest/meta-data/ami-id";

    private readonly HttpClient _http;
    private bool _initialised;
    private bool _disposed;

    // ── Cached results ────────────────────────────────────────────────────────
    public CloudProvider         Provider        { get; private set; } = CloudProvider.Unknown;
    public GcpInstanceMetadata?  GcpMetadata     { get; private set; }
    public WindowsServerEdition  ServerEdition   { get; private set; } = WindowsServerEdition.NotServer;
    public bool                  IsServerCore    { get; private set; }
    public bool                  IsWindowsServer => ServerEdition != WindowsServerEdition.NotServer;
    public bool                  IsGcp           => Provider == CloudProvider.GoogleCloud;
    public bool                  IsCloud         => Provider != CloudProvider.OnPremises &&
                                                    Provider != CloudProvider.Unknown;

    public CloudEnvironment()
    {
        // Short timeout HTTP client — metadata server probes must never block service startup
        _http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(MetadataTimeoutMs) };
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    /// <summary>
    /// Probes metadata endpoints and reads OS info.
    /// Must be called once at startup before reading any properties.
    /// Safe to call multiple times (idempotent after first call).
    /// </summary>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        if (_initialised) return;

        // OS detection first (synchronous, no I/O)
        DetectWindowsServerEdition();
        DetectServerCore();

        // Cloud detection (network I/O — limited to MetadataTimeoutMs each)
        await DetectCloudProviderAsync(ct).ConfigureAwait(false);

        if (IsGcp)
            await ReadGcpMetadataAsync(ct).ConfigureAwait(false);

        _initialised = true;
    }

    // ── OS detection ─────────────────────────────────────────────────────────

    private void DetectWindowsServerEdition()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            ServerEdition = WindowsServerEdition.NotServer;
            return;
        }

        try
        {
            // ProductName examples:
            //   "Windows Server 2022 Standard"
            //   "Windows Server 2025 Datacenter"
            //   "Windows 11 Pro"
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);

            var productName  = key?.GetValue("ProductName")  as string ?? string.Empty;
            var buildLabEx   = key?.GetValue("BuildLabEx")   as string ?? string.Empty;
            var currentBuild = key?.GetValue("CurrentBuild")  as string ?? string.Empty;

            if (!productName.Contains("Server", StringComparison.OrdinalIgnoreCase))
            {
                ServerEdition = WindowsServerEdition.NotServer;
                return;
            }

            // Map build number → edition
            // Server 2016: 14393,  Server 2019: 17763
            // Server 2022: 20348,  Server 2025: 26100+
            if (int.TryParse(currentBuild, out int build))
            {
                ServerEdition = build switch
                {
                    >= 26100 => WindowsServerEdition.Server2025,
                    >= 20348 => WindowsServerEdition.Server2022,
                    >= 17763 => WindowsServerEdition.Server2019,
                    >= 14393 => WindowsServerEdition.Server2016,
                    _        => WindowsServerEdition.ServerOther,
                };
            }
            else
            {
                ServerEdition = WindowsServerEdition.ServerOther;
            }
        }
        catch
        {
            ServerEdition = WindowsServerEdition.NotServer;
        }
    }

    private void DetectServerCore()
    {
        if (!IsWindowsServer)
        {
            IsServerCore = false;
            return;
        }

        try
        {
            // Server Core has no shell (explorer.exe) and no Desktop Experience.
            // Registry key InstallationType = "Server Core" vs "Server" (full).
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);

            var installationType = key?.GetValue("InstallationType") as string ?? string.Empty;

            // "Server Core" = headless, "Server" = with Desktop Experience,
            // "Nano Server" = even more minimal
            IsServerCore = installationType.Equals("Server Core", StringComparison.OrdinalIgnoreCase)
                        || installationType.Equals("Nano Server",  StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            IsServerCore = false;
        }
    }

    // ── Cloud provider detection ──────────────────────────────────────────────

    private async Task DetectCloudProviderAsync(CancellationToken ct)
    {
        // GCP check: metadata server responds with "Metadata-Flavor: Google" header
        if (await IsGcpAsync(ct).ConfigureAwait(false))
        {
            Provider = CloudProvider.GoogleCloud;
            return;
        }

        // Azure check: IMDS responds with JSON containing "azure"
        if (await IsAzureAsync(ct).ConfigureAwait(false))
        {
            Provider = CloudProvider.Azure;
            return;
        }

        // AWS check: IMDS returns AMI ID
        if (await IsAwsAsync(ct).ConfigureAwait(false))
        {
            Provider = CloudProvider.Aws;
            return;
        }

        Provider = CloudProvider.OnPremises;
    }

    private async Task<bool> IsGcpAsync(CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"{GcpMetadataBase}/instance/id");
            req.Headers.Add(GcpMetadataFlavor, GcpMetadataValue);

            using var cts  = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(MetadataTimeoutMs);

            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);

            // Must return 200 AND the header must be present
            return resp.IsSuccessStatusCode &&
                   resp.Headers.TryGetValues(GcpMetadataFlavor, out var vals) &&
                   string.Join(",", vals).Contains(GcpMetadataValue, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> IsAzureAsync(CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, AzureImdsUrl);
            req.Headers.Add("Metadata", "true");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(MetadataTimeoutMs);
            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return false;
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return body.Contains("azure", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private async Task<bool> IsAwsAsync(CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(MetadataTimeoutMs);
            using var resp = await _http.GetAsync(AwsImdsUrl, cts.Token).ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── GCP metadata reader ───────────────────────────────────────────────────

    private async Task ReadGcpMetadataAsync(CancellationToken ct)
    {
        try
        {
            string projectId    = await GetGcpValueAsync("project/project-id",              ct);
            string instanceId   = await GetGcpValueAsync("instance/id",                     ct);
            string instanceName = await GetGcpValueAsync("instance/name",                   ct);
            string zone         = await GetGcpValueAsync("instance/zone",                   ct);
            string machineType  = await GetGcpValueAsync("instance/machine-type",           ct);
            string sa           = await GetGcpValueAsync("instance/service-accounts/default/email", ct);

            // Custom metadata keys — set with:
            //   gcloud compute instances add-metadata <VM> \
            //     --metadata coinshield-mode=Enforcement,coinshield-config-gcs=gs://bucket/config.json
            string? csMode      = await GetGcpCustomMetaAsync("coinshield-mode",       ct);
            string? csConfigGcs = await GetGcpCustomMetaAsync("coinshield-config-gcs", ct);

            // Simplify zone: "projects/123/zones/us-central1-a" → "us-central1-a"
            var zoneParts = zone.Split('/');
            var shortZone = zoneParts.Length > 0 ? zoneParts[^1] : zone;

            // Simplify machine-type similarly
            var mtParts  = machineType.Split('/');
            var shortMt  = mtParts.Length > 0 ? mtParts[^1] : machineType;

            GcpMetadata = new GcpInstanceMetadata
            {
                ProjectId          = projectId,
                InstanceId         = instanceId,
                InstanceName       = instanceName,
                Zone               = shortZone,
                MachineType        = shortMt,
                ServiceAccount     = sa,
                CoinShieldMode     = string.IsNullOrWhiteSpace(csMode)      ? null : csMode.Trim(),
                CoinShieldConfigGcs= string.IsNullOrWhiteSpace(csConfigGcs) ? null : csConfigGcs.Trim(),
            };
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"CloudEnvironment: GCP metadata read failed: {ex.Message}");
            // Non-fatal — service continues with null GcpMetadata
        }
    }

    private async Task<string> GetGcpValueAsync(string path, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"{GcpMetadataBase}/{path}");
            req.Headers.Add(GcpMetadataFlavor, GcpMetadataValue);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(MetadataTimeoutMs);

            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            return resp.IsSuccessStatusCode
                ? (await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false)).Trim()
                : string.Empty;
        }
        catch { return string.Empty; }
    }

    private async Task<string?> GetGcpCustomMetaAsync(string key, CancellationToken ct)
    {
        var val = await GetGcpValueAsync($"instance/attributes/{key}", ct).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(val) ? null : val;
    }

    // ── Summary helpers ───────────────────────────────────────────────────────

    /// <summary>Human-readable environment summary for Event Log / startup banner.</summary>
    public string GetSummary()
    {
        var os = ServerEdition switch
        {
            WindowsServerEdition.Server2025 => "Windows Server 2025",
            WindowsServerEdition.Server2022 => "Windows Server 2022",
            WindowsServerEdition.Server2019 => "Windows Server 2019",
            WindowsServerEdition.Server2016 => "Windows Server 2016",
            WindowsServerEdition.ServerOther => "Windows Server (other)",
            WindowsServerEdition.NotServer  => RuntimeInformation.OSDescription,
            _                               => RuntimeInformation.OSDescription,
        };

        if (IsServerCore) os += " (Server Core — headless)";

        var cloud = Provider switch
        {
            CloudProvider.GoogleCloud  => $"Google Cloud Platform (project={GcpMetadata?.ProjectId} " +
                                          $"zone={GcpMetadata?.Zone} type={GcpMetadata?.MachineType})",
            CloudProvider.Azure        => "Microsoft Azure",
            CloudProvider.Aws          => "Amazon Web Services",
            CloudProvider.OnPremises   => "On-Premises",
            _                          => "Unknown",
        };

        return $"OS: {os} | Cloud: {cloud}";
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _http.Dispose();
    }
}
