using System;
using System.IO;
using System.Text.Json;

namespace CoinShield.Configuration;

// ─────────────────────────────────────────────────────────────────────────────
//  Root configuration object
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Top-level configuration for CoinShield.  Loaded from config.json at startup
/// and validated before use.  Never execute commands or download binaries from
/// values in this file.
/// </summary>
public sealed class CoinShieldConfig
{
    public MonitoringConfig   Monitoring   { get; set; } = new();
    public DetectionConfig    Detection    { get; set; } = new();
    public ScoringWeights     Scoring      { get; set; } = new();
    public AiProtectionConfig AiProtection { get; set; } = new();
    public ResponseConfig     Response     { get; set; } = new();
    public LoggingConfig      Logging      { get; set; } = new();
    public PathsConfig        Paths        { get; set; } = new();
    public WebMiningConfig    WebMining    { get; set; } = new();
    public CloudConfig        Cloud        { get; set; } = new();

    // ── Loader ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Loads and validates config.json from the given path.
    /// Throws <see cref="ConfigurationException"/> on validation failure.
    /// Never trusts values blindly — all fields are range-checked.
    /// </summary>
    public static CoinShieldConfig Load(string filePath)
    {
        if (!File.Exists(filePath))
            throw new ConfigurationException($"Configuration file not found: {filePath}");

        string json;
        try
        {
            json = File.ReadAllText(filePath);
        }
        catch (Exception ex)
        {
            throw new ConfigurationException($"Cannot read configuration file: {ex.Message}", ex);
        }

        CoinShieldConfig? cfg;
        try
        {
            cfg = JsonSerializer.Deserialize<CoinShieldConfig>(json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas         = true,
                    ReadCommentHandling         = JsonCommentHandling.Skip,
                });
        }
        catch (JsonException ex)
        {
            throw new ConfigurationException($"Malformed configuration JSON: {ex.Message}", ex);
        }

        if (cfg is null)
            throw new ConfigurationException("Configuration file produced a null result.");

        cfg.Validate();
        return cfg;
    }

    // ── Validation ────────────────────────────────────────────────────────────

    public void Validate()
    {
        Monitoring.Validate();
        Detection.Validate();
        Scoring.Validate();
        AiProtection.Validate();
        Response.Validate();
        Logging.Validate();
        WebMining.Validate();
        Cloud.Validate();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Monitoring intervals
// ─────────────────────────────────────────────────────────────────────────────

public sealed class MonitoringConfig
{
    /// <summary>CPU statistics refresh interval (seconds). Default 1.</summary>
    public int CpuIntervalSeconds     { get; set; } = 1;
    /// <summary>GPU statistics refresh interval (seconds). Default 1.</summary>
    public int GpuIntervalSeconds     { get; set; } = 1;
    /// <summary>Full process-list enumeration interval (seconds). Default 2.</summary>
    public int ProcessIntervalSeconds { get; set; } = 2;
    /// <summary>Command-line and network correlation interval (seconds). Default 5.</summary>
    public int NetworkIntervalSeconds { get; set; } = 5;
    /// <summary>Persistence-location scan interval (seconds). Default 30.</summary>
    public int PersistenceScanIntervalSeconds { get; set; } = 30;
    /// <summary>Minimum process lifetime (seconds) before deep analysis is triggered. Default 120.</summary>
    public int DeepAnalysisMinLifetimeSeconds { get; set; } = 120;

    public void Validate()
    {
        ConfigGuard.Positive(CpuIntervalSeconds,     nameof(CpuIntervalSeconds));
        ConfigGuard.Positive(GpuIntervalSeconds,     nameof(GpuIntervalSeconds));
        ConfigGuard.Positive(ProcessIntervalSeconds, nameof(ProcessIntervalSeconds));
        ConfigGuard.Positive(NetworkIntervalSeconds, nameof(NetworkIntervalSeconds));
        ConfigGuard.Positive(PersistenceScanIntervalSeconds, nameof(PersistenceScanIntervalSeconds));
        ConfigGuard.Positive(DeepAnalysisMinLifetimeSeconds, nameof(DeepAnalysisMinLifetimeSeconds));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Detection thresholds
// ─────────────────────────────────────────────────────────────────────────────

public sealed class DetectionConfig
{
    /// <summary>Score at which monitoring is increased. Default 30.</summary>
    public int SuspiciousThreshold { get; set; } = 30;
    /// <summary>Score at which deep analysis begins. Default 60.</summary>
    public int HighRiskThreshold   { get; set; } = 60;
    /// <summary>Minimum score before ConfirmedMining state is possible. Default 85.</summary>
    public int ConfirmedMiningThreshold { get; set; } = 85;
    /// <summary>Seconds the process must remain suspicious before action is allowed. Default 60.</summary>
    public int ConfirmationSeconds { get; set; } = 60;
    /// <summary>Independent strong-indicator count required before any response. Default 2.</summary>
    public int MinimumStrongIndicators { get; set; } = 2;
    /// <summary>GPU utilisation % threshold used as one partial signal only. Default 90.</summary>
    public double GpuUtilizationThreshold { get; set; } = 90.0;
    /// <summary>Sustained minutes at high GPU before the GPU-sustained score is awarded. Default 10.</summary>
    public int GpuSustainedMinutes { get; set; } = 10;
    /// <summary>Operating mode. Monitor / Enforcement / Emergency. Default Monitor.</summary>
    public OperatingMode Mode { get; set; } = OperatingMode.Monitor;

    public void Validate()
    {
        ConfigGuard.Range(SuspiciousThreshold,      1, 100, nameof(SuspiciousThreshold));
        ConfigGuard.Range(HighRiskThreshold,        1, 200, nameof(HighRiskThreshold));
        ConfigGuard.Range(ConfirmedMiningThreshold, 1, 300, nameof(ConfirmedMiningThreshold));
        ConfigGuard.Positive(ConfirmationSeconds,        nameof(ConfirmationSeconds));
        ConfigGuard.Range(MinimumStrongIndicators,  1, 10,  nameof(MinimumStrongIndicators));
        ConfigGuard.Positive(GpuSustainedMinutes,        nameof(GpuSustainedMinutes));

        if (SuspiciousThreshold >= HighRiskThreshold)
            throw new ConfigurationException(
                "SuspiciousThreshold must be less than HighRiskThreshold.");
        if (HighRiskThreshold >= ConfirmedMiningThreshold)
            throw new ConfigurationException(
                "HighRiskThreshold must be less than ConfirmedMiningThreshold.");
        if (GpuUtilizationThreshold is < 1.0 or > 100.0)
            throw new ConfigurationException(
                "GpuUtilizationThreshold must be between 1 and 100.");
    }
}

/// <summary>Service operating mode — controls how aggressively the response engine acts.</summary>
public enum OperatingMode
{
    /// <summary>Detect and log only.  No process termination.  No shutdown.  Safe default.</summary>
    Monitor,
    /// <summary>Terminate confirmed mining processes.  No shutdown.</summary>
    Enforcement,
    /// <summary>Terminate confirmed mining processes and initiate machine shutdown.</summary>
    Emergency,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Scoring weights (all configurable so admins can tune for their environment)
// ─────────────────────────────────────────────────────────────────────────────

public sealed class ScoringWeights
{
    // ── Additive (increase suspicion) ────────────────────────────────────────
    public int GpuSustained10Min       { get; set; } = 10;
    public int GpuSustained30Min       { get; set; } = 10;
    public int UnknownExecutable       { get; set; } = 15;
    public int UnsignedExecutable      { get; set; } = 10;
    public int SuspiciousPath          { get; set; } = 10;
    public int SuspiciousCommandLine   { get; set; } = 25;
    public int SuspiciousNetwork       { get; set; } = 25;
    public int MiningProtocol          { get; set; } = 30;
    public int SuspiciousPersistence   { get; set; } = 20;
    public int KnownMaliciousHash      { get; set; } = 100;

    // ── Subtractive mitigations (reduce suspicion) ────────────────────────────
    public int AiTrainingMitigation    { get; set; } = 40;
    public int TrustedApplication      { get; set; } = 50;
    public int TrustedPublisher        { get; set; } = 15;
    public int UserLaunchedProcess     { get; set; } = 10;

    public void Validate()
    {
        ConfigGuard.NonNegative(GpuSustained10Min,     nameof(GpuSustained10Min));
        ConfigGuard.NonNegative(GpuSustained30Min,     nameof(GpuSustained30Min));
        ConfigGuard.NonNegative(UnknownExecutable,      nameof(UnknownExecutable));
        ConfigGuard.NonNegative(UnsignedExecutable,     nameof(UnsignedExecutable));
        ConfigGuard.NonNegative(SuspiciousPath,         nameof(SuspiciousPath));
        ConfigGuard.NonNegative(SuspiciousCommandLine,  nameof(SuspiciousCommandLine));
        ConfigGuard.NonNegative(SuspiciousNetwork,      nameof(SuspiciousNetwork));
        ConfigGuard.NonNegative(MiningProtocol,         nameof(MiningProtocol));
        ConfigGuard.NonNegative(SuspiciousPersistence,  nameof(SuspiciousPersistence));
        ConfigGuard.NonNegative(KnownMaliciousHash,     nameof(KnownMaliciousHash));
        ConfigGuard.NonNegative(AiTrainingMitigation,   nameof(AiTrainingMitigation));
        ConfigGuard.NonNegative(TrustedApplication,     nameof(TrustedApplication));
        ConfigGuard.NonNegative(TrustedPublisher,       nameof(TrustedPublisher));
        ConfigGuard.NonNegative(UserLaunchedProcess,    nameof(UserLaunchedProcess));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  AI workload protection
// ─────────────────────────────────────────────────────────────────────────────

public sealed class AiProtectionConfig
{
    /// <summary>Enable the AI workload classification layer. Default true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// If AI confidence exceeds this value the process is classified as AI_WORKLOAD
    /// and the confirmation engine will NOT allow any destructive action. Default 0.65.
    /// </summary>
    public double MinimumConfidence { get; set; } = 0.65;

    public void Validate()
    {
        if (MinimumConfidence is < 0.0 or > 1.0)
            throw new ConfigurationException(
                "AiProtection.MinimumConfidence must be between 0.0 and 1.0.");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Response behaviour
// ─────────────────────────────────────────────────────────────────────────────

public sealed class ResponseConfig
{
    /// <summary>Terminate confirmed mining processes. Default false (safe production default).</summary>
    public bool TerminateMiningProcess { get; set; } = false;

    /// <summary>
    /// Initiate OS shutdown after confirmed mining is detected.
    /// Default false.  Must be explicitly enabled for production.
    /// </summary>
    public bool EmergencyShutdown { get; set; } = false;

    /// <summary>Seconds between confirmation and shutdown initiation. Default 30.</summary>
    public int ShutdownGraceSeconds { get; set; } = 30;

    public void Validate()
    {
        if (ShutdownGraceSeconds < 0)
            throw new ConfigurationException(
                "Response.ShutdownGraceSeconds must be >= 0.");

        if (EmergencyShutdown && !TerminateMiningProcess)
            throw new ConfigurationException(
                "Response.EmergencyShutdown=true requires TerminateMiningProcess=true.");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Logging
// ─────────────────────────────────────────────────────────────────────────────

public sealed class LoggingConfig
{
    /// <summary>Write to Windows Event Log. Default true.</summary>
    public bool EventLog      { get; set; } = true;
    /// <summary>Write structured JSON log files. Default true.</summary>
    public bool JsonLog       { get; set; } = true;
    /// <summary>Days to retain JSON log files. Default 14.</summary>
    public int  RetentionDays { get; set; } = 14;
    /// <summary>Log verbosity: 0=Error, 1=Warning, 2=Info, 3=Debug. Default 2.</summary>
    public int  Verbosity     { get; set; } = 2;

    public void Validate()
    {
        ConfigGuard.Range(RetentionDays, 1, 365, nameof(RetentionDays));
        ConfigGuard.Range(Verbosity,     0,   3, nameof(Verbosity));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  File paths
// ─────────────────────────────────────────────────────────────────────────────

public sealed class PathsConfig
{
    /// <summary>Directory where JSON logs and incident bundles are written.</summary>
    public string LogDirectory { get; set; } =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CoinShield", "Logs");

    /// <summary>Path to the allowlist JSON file.</summary>
    public string AllowlistFile { get; set; } = "allowlist.json";
}

// ─────────────────────────────────────────────────────────────────────────────
//  Web Mining Protection configuration
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Configuration for browser-based / web cryptomining detection.
/// Controls DNS filtering, browser process monitoring, and domain blocking.
/// </summary>
public sealed class WebMiningConfig
{
    /// <summary>Enable the entire web mining detection subsystem. Default true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Confidence threshold (0–100) for confirmed web miner classification.
    /// Requires at least 2 independent signals. Default 60.
    /// </summary>
    public int ConfirmedMiningThreshold { get; set; } = 60;

    /// <summary>
    /// Confidence threshold (0–100) for suspicious classification (triggers alert/log).
    /// Default 35.
    /// </summary>
    public int SuspiciousThreshold { get; set; } = 35;

    /// <summary>
    /// How often to run the browser/DNS scan cycle (seconds). Default 5.
    /// Separate from the main 1-second process loop.
    /// </summary>
    public int BrowserIntervalSeconds { get; set; } = 5;

    /// <summary>
    /// CPU % threshold for a browser renderer to be considered high-CPU.
    /// Contributes to the browser miner confidence score.
    /// BYPASS-06 FIX: Lowered from 80% to 50% — throttled miners cap CPU at ~60-70%
    /// to avoid detection. 50% is still above normal idle-tab usage.
    /// </summary>
    public double RendererCpuThreshold { get; set; } = 50.0;

    /// <summary>
    /// Seconds a JavaScript worker must run continuously to be counted as
    /// a long-running worker (mining indicator). Default 30.
    /// </summary>
    public int LongRunningWorkerSeconds { get; set; } = 30;

    /// <summary>
    /// Enable blocking mining domains via the Windows hosts file.
    /// Writes "0.0.0.0 domain" entries for confirmed mining domains.
    /// Requires the service to run as SYSTEM (already true). Default true.
    /// </summary>
    public bool EnableDomainBlocking { get; set; } = true;

    /// <summary>
    /// Path to the mining domains JSON blacklist file. Default: mining-domains.json
    /// in the installation directory.
    /// </summary>
    public string MiningDomainsFile { get; set; } = "mining-domains.json";

    /// <summary>
    /// Enable browser process correlation (tab/renderer identification).
    /// Allows terminating individual tabs instead of the entire browser. Default true.
    /// </summary>
    public bool EnableBrowserCorrelation { get; set; } = true;

    /// <summary>
    /// Enable process resurrection detection (A→B→A patterns). Default true.
    /// Detects miners that restart themselves via a watchdog process.
    /// </summary>
    public bool EnableResurrectionDetection { get; set; } = true;

    /// <summary>
    /// Score bonus added to the main risk score when resurrection is detected.
    /// This feeds into the existing RiskScorer. Default 30.
    /// </summary>
    public int ResurrectionScoreBonus { get; set; } = 30;

    /// <summary>
    /// Score bonus added when a known mining script CDN (Coinhive, CryptoLoot etc.)
    /// is contacted by a browser process. Default 50.
    /// </summary>
    public int MiningScriptDomainBonus { get; set; } = 50;

    /// <summary>
    /// Score bonus added when a mining pool domain is queried. Default 35.
    /// </summary>
    public int MiningPoolDomainBonus { get; set; } = 35;

    public void Validate()
    {
        ConfigGuard.Range(ConfirmedMiningThreshold, 1, 100, nameof(ConfirmedMiningThreshold));
        ConfigGuard.Range(SuspiciousThreshold,      1, 100, nameof(SuspiciousThreshold));
        ConfigGuard.Positive(BrowserIntervalSeconds,    nameof(BrowserIntervalSeconds));
        ConfigGuard.Positive(LongRunningWorkerSeconds,  nameof(LongRunningWorkerSeconds));
        ConfigGuard.NonNegative(ResurrectionScoreBonus,  nameof(ResurrectionScoreBonus));
        ConfigGuard.NonNegative(MiningScriptDomainBonus, nameof(MiningScriptDomainBonus));
        ConfigGuard.NonNegative(MiningPoolDomainBonus,   nameof(MiningPoolDomainBonus));

        if (RendererCpuThreshold is < 10.0 or > 100.0)
            throw new ConfigurationException(
                "WebMining.RendererCpuThreshold must be between 10 and 100.");
        if (SuspiciousThreshold >= ConfirmedMiningThreshold)
            throw new ConfigurationException(
                "WebMining.SuspiciousThreshold must be less than ConfirmedMiningThreshold.");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cloud environment configuration
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Settings for cloud VM deployments (GCP, Azure, AWS, Windows Server 2022/2025).
/// </summary>
public sealed class CloudConfig
{
    /// <summary>Enable cloud-specific behaviors. Default true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Timeout (seconds) for GCP instance metadata server probes.
    /// Keep short — metadata server is either available immediately or not at all.
    /// Default 2.
    /// </summary>
    public int GcpMetadataTimeoutSeconds { get; set; } = 2;

    /// <summary>
    /// When true, allow the GCP instance metadata key "coinshield-mode" to
    /// override the detection.mode setting in config.json.
    /// Useful for per-VM operating mode without editing config files.
    /// Default true.
    /// </summary>
    public bool AllowGcpModeOverride { get; set; } = true;

    /// <summary>
    /// When running on a cloud VM, increase persistence scan interval to
    /// reduce WMI overhead on VMs that share physical CPU.
    /// Default true (minimum interval becomes 60 s instead of 30 s).
    /// </summary>
    public bool ReduceWmiOverheadOnCloud { get; set; } = true;

    /// <summary>
    /// Behavior on Windows Server Core (no Desktop Experience).
    /// "HeadlessOnly" (default): JSON log + Event Log only, no browser detection
    ///   (no browsers run on Server Core).
    /// "Full": run all detectors even on Server Core.
    /// </summary>
    public string ServerCoreMode { get; set; } = "HeadlessOnly";

    /// <summary>
    /// Write instance metadata (zone, machine type, project) to Event Log at startup.
    /// Default true.
    /// </summary>
    public bool LogInstanceMetadataAtStartup { get; set; } = true;

    public void Validate()
    {
        ConfigGuard.Positive(GcpMetadataTimeoutSeconds, nameof(GcpMetadataTimeoutSeconds));
        if (GcpMetadataTimeoutSeconds > 30)
            throw new ConfigurationException(
                "Cloud.GcpMetadataTimeoutSeconds must be <= 30.");
        if (ServerCoreMode is not ("HeadlessOnly" or "Full"))
            throw new ConfigurationException(
                "Cloud.ServerCoreMode must be 'HeadlessOnly' or 'Full'.");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Configuration exception
// ─────────────────────────────────────────────────────────────────────────────

public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message) : base(message) { }
    public ConfigurationException(string message, Exception inner) : base(message, inner) { }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal validation guard (not part of the public API)
// ─────────────────────────────────────────────────────────────────────────────

internal static class ConfigGuard
{
    internal static void Positive(int value, string name)
    {
        if (value <= 0)
            throw new ConfigurationException(
                $"{name} must be a positive integer, got {value}.");
    }

    internal static void NonNegative(int value, string name)
    {
        if (value < 0)
            throw new ConfigurationException($"{name} must be >= 0, got {value}.");
    }

    internal static void Range(int value, int min, int max, string name)
    {
        if (value < min || value > max)
            throw new ConfigurationException(
                $"{name} must be between {min} and {max}, got {value}.");
    }
}
