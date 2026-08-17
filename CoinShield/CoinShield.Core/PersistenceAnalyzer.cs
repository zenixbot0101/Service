using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using Microsoft.Win32;
using CoinShield.Configuration;
using CoinShield.Logging;

namespace CoinShield.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  Persistence finding
// ─────────────────────────────────────────────────────────────────────────────

public enum PersistenceType
{
    RegistryRunKey,
    RegistryRunOnceKey,
    StartupFolder,
    ScheduledTask,
    WindowsService,
    WmiEventSubscription,
}

public sealed class PersistenceEntry
{
    public PersistenceType Type        { get; init; }
    public string          Location    { get; init; } = string.Empty;
    public string          Name        { get; init; } = string.Empty;
    public string          Value       { get; init; } = string.Empty;
    /// <summary>True if the command points to a suspicious/temp path.</summary>
    public bool            IsSuspicious { get; init; }
    public string          Reason      { get; init; } = string.Empty;
}

// ─────────────────────────────────────────────────────────────────────────────
//  PersistenceAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Periodically scans common Windows persistence locations for entries that
/// could indicate a cryptominer installed itself to survive reboots.
///
/// Key design principle:
/// Persistence alone is not evidence of mining.  A legitimate application
/// (e.g. antivirus, a development tool) will also have persistence entries.
/// This class flags entries as suspicious only when they reference executables
/// in unusual paths OR match known miner binary names.
/// The persistence score is combined with all other signals by the RiskScorer.
///
/// Locations scanned:
///   ─ HKLM/HKCU Run / RunOnce registry keys
///   ─ User startup folders
///   ─ Common startup folder
///   ─ Scheduled tasks (via WMI Win32_ScheduledJob + schtasks WMI class)
///   ─ Windows services (Win32_Service) — only non-system services
///   ─ WMI event subscriptions (__EventFilter, __EventConsumer)
/// </summary>
public sealed class PersistenceAnalyzer
{
    private readonly CoinShieldConfig _cfg;
    private readonly CoinShieldLogger _logger;

    // ── Registry run key locations ────────────────────────────────────────────
    private static readonly (RegistryHive hive, string subKey)[] _runKeys =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        // 64-bit on 32-bit OS node
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    };

    // ── Suspicious path fragments ─────────────────────────────────────────────
    private static readonly string[] _suspiciousPathFragments =
    {
        @"\temp\", @"\tmp\",
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\downloads\",
        @"\recycle", @"\$recycle.bin\",
        @"\public\",
        // Random-looking sub-directories sometimes used by malware
        @"\appdata\local\microsoft\windows\inetcache\",
    };

    // ── Known system service name prefixes (skip to reduce noise) ────────────
    private static readonly HashSet<string> _systemServicePrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Windows", "Microsoft", "BITS", "Spooler", "WinDefend", "MpsSvc",
        "EventLog", "Schedule", "Dnscache", "LanmanServer", "LanmanWorkstation",
        "Dhcp", "Netlogon", "RemoteRegistry", "wuauserv", "CryptSvc",
        "TrkWks", "W32Time", "AudioSrv", "Audiosrv",
    };

    public PersistenceAnalyzer(CoinShieldConfig cfg, CoinShieldLogger logger)
    {
        _cfg    = cfg    ?? throw new ArgumentNullException(nameof(cfg));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Full scan ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Performs a full scan of all persistence locations.
    /// Returns all found entries (suspicious and benign).
    /// Callers should use <see cref="GetSuspiciousEntries"/> to filter.
    /// </summary>
    public List<PersistenceEntry> ScanAll()
    {
        var entries = new List<PersistenceEntry>();

        try { entries.AddRange(ScanRegistryRunKeys()); }
        catch (Exception ex) { _logger.Debug("PersistenceAnalyzer", $"Registry scan error: {ex.Message}"); }

        try { entries.AddRange(ScanStartupFolders()); }
        catch (Exception ex) { _logger.Debug("PersistenceAnalyzer", $"Startup folder scan error: {ex.Message}"); }

        try { entries.AddRange(ScanScheduledTasks()); }
        catch (Exception ex) { _logger.Debug("PersistenceAnalyzer", $"Scheduled task scan error: {ex.Message}"); }

        try { entries.AddRange(ScanServices()); }
        catch (Exception ex) { _logger.Debug("PersistenceAnalyzer", $"Service scan error: {ex.Message}"); }

        try { entries.AddRange(ScanWmiSubscriptions()); }
        catch (Exception ex) { _logger.Debug("PersistenceAnalyzer", $"WMI subscription scan error: {ex.Message}"); }

        return entries;
    }

    /// <summary>
    /// Scans all persistence locations and returns only entries classified
    /// as suspicious.  Suitable for correlation with process snapshots.
    /// </summary>
    public List<PersistenceEntry> GetSuspiciousEntries() =>
        ScanAll().Where(e => e.IsSuspicious).ToList();

    /// <summary>
    /// Checks whether any persistence entry references an executable at the
    /// same path as (or with the same name as) the given process.
    /// Returns matching entries.
    /// </summary>
    public List<PersistenceEntry> FindEntriesForProcess(string executablePath, string processName)
    {
        var all    = ScanAll();
        var lower  = (executablePath ?? string.Empty).ToLowerInvariant();
        var nLower = (processName    ?? string.Empty).ToLowerInvariant().Replace(".exe", string.Empty);

        return all.Where(e =>
        {
            var vLower = e.Value.ToLowerInvariant();
            return (!string.IsNullOrWhiteSpace(lower) && vLower.Contains(lower))
                || (!string.IsNullOrWhiteSpace(nLower) && vLower.Contains(nLower));
        }).ToList();
    }

    // ── Registry Run keys ─────────────────────────────────────────────────────

    private List<PersistenceEntry> ScanRegistryRunKeys()
    {
        var results = new List<PersistenceEntry>();

        foreach (var (hive, subKey) in _runKeys)
        {
            var isRunOnce = subKey.Contains("RunOnce", StringComparison.OrdinalIgnoreCase);
            var type      = isRunOnce ? PersistenceType.RegistryRunOnceKey
                                      : PersistenceType.RegistryRunKey;

            try
            {
                using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64)
                                            .OpenSubKey(subKey, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    var (suspicious, reason) = ClassifyValue(value, valueName);

                    results.Add(new PersistenceEntry
                    {
                        Type         = type,
                        Location     = $"{hive}\\{subKey}",
                        Name         = valueName,
                        Value        = value,
                        IsSuspicious = suspicious,
                        Reason       = reason,
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("PersistenceAnalyzer",
                    $"Cannot open {hive}\\{subKey}: {ex.Message}");
            }
        }

        return results;
    }

    // ── Startup folders ───────────────────────────────────────────────────────

    private List<PersistenceEntry> ScanStartupFolders()
    {
        var results = new List<PersistenceEntry>();
        var folders = new List<string>();

        void Add(Environment.SpecialFolder f)
        {
            var p = Environment.GetFolderPath(f);
            if (!string.IsNullOrWhiteSpace(p))
            {
                var startup = Path.Combine(p, "Microsoft", "Windows", "Start Menu",
                                           "Programs", "Startup");
                if (Directory.Exists(startup)) folders.Add(startup);
            }
        }

        Add(Environment.SpecialFolder.ApplicationData);
        Add(Environment.SpecialFolder.CommonApplicationData);

        // Common startup
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (!string.IsNullOrWhiteSpace(common) && Directory.Exists(common))
            folders.Add(common);

        var user = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(user) && Directory.Exists(user))
            folders.Add(user);

        foreach (var folder in folders.Distinct())
        {
            foreach (var file in SafeEnumerateFiles(folder))
            {
                var value = file;
                var (suspicious, reason) = ClassifyValue(value, Path.GetFileName(file));

                results.Add(new PersistenceEntry
                {
                    Type         = PersistenceType.StartupFolder,
                    Location     = folder,
                    Name         = Path.GetFileName(file),
                    Value        = value,
                    IsSuspicious = suspicious,
                    Reason       = reason,
                });
            }
        }

        return results;
    }

    // ── Scheduled tasks (WMI) ─────────────────────────────────────────────────

    private List<PersistenceEntry> ScanScheduledTasks()
    {
        var results = new List<PersistenceEntry>();

        try
        {
            // Win32_ScheduledJob covers AT-style tasks; for Task Scheduler tasks
            // we enumerate the tasks directory as a lightweight alternative to
            // the Task Scheduler COM API (avoids additional COM dependency).
            var taskDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"..\Tasks");

            taskDir = Path.GetFullPath(taskDir); // normalise

            if (!Directory.Exists(taskDir)) return results;

            foreach (var taskFile in SafeEnumerateFiles(taskDir, "*.xml",
                         SearchOption.AllDirectories))
            {
                try
                {
                    var content = File.ReadAllText(taskFile);

                    // Extract Exec/Command element value (simple XML scan)
                    var commandMatch = System.Text.RegularExpressions.Regex.Match(
                        content, @"<Command>(.*?)</Command>",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                        System.Text.RegularExpressions.RegexOptions.Singleline,
                        TimeSpan.FromMilliseconds(200));

                    if (!commandMatch.Success) continue;

                    var command = commandMatch.Groups[1].Value.Trim();
                    var taskName = Path.GetFileNameWithoutExtension(taskFile);

                    var (suspicious, reason) = ClassifyValue(command, taskName);

                    results.Add(new PersistenceEntry
                    {
                        Type         = PersistenceType.ScheduledTask,
                        Location     = taskFile,
                        Name         = taskName,
                        Value        = command,
                        IsSuspicious = suspicious,
                        Reason       = reason,
                    });
                }
                catch { /* Skip unreadable task files */ }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("PersistenceAnalyzer", $"Scheduled task scan: {ex.Message}");
        }

        return results;
    }

    // ── Windows services ──────────────────────────────────────────────────────

    private List<PersistenceEntry> ScanServices()
    {
        var results = new List<PersistenceEntry>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, PathName, StartMode, State FROM Win32_Service " +
                "WHERE StartMode = 'Auto' OR StartMode = 'Manual'");

            foreach (ManagementObject obj in searcher.Get())
            {
                var name     = obj["Name"]?.ToString()     ?? string.Empty;
                var pathName = obj["PathName"]?.ToString() ?? string.Empty;

                // Skip well-known system services to reduce noise
                if (_systemServicePrefixes.Any(p =>
                        name.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var (suspicious, reason) = ClassifyValue(pathName, name);

                if (suspicious)
                {
                    results.Add(new PersistenceEntry
                    {
                        Type         = PersistenceType.WindowsService,
                        Location     = @"HKLM\SYSTEM\CurrentControlSet\Services\" + name,
                        Name         = name,
                        Value        = pathName,
                        IsSuspicious = true,
                        Reason       = reason,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug("PersistenceAnalyzer", $"Service scan WMI: {ex.Message}");
        }

        return results;
    }

    // ── WMI event subscriptions ───────────────────────────────────────────────

    private List<PersistenceEntry> ScanWmiSubscriptions()
    {
        var results = new List<PersistenceEntry>();

        // CommandLineEventConsumer and ActiveScriptEventConsumer are common
        // malware persistence vectors.  Their existence is always flagged.
        string[] consumerClasses =
        {
            "CommandLineEventConsumer",
            "ActiveScriptEventConsumer",
        };

        foreach (var cls in consumerClasses)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\subscription", $"SELECT * FROM {cls}");

                foreach (ManagementObject obj in searcher.Get())
                {
                    var name    = obj["Name"]?.ToString() ?? cls;
                    var command = obj.GetPropertyValue("CommandLineTemplate")?.ToString()
                               ?? obj.GetPropertyValue("ScriptText")?.ToString()
                               ?? string.Empty;

                    results.Add(new PersistenceEntry
                    {
                        Type         = PersistenceType.WmiEventSubscription,
                        Location     = $@"root\subscription:{cls}",
                        Name         = name,
                        Value        = command,
                        IsSuspicious = true,  // Any WMI consumer warrants investigation
                        Reason       = $"WMI {cls} subscription detected — rare in legitimate software.",
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("PersistenceAnalyzer",
                    $"WMI subscription scan ({cls}): {ex.Message}");
            }
        }

        return results;
    }

    // ── Classification helper ─────────────────────────────────────────────────

    /// <summary>
    /// Returns (isSuspicious, reason) for a value string (path/command).
    /// Suspicious = executable in a temp/unusual location or matching a
    /// known miner name.  Benign system entries are NOT flagged.
    /// </summary>
    private (bool suspicious, string reason) ClassifyValue(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
            return (false, string.Empty);

        var lower = value.ToLowerInvariant();

        // ── Suspicious path fragments ─────────────────────────────────────────
        foreach (var fragment in _suspiciousPathFragments)
        {
            if (lower.Contains(fragment))
                return (true, $"Entry points to suspicious path containing '{fragment}'.");
        }

        // ── Random-looking name in a user-writable directory ──────────────────
        var fileName = Path.GetFileNameWithoutExtension(
            ExtractExecutablePath(lower)).ToLowerInvariant();

        if (fileName.Length >= 8)
        {
            int hexLike = fileName.Count(c => "0123456789abcdef".Contains(c));
            if ((double)hexLike / fileName.Length > 0.80)
                return (true, $"Entry name '{fileName}' looks randomly generated.");
        }

        // ── Known miner names in path or entry name ───────────────────────────
        string[] knownMinerNames = {
            "xmrig", "xmr-stak", "ccminer", "cgminer", "bfgminer",
            "nbminer", "gminer", "t-rex", "lolminer", "phoenixminer",
            "ethminer", "claymore", "nanominer", "srbminer", "cpuminer",
        };

        foreach (var miner in knownMinerNames)
        {
            if (lower.Contains(miner) || name.ToLowerInvariant().Contains(miner))
                return (true, $"Entry references known mining software: '{miner}'.");
        }

        return (false, string.Empty);
    }

    /// <summary>
    /// Extracts the executable path from a command-line value,
    /// stripping arguments.
    /// </summary>
    private static string ExtractExecutablePath(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return string.Empty;
        cmd = cmd.Trim();

        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            return end > 0 ? cmd[1..end] : cmd;
        }

        int space = cmd.IndexOf(' ');
        return space > 0 ? cmd[..space] : cmd;
    }

    // ── Safe file enumeration ─────────────────────────────────────────────────

    private static IEnumerable<string> SafeEnumerateFiles(
        string dir,
        string pattern        = "*",
        SearchOption option   = SearchOption.TopDirectoryOnly)
    {
        if (!Directory.Exists(dir)) yield break;
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, pattern, option);
        }
        catch { yield break; }

        foreach (var f in files)
        {
            string result = string.Empty;
            try { result = f; } catch { }
            if (!string.IsNullOrEmpty(result))
                yield return result;
        }
    }
}
