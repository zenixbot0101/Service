using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using CoinShield.Models;

namespace CoinShield.Core;

/// <summary>
/// Browser process analyzer with tab/renderer correlation.
/// Detects browser-based cryptomining without killing entire browser.
/// 
/// Key features:
/// - Identifies browser child processes (tabs, renderers, GPU, workers)
/// - Detects WebAssembly activity patterns
/// - Correlates high-CPU renderer processes with network connections
/// - Attempts to isolate mining tab/worker instead of terminating entire browser
/// </summary>
public sealed class BrowserAnalyzer
{
    private readonly Dictionary<int, BrowserProcessTree> _browserTrees;
    private readonly Dictionary<int, DateTime> _processStartTimes;
    // BUG-05 FIX: Store previous CPU sample for delta calculation
    // Key: PID, Value: (processorTimeTicks, sampleTime)
    private readonly Dictionary<int, (long cpuTicks, DateTime sampleTime)> _cpuSamples;
    private readonly object _lock = new();

    // Known browser process names
    private static readonly Dictionary<string, BrowserType> BrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        { "chrome", BrowserType.Chrome },
        { "msedge", BrowserType.Edge },
        { "firefox", BrowserType.Firefox },
        { "opera", BrowserType.Opera },
        { "brave", BrowserType.Brave },
        { "chromium", BrowserType.Chromium },
        { "vivaldi", BrowserType.Vivaldi },
        { "safari", BrowserType.Safari }
    };

    // Chromium-based browser process types (from --type= command line)
    private static readonly HashSet<string> ChromiumProcessTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "renderer",
        "gpu-process",
        "utility",
        "broker",
        "crashpad-handler",
        "ppapi",
        "ppapi-broker"
    };

    public BrowserAnalyzer()
    {
        _browserTrees    = new Dictionary<int, BrowserProcessTree>();
        _processStartTimes = new Dictionary<int, DateTime>();
        _cpuSamples      = new Dictionary<int, (long, DateTime)>();
    }

    /// <summary>
    /// Check if a process is a browser
    /// </summary>
    public bool IsBrowserProcess(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return false;

        return BrowserProcessNames.Keys.Any(browser => 
            processName.Contains(browser, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Identify browser type from process name
    /// </summary>
    public BrowserType GetBrowserType(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return BrowserType.Unknown;

        foreach (var kvp in BrowserProcessNames)
        {
            if (processName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                return kvp.Value;
        }

        return BrowserType.Unknown;
    }

    /// <summary>
    /// Capture comprehensive browser snapshot including all child processes
    /// </summary>
    public BrowserSnapshot CaptureBrowserSnapshot(int mainBrowserPid)
    {
        try
        {
            var mainProcess = Process.GetProcessById(mainBrowserPid);
            var browserType = GetBrowserType(mainProcess.ProcessName);

            var snapshot = new BrowserSnapshot
            {
                ProcessId = mainBrowserPid,
                Type = browserType,
                ProcessName = mainProcess.ProcessName,
                Timestamp = DateTime.UtcNow
            };

            // Get all child processes
            var children = GetBrowserChildProcesses(mainBrowserPid, browserType);
            snapshot.ChildProcesses.AddRange(children);

            // Calculate totals
            snapshot.TotalCpuUsage = children.Sum(c => c.CpuUsage);
            snapshot.TotalMemoryMB = children.Sum(c => c.MemoryMB);

            // Detect WebAssembly activity (heuristic based on high CPU + specific patterns)
            snapshot.HasWebAssemblyActivity = children.Any(c => 
                c.IsTabRenderer && 
                c.CpuUsage > 70 && 
                c.UptimeSeconds > 10);

            // Count long-running workers (>30s with consistent CPU)
            snapshot.LongRunningWorkerCount = children.Count(c => 
                c.IsTabRenderer && 
                c.UptimeSeconds > 30 && 
                c.CpuUsage > 50);

            // Count high-CPU renderers
            snapshot.HighCpuRendererCount = children.Count(c => 
                c.IsTabRenderer && 
                c.CpuUsage > 80);

            // Update browser tree cache
            lock (_lock)
            {
                _browserTrees[mainBrowserPid] = new BrowserProcessTree
                {
                    MainProcessId = mainBrowserPid,
                    BrowserType = browserType,
                    ChildProcessIds = children.Select(c => c.ProcessId).ToList(),
                    LastUpdate = DateTime.UtcNow
                };
            }

            return snapshot;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Browser snapshot failed for PID {mainBrowserPid}: {ex.Message}");
            return new BrowserSnapshot { ProcessId = mainBrowserPid };
        }
    }

    /// <summary>
    /// Find all browser child processes (tabs, renderers, workers)
    /// </summary>
    private List<BrowserChildProcess> GetBrowserChildProcesses(int mainBrowserPid, BrowserType browserType)
    {
        var children = new List<BrowserChildProcess>();

        try
        {
            // Strategy differs by browser type
            if (browserType is BrowserType.Chrome or BrowserType.Edge or BrowserType.Chromium or 
                BrowserType.Brave or BrowserType.Vivaldi or BrowserType.Opera)
            {
                // Chromium-based: look for child processes with same executable
                children = GetChromiumChildProcesses(mainBrowserPid);
            }
            else if (browserType == BrowserType.Firefox)
            {
                // Firefox: different architecture, use parent PID
                children = GetFirefoxChildProcesses(mainBrowserPid);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to enumerate browser children: {ex.Message}");
        }

        return children;
    }

    /// <summary>
    /// Get Chromium-based browser child processes (Chrome, Edge, Brave, etc.)
    /// </summary>
    private List<BrowserChildProcess> GetChromiumChildProcesses(int mainPid)
    {
        var children = new List<BrowserChildProcess>();

        try
        {
            // Get main process to find executable path
            var mainProcess = Process.GetProcessById(mainPid);
            var mainExeName = mainProcess.ProcessName;

            // Find all processes with same name
            var allBrowserProcesses = Process.GetProcessesByName(mainExeName);

            foreach (var proc in allBrowserProcesses)
            {
                try
                {
                    if (proc.Id == mainPid)
                        continue; // Skip main process

                    // Get command line to identify process type
                    var cmdLine = GetProcessCommandLine(proc.Id);
                    var processType = ExtractChromiumProcessType(cmdLine);

                    // Track start time
                    var startTime = GetProcessStartTime(proc.Id);
                    var uptime = startTime.HasValue 
                        ? (DateTime.UtcNow - startTime.Value).TotalSeconds 
                        : 0;

                    // Get CPU and memory
                    var cpu = GetProcessCpuUsage(proc);
                    var memoryMB = proc.WorkingSet64 / (1024 * 1024);

                    var child = new BrowserChildProcess
                    {
                        ProcessId = proc.Id,
                        ProcessType = processType,
                        CommandLine = cmdLine,
                        CpuUsage = cpu,
                        MemoryMB = memoryMB,
                        UptimeSeconds = uptime,
                        IsTabRenderer = processType.Equals("renderer", StringComparison.OrdinalIgnoreCase),
                        HasWebAssembly = DetectWebAssemblyHeuristic(proc, cmdLine)
                    };

                    children.Add(child);
                }
                catch
                {
                    // Process may have exited
                    continue;
                }
                finally
                {
                    proc?.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Chromium child enumeration failed: {ex.Message}");
        }

        return children;
    }

    /// <summary>
    /// Get Firefox child processes
    /// </summary>
    private List<BrowserChildProcess> GetFirefoxChildProcesses(int mainPid)
    {
        var children = new List<BrowserChildProcess>();

        try
        {
            // Firefox uses a different multi-process architecture
            // Look for processes with firefox.exe and check parent PID
            var query = $"SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process WHERE Name = 'firefox.exe'";
            
            using var searcher = new ManagementObjectSearcher(query);
            using var results = searcher.Get();

            foreach (ManagementObject obj in results)
            {
                try
                {
                    var pid = Convert.ToInt32(obj["ProcessId"]);
                    var parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                    
                    if (pid == mainPid)
                        continue;

                    // Firefox child processes have main process as parent
                    if (parentPid != mainPid)
                        continue;

                    var proc = Process.GetProcessById(pid);
                    var cmdLine = obj["CommandLine"]?.ToString() ?? string.Empty;
                    
                    var processType = cmdLine.Contains("-contentproc", StringComparison.OrdinalIgnoreCase) 
                        ? "content" 
                        : "unknown";

                    var startTime = GetProcessStartTime(pid);
                    var uptime = startTime.HasValue 
                        ? (DateTime.UtcNow - startTime.Value).TotalSeconds 
                        : 0;

                    var cpu = GetProcessCpuUsage(proc);
                    var memoryMB = proc.WorkingSet64 / (1024 * 1024);

                    var child = new BrowserChildProcess
                    {
                        ProcessId = pid,
                        ProcessType = processType,
                        CommandLine = cmdLine,
                        CpuUsage = cpu,
                        MemoryMB = memoryMB,
                        UptimeSeconds = uptime,
                        IsTabRenderer = processType == "content",
                        HasWebAssembly = DetectWebAssemblyHeuristic(proc, cmdLine)
                    };

                    children.Add(child);
                    proc.Dispose();
                }
                catch
                {
                    continue;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Firefox child enumeration failed: {ex.Message}");
        }

        return children;
    }

    /// <summary>
    /// Identify the most suspicious browser tab/renderer process
    /// Returns null if no suspicious tab found
    /// </summary>
    public int? IdentifyMiningTab(BrowserSnapshot snapshot, double cpuThreshold = 80.0)
    {
        // Look for renderer processes with:
        // 1. High CPU usage (> 80%)
        // 2. Long running (> 30s)
        // 3. Potential WebAssembly activity

        var suspiciousRenderers = snapshot.ChildProcesses
            .Where(c => c.IsTabRenderer)
            .Where(c => c.CpuUsage > cpuThreshold)
            .Where(c => c.UptimeSeconds > 30)
            .OrderByDescending(c => c.CpuUsage)
            .ToList();

        return suspiciousRenderers.FirstOrDefault()?.ProcessId;
    }

    /// <summary>
    /// Get browser process tree from cache
    /// </summary>
    public BrowserProcessTree? GetBrowserTree(int mainBrowserPid)
    {
        lock (_lock)
        {
            return _browserTrees.TryGetValue(mainBrowserPid, out var tree) ? tree : null;
        }
    }

    /// <summary>
    /// Clear cached browser tree (call when browser exits)
    /// </summary>
    public void ClearBrowserTree(int mainBrowserPid)
    {
        lock (_lock)
        {
            _browserTrees.Remove(mainBrowserPid);
            _cpuSamples.Remove(mainBrowserPid);
            _processStartTimes.Remove(mainBrowserPid);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private string GetProcessCommandLine(int processId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
            using var results = searcher.Get();
            
            foreach (ManagementObject obj in results)
            {
                return obj["CommandLine"]?.ToString() ?? string.Empty;
            }
        }
        catch
        {
            // Fallback: access denied or process exited
        }

        return string.Empty;
    }

    private string ExtractChromiumProcessType(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return "main";

        // Look for --type=renderer, --type=gpu-process, etc.
        var match = System.Text.RegularExpressions.Regex.Match(
            commandLine, 
            @"--type=(\S+)", 
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        if (match.Success && match.Groups.Count > 1)
        {
            return match.Groups[1].Value;
        }

        return "unknown";
    }

    private DateTime? GetProcessStartTime(int processId)
    {
        lock (_lock)
        {
            if (_processStartTimes.TryGetValue(processId, out var cached))
                return cached;
        }

        try
        {
            var proc = Process.GetProcessById(processId);
            var startTime = proc.StartTime.ToUniversalTime();
            
            lock (_lock)
            {
                _processStartTimes[processId] = startTime;
            }
            
            return startTime;
        }
        catch
        {
            return null;
        }
    }

    private double GetProcessCpuUsage(Process process)
    {
        // BUG-05 FIX: Delta sampling — compare CPU ticks between two snapshots
        // instead of dividing total CPU time by total uptime (which gives a
        // near-zero lifetime average for newly-elevated miners).
        try
        {
            var now        = DateTime.UtcNow;
            long curTicks  = process.TotalProcessorTime.Ticks;
            int  pid       = process.Id;

            lock (_lock)
            {
                if (_cpuSamples.TryGetValue(pid, out var prev))
                {
                    double elapsedMs = (now - prev.sampleTime).TotalMilliseconds;
                    if (elapsedMs > 100) // require at least 100 ms between samples
                    {
                        long deltaTicks = curTicks - prev.cpuTicks;
                        double cpuUsage = (deltaTicks / (double)TimeSpan.TicksPerMillisecond)
                                          / (elapsedMs * Environment.ProcessorCount) * 100.0;

                        _cpuSamples[pid] = (curTicks, now);
                        return Math.Min(100.0, Math.Max(0.0, cpuUsage));
                    }
                }

                // First sample for this PID — store baseline, return 0
                _cpuSamples[pid] = (curTicks, now);
                return 0.0;
            }
        }
        catch
        {
            return 0;
        }
    }

    private bool DetectWebAssemblyHeuristic(Process process, string commandLine)
    {
        // Heuristic: WebAssembly typically shows as:
        // - High CPU usage in renderer
        // - No command line indicators of legitimate GPU work
        // This is a weak signal and needs correlation with other indicators

        try
        {
            // Check for GPU-related flags (legitimate WebGL/WebGPU work)
            if (commandLine.Contains("--enable-webgl", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("--enable-webgpu", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("--gpu-process", StringComparison.OrdinalIgnoreCase))
            {
                return false; // Likely legitimate
            }

            // High CPU + no GPU flags = potential WASM mining
            var cpu = GetProcessCpuUsage(process);
            return cpu > 70;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// Cached browser process tree
/// </summary>
public sealed class BrowserProcessTree
{
    public int MainProcessId { get; init; }
    public BrowserType BrowserType { get; init; }
    public List<int> ChildProcessIds { get; init; } = new();
    public DateTime LastUpdate { get; init; }
}
