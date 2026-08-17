#Requires -RunAsAdministrator

Write-Host "`nStarting CoinShield Service...`n" -ForegroundColor Cyan

# Try to start the service
$service = Get-Service CoinShield -ErrorAction SilentlyContinue

if (-not $service) {
    Write-Host "ERROR: CoinShield service not found!" -ForegroundColor Red
    exit 1
}

Write-Host "Current status: $($service.Status)" -ForegroundColor Yellow

if ($service.Status -eq 'Running') {
    Write-Host "`nService is already running!`n" -ForegroundColor Green
    Get-Service CoinShield, CoinShieldWatchdog | Format-Table Status, Name, DisplayName -AutoSize
    exit 0
}

Write-Host "Starting service..." -ForegroundColor Yellow

try {
    Start-Service CoinShield -ErrorAction Stop
    Start-Sleep -Seconds 3
    
    $service.Refresh()
    
    if ($service.Status -eq 'Running') {
        Write-Host "`nSUCCESS! Service started.`n" -ForegroundColor Green
        Get-Service CoinShield, CoinShieldWatchdog | Format-Table Status, Name, DisplayName -AutoSize
        
        Write-Host "Recent logs:" -ForegroundColor Cyan
        Get-EventLog -LogName Application -Source CoinShield -Newest 3 | 
            Format-Table TimeGenerated, EntryType, Message -AutoSize -Wrap
    } else {
        Write-Host "`nWARNING: Service status is $($service.Status)`n" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "`nERROR starting service:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    Write-Host "`nChecking for detailed error in Event Log..." -ForegroundColor Yellow
    Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 
        Where-Object { $_.Message -match 'CoinShield' } |
        Format-List TimeGenerated, EntryType, Message
    
    Write-Host "`nTroubleshooting:" -ForegroundColor Cyan
    Write-Host "1. Check if .NET 10 Runtime is installed:" -ForegroundColor Gray
    Write-Host "   dotnet --list-runtimes | Select-String '10.0'" -ForegroundColor White
    Write-Host "`n2. Check service binary exists:" -ForegroundColor Gray
    Write-Host "   Test-Path 'C:\Program Files\CoinShield\CoinShield.Service.exe'" -ForegroundColor White
    Write-Host "`n3. Try running binary directly to see error:" -ForegroundColor Gray
    Write-Host "   & 'C:\Program Files\CoinShield\CoinShield.Service.exe'" -ForegroundColor White
}
