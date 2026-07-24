# ============================================================
#  sync-clock.ps1  -  run as Administrator on BOTH machines
#  Syncs the Windows clock to a shared NTP source and reports
#  the offset. Both machines must show offset < 1 second.
#
#  Run:  powershell -ExecutionPolicy Bypass -File .\sync-clock.ps1
#  (from an Administrator PowerShell, on each machine)
# ============================================================

$NtpServer = "time.windows.com"   # use the SAME server on both machines

# --- require elevation (single line: paste/parsing safe) ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] Not elevated. Re-open PowerShell as Administrator and re-run." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Configuring Windows Time service against $NtpServer ..." -ForegroundColor Cyan

Set-Service  w32time -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service w32time -ErrorAction SilentlyContinue

& w32tm /config /manualpeerlist:"$NtpServer,0x8" /syncfromflags:manual /update | Out-Null
Restart-Service w32time
Start-Sleep -Seconds 2
$resync = (& w32tm /resync /force 2>&1) -join "`n"

# --- self-heal if the service is wedged ---
if ($resync -match "0x800705B4|not been started|error|failed") {
    Write-Host "[!] Resync failed - re-registering the time service..." -ForegroundColor Yellow
    & net stop w32time  | Out-Null
    & w32tm /unregister | Out-Null
    & w32tm /register   | Out-Null
    & net start w32time | Out-Null
    Start-Sleep -Seconds 2
    & w32tm /config /manualpeerlist:"$NtpServer,0x8" /syncfromflags:manual /update | Out-Null
    Restart-Service w32time
    Start-Sleep -Seconds 2
    & w32tm /resync /force | Out-Null
}

Write-Host "`n[*] Time service status:" -ForegroundColor Cyan
& w32tm /query /status | Select-String "Source|Last Successful|Poll"

Write-Host "`n[*] Offset vs $NtpServer (want << 1s):" -ForegroundColor Cyan
$chart = & w32tm /stripchart /computer:$NtpServer /samples:3 /dataonly 2>&1
$chart | ForEach-Object { Write-Host "    $_" }

# --- final verdict ---
$matches = $chart | Select-String -Pattern '([+-]\d+\.\d+)s' -AllMatches
$offsets = @()
foreach ($m in $matches) {
    foreach ($mm in $m.Matches) {
        $offsets += [double]($mm.Value -replace 's', '')
    }
}
Write-Host ""
if ($offsets.Count -gt 0) {
    $worst = ($offsets | ForEach-Object { [math]::Abs($_) } | Measure-Object -Maximum).Maximum
    if ($worst -lt 1.0) {
        Write-Host ("[+] GOOD - worst offset {0:N3}s. Clock is synced." -f $worst) -ForegroundColor Green
    } else {
        Write-Host ("[-] HIGH - worst offset {0:N3}s. Re-run, or set `$NtpServer to time.google.com." -f $worst) -ForegroundColor Red
    }
} else {
    Write-Host "[!] Could not read offset - check network/firewall access (UDP 123) to $NtpServer." -ForegroundColor Yellow
}

Write-Host "`n[i] Local time now: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')"
Write-Host "[i] Run on BOTH machines within a minute of each other; both must read GOOD."
