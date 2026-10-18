param(
    [string]$HomeIP = "",
    [string]$HotspotIP = "",
    [int]$Count = 100
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $PSScriptRoot '..\_dist'
$probeExe = Join-Path $dist 'stunprobe.exe'
$logFile = Join-Path $dist 'engine-session.log'
$detourExe = Join-Path $dist 'detour.exe'

function Get-AdapterPublicIP([string]$adapterName) {
    try {
        $ip = (Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "169.254*" }).IPAddress | Select-Object -First 1
        if ($ip) {
            $out = & curl.exe -s --interface $ip --connect-timeout 4 http://api.ipify.org
            return ($out | Out-String).Trim()
        }
    } catch {}
    return ""
}

if (-not $HomeIP) {
    $HomeIP = Get-AdapterPublicIP "Ethernet"
    Write-Output ("Discovered Home IP (Ethernet): {0}" -f $HomeIP)
}
if (-not $HotspotIP) {
    $HotspotIP = Get-AdapterPublicIP "Wi-Fi"
    Write-Output ("Discovered Hotspot IP (Wi-Fi): {0}" -f $HotspotIP)
}

function Run-StunPass([string]$Adapter, [string]$ExpectedIP, [string]$WrongIP) {
    Write-Output "`n======================================================="
    Write-Output "Running STUN Pass for Rule: stunprobe.exe=$Adapter"
    Write-Output "Expected IP: $ExpectedIP | Wrong IP: $WrongIP"
    Write-Output "======================================================="

    # Teardown any previous run
    & "$PSScriptRoot\m1-kill.ps1"
    Start-Sleep -Seconds 3
    & $detourExe cleanup
    Start-Sleep -Seconds 2

    # Clear log
    if (Test-Path $logFile) { Remove-Item $logFile -Force }

    # Start engine
    & "$PSScriptRoot\m1-start.ps1" -Rules "stunprobe.exe=$Adapter" -RunForSec 90 -LogPath $logFile
    Start-Sleep -Seconds 3

    # Run STUN probes
    $out = & $probeExe -count $Count -expected-ip $ExpectedIP -wrong-ip $WrongIP | Out-String
    Write-Output $out.Trim()

    Start-Sleep -Seconds 1

    # Parse engine-session.log for stunprobe delays
    $delays = [System.Collections.Generic.List[int]]::new()
    $queuedCount = 0
    if (Test-Path $logFile) {
        $lines = Get-Content $logFile -Encoding Unicode -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -match 'app=stunprobe\.exe.*adapter=(\S+).*delay=(\d+)ms.*unknown=(\w+)') {
                $actAdapter = $matches[1]
                $d = [int]$matches[2]
                $delays.Add($d)
                $queuedCount++
            }
        }
    }

    $medianDelay = 0
    if ($delays.Count -gt 0) {
        $sorted = $delays | Sort-Object
        $medianDelay = $sorted[[math]::Floor($sorted.Count / 2)]
    }

    Write-Output ("ENGINE_STATS adapter={0} flowsLogged={1} queuedCount={2} medianQueueDelay={3}ms" -f `
        $Adapter, $delays.Count, $queuedCount, $medianDelay)

    # Stop engine
    & "$PSScriptRoot\m1-kill.ps1"
    Start-Sleep -Seconds 3
    & $detourExe cleanup
}

# Run Pass 1: Ethernet
Run-StunPass -Adapter "Ethernet" -ExpectedIP $HomeIP -WrongIP $HotspotIP

Start-Sleep -Seconds 4

# Run Pass 2: Wi-Fi
Run-StunPass -Adapter "Wi-Fi" -ExpectedIP $HotspotIP -WrongIP $HomeIP
