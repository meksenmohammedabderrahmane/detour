param(
    [string]$TargetIP = "1.1.1.1",
    [int]$TargetPort = 53,
    [int]$Count = 1000,
    [int]$TimeoutMs = 1000,
    [string]$Label = "UDP Latency Test"
)

# Standard DNS query for a.root-servers.net (small UDP payload: 36 bytes)
$dnsQuery = [byte[]](
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x61, 0x0c, 0x72,
    0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
    0x00, 0x01, 0x00, 0x01
)

$udp = New-Object System.Net.Sockets.UdpClient
$udp.Client.ReceiveTimeout = $TimeoutMs

$rtts = [System.Collections.Generic.List[double]]::new()
$lost = 0

Write-Output "[$Label] Sending $Count UDP round trips to ${TargetIP}:${TargetPort}..."
$startTotal = [System.Diagnostics.Stopwatch]::StartNew()

for ($i = 0; $i -lt $Count; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $udp.Send($dnsQuery, $dnsQuery.Length, $TargetIP, $TargetPort) | Out-Null
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    try {
        $res = $udp.Receive([ref]$ep)
        $sw.Stop()
        $rtts.Add($sw.Elapsed.TotalMilliseconds)
    } catch {
        $lost++
    }
    # Slight pacing (~1ms) to avoid overwhelming local socket buffers
    if ($i % 20 -eq 0) {
        Start-Sleep -Milliseconds 1
    }
}
$startTotal.Stop()
$udp.Close()

if ($rtts.Count -eq 0) {
    Write-Output "[$Label] ERROR: All $Count packets timed out."
    exit 1
}

$sorted = $rtts | Sort-Object
$median = $sorted[[math]::Floor($sorted.Count / 2)]
$p95 = $sorted[[math]::Floor($sorted.Count * 0.95)]
$p99 = $sorted[[math]::Floor($sorted.Count * 0.99)]
$max = $sorted[-1]
$lossPct = [math]::Round(($lost / $Count) * 100, 2)

Write-Output ("RESULT label={0} count={1} lost={2} lossPct={3}% median={4:F3}ms p95={5:F3}ms p99={6:F3}ms max={7:F3}ms totalSec={8:F1}s" -f `
    $Label, $Count, $lost, $lossPct, $median, $p95, $p99, $max, $startTotal.Elapsed.TotalSeconds)
