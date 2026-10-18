# Downloads the Wintun driver DLL, verifies SHA-256 + the WireGuard LLC
# signature, and copies it (plus its license) next to detour.exe.
param([string]$OutDir = '.')
$ErrorActionPreference = 'Stop'
# WHY: Windows PowerShell 5 defaults to TLS 1.0/1.1 for Invoke-WebRequest on
# old profiles; wintun.net requires TLS 1.2+.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$version = '0.14.1'
$sha256  = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

$tmp = Join-Path ([IO.Path]::GetTempPath()) "wintun-$version"
New-Item -ItemType Directory -Force $tmp, $OutDir | Out-Null
$zip = Join-Path $tmp 'wintun.zip'
Invoke-WebRequest "https://www.wintun.net/builds/wintun-$version.zip" -OutFile $zip -TimeoutSec 120

$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $sha256) { throw "wintun-$version.zip checksum mismatch: got $actual" }

$x = Join-Path $tmp 'x'
Expand-Archive $zip -DestinationPath $x -Force
$dll = Join-Path $x 'wintun\bin\amd64\wintun.dll'
$sig = Get-AuthenticodeSignature $dll
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
    throw "wintun.dll is not validly signed by WireGuard LLC (status: $($sig.Status))"
}
Copy-Item $dll (Join-Path $OutDir 'wintun.dll') -Force
Copy-Item (Join-Path $x 'wintun\LICENSE.txt') (Join-Path $OutDir 'wintun-LICENSE.txt') -Force
Write-Host "wintun $version OK (sha256 + WireGuard LLC signature verified)"
