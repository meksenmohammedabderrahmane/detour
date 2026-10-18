# pack-release.ps1
# Creates binary release zip archive and computes SHA256SUMS.txt for release assets.

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dist = Join-Path $repoRoot "_dist"

$zipPath = Join-Path $dist "detour-v0.1.0-windows-amd64.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

$filesToZip = @(
    (Join-Path $dist "detour.exe"),
    (Join-Path $dist "detour-ui.exe"),
    (Join-Path $dist "wintun.dll"),
    (Join-Path $dist "wintun-LICENSE.txt"),
    (Join-Path $repoRoot "LICENSE"),
    (Join-Path $repoRoot "README.md"),
    (Join-Path $repoRoot "THIRD-PARTY-NOTICES.md")
)

Write-Output "Creating zip archive: $zipPath"
Compress-Archive -Path $filesToZip -DestinationPath $zipPath -CompressionLevel Optimal

$installerPath = Join-Path $dist "DetourSetup-0.1.0.exe"

$sumsFile = Join-Path $dist "SHA256SUMS.txt"
$sb = [System.Text.StringBuilder]::new()

$targets = @($installerPath, $zipPath)
foreach ($target in $targets) {
    if (Test-Path $target) {
        $hash = (Get-FileHash -Path $target -Algorithm SHA256).Hash.ToLowerInvariant()
        $fileName = [System.IO.Path]::GetFileName($target)
        $line = "$hash  $fileName"
        [void]$sb.AppendLine($line)
        Write-Output $line
    }
}

[System.IO.File]::WriteAllText($sumsFile, $sb.ToString(), [System.Text.Encoding]::UTF8)
Write-Output "`nSHA256 checksums written to $sumsFile"
