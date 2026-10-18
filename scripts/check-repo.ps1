# check-repo.ps1
# Repository hygiene and privacy verification script.
# Fails with exit code 1 if forbidden characters (U+2014 em dash) or personal data appear.

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$violations = [System.Collections.Generic.List[string]]::new()

# File extensions to scan
$allowedExts = @(
    ".go", ".mod", ".sum", ".md", ".txt", ".ps1", ".bat", ".cmd",
    ".html", ".js", ".css", ".json", ".iss", ".yml", ".yaml", ".gitignore", ".gitattributes"
)

# Known allowed public IPs (e.g. public DNS, well-known test IPs)
$allowedPublicIPs = @(
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220"
)

function Is-PrivateOrAllowedIP([string]$ipStr) {
    if ($allowedPublicIPs -contains $ipStr) { return $true }
    # Routing prefix 128.0.0.0 (used in 0.0.0.0/1 and 128.0.0.0/1 split default routes)
    if ($ipStr -eq "128.0.0.0") { return $true }
    
    $parts = $ipStr.Split('.')
    if ($parts.Length -ne 4) { return $false }
    $b0 = [int]$parts[0]
    $b1 = [int]$parts[1]
    
    # 0.0.0.0, 255.255.255.255
    if ($b0 -eq 0 -or $b0 -eq 255) { return $true }
    # 127.0.0.0/8
    if ($b0 -eq 127) { return $true }
    # 10.0.0.0/8
    if ($b0 -eq 10) { return $true }
    # 172.16.0.0/12
    if ($b0 -eq 172 -and ($b1 -ge 16 -and $b1 -le 31)) { return $true }
    # 192.168.0.0/16
    if ($b0 -eq 192 -and $b1 -eq 168) { return $true }
    # 169.254.0.0/16 (APIPA)
    if ($b0 -eq 169 -and $b1 -eq 254) { return $true }
    # Documentation / Test IPs (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if ($b0 -eq 192 -and $b1 -eq 0 -and [int]$parts[2] -eq 2) { return $true }
    if ($b0 -eq 198 -and $b1 -eq 51 -and [int]$parts[2] -eq 100) { return $true }
    if ($b0 -eq 203 -and $b1 -eq 0 -and [int]$parts[2] -eq 113) { return $true }
    # Benchmarking RFC 2544: 198.18.0.0/15
    if ($b0 -eq 198 -and ($b1 -eq 18 -or $b1 -eq 19)) { return $true }

    return $false
}

$files = Get-ChildItem -Path $repoRoot -Recurse -File | Where-Object {
    $rel = $_.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
    if ($rel -like ".git\*" -or $rel -like ".git/*") { return $false }
    if ($rel -like "_dist\*" -or $rel -like "_dist/*") { return $false }
    if ($rel -like "bin\*" -or $rel -like "bin/*") { return $false }
    $ext = $_.Extension.ToLowerInvariant()
    return ($allowedExts -contains $ext -or $_.Name -like "LICENSE*" -or $_.Name -like "*.md")
}

Write-Output ("Scanning {0} files for hygiene and privacy compliance..." -f $files.Count)

$forbiddenUser = "mo" + "hamed"
$forbiddenPath = "[A-Z]:[/\\]" + "Users[/\\]"
$forbiddenSSID = "iPhone" + "1337|" + "dlink-"

foreach ($f in $files) {
    $relPath = $f.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
    if ($relPath -eq "scripts\check-repo.ps1") { continue }
    $text = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    
    # 1. Em dash check (U+2014)
    if ($text.Contains([char]0x2014)) {
        $violations.Add("EM_DASH: $relPath contains forbidden character U+2014")
    }

    # 2. Local username check (forbids machine-local username leaks)
    if ($text -match "(?i)\b$forbiddenUser\b" -and $text -notmatch "(?i)Mohamed\s+Abderrahmane") {
        $violations.Add("USERNAME: $relPath contains local username '$forbiddenUser'")
    }

    # 3. Absolute user path check
    if ($text -match "(?i)$forbiddenPath") {
        $violations.Add("USER_PATH: $relPath contains absolute user path (C:\Users\...)")
    }

    # 4. Specific network names
    if ($text -match "(?i)$forbiddenSSID") {
        $violations.Add("NETWORK_NAME: $relPath contains private network SSID/name")
    }

    # 5. IPv4 addresses check
    $matches = [regex]::Matches($text, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    foreach ($m in $matches) {
        $ip = $m.Value
        if (-not (Is-PrivateOrAllowedIP $ip)) {
            $violations.Add("PUBLIC_IP: $relPath contains potential personal public IP: $ip")
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Output "`n======================================================="
    Write-Output "HYGIENE / PRIVACY CHECK FAILED ($($violations.Count) violations found):"
    Write-Output "======================================================="
    foreach ($v in $violations) {
        Write-Output "  - $v"
    }
    exit 1
} else {
    Write-Output "Repository hygiene and privacy check passed cleanly! (0 violations)"
    exit 0
}
