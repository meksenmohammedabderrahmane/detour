# github-release.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dist = Join-Path $repoRoot "_dist"

$owner = "meksenmohammedabderrahmane"
$repo = "detour"
$tag = "v0.1.0"
$releaseTitle = "Detour v0.1.0: Initial Public Release"

$notesFile = Join-Path $repoRoot "docs\RELEASE_NOTES_v0.1.0.md"
$body = [System.IO.File]::ReadAllText($notesFile, [System.Text.Encoding]::UTF8)

$headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github.v3+json"
    "User-Agent" = "Detour-Release-Agent"
}

Write-Output "Checking if release $tag already exists..."
$releasesUrl = "https://api.github.com/repos/$owner/$repo/releases"
$release = $null

try {
    $existing = Invoke-RestMethod -Uri "$releasesUrl/tags/$tag" -Headers $headers -Method Get
    if ($existing -and $existing.id) {
        Write-Output "Release for $tag already exists (ID: $($existing.id))."
        $release = $existing
    }
} catch {
    # 404 means it does not exist yet
}

if (-not $release) {
    Write-Output "Creating release $tag..."
    $payload = @{
        tag_name = $tag
        name = $releaseTitle
        body = $body
        draft = $false
        prerelease = $false
    } | ConvertTo-Json

    $release = Invoke-RestMethod -Uri $releasesUrl -Headers $headers -Method Post -Body $payload
    Write-Output "Release created successfully! (ID: $($release.id))"
}

$uploadBase = $release.upload_url -replace '\{\?name,label\}', ''
Write-Output "Upload base URL: $uploadBase"

$assets = @(
    @{ Name = "DetourSetup-0.1.0.exe"; Path = (Join-Path $dist "DetourSetup-0.1.0.exe"); ContentType = "application/octet-stream" },
    @{ Name = "detour-v0.1.0-windows-amd64.zip"; Path = (Join-Path $dist "detour-v0.1.0-windows-amd64.zip"); ContentType = "application/zip" },
    @{ Name = "SHA256SUMS.txt"; Path = (Join-Path $dist "SHA256SUMS.txt"); ContentType = "text/plain" }
)

foreach ($asset in $assets) {
    Write-Output "`nUploading asset: $($asset.Name)..."
    
    # Check if asset already exists on this release
    $existingAsset = $release.assets | Where-Object { $_.name -eq $asset.Name }
    if ($existingAsset) {
        Write-Output "Asset $($asset.Name) already exists on release. Deleting old asset ID: $($existingAsset.id)..."
        $delUrl = "https://api.github.com/repos/$owner/$repo/releases/assets/$($existingAsset.id)"
        Invoke-RestMethod -Uri $delUrl -Headers $headers -Method Delete
    }

    $uploadUrl = "$uploadBase`?name=$($asset.Name)"
    $uploadHeaders = @{
        "Authorization" = "token $Token"
        "Accept" = "application/vnd.github.v3+json"
        "User-Agent" = "Detour-Release-Agent"
        "Content-Type" = $asset.ContentType
    }

    $res = Invoke-RestMethod -Uri $uploadUrl -Headers $uploadHeaders -Method Post -InFile $asset.Path
    Write-Output "Uploaded $($asset.Name) successfully! (Size: $($res.size) bytes, URL: $($res.browser_download_url))"
}

Write-Output "`n=== RELEASE PUBLISHED SUCCESSFULLY ==="
Write-Output "HTML URL: $($release.html_url)"
