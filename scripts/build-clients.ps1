$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = if ($env:VERSION) { $env:VERSION } else {
    try { git describe --tags --always --dirty 2>$null } catch { "dev" }
}
if (-not $version) { $version = "dev" }
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ldflags = "-s -w -X gokeeper/pkg/version.Version=$version -X gokeeper/pkg/version.BuildDate=$date"

$out = Join-Path $root "bin\clients"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Name = "gophkeeper-windows-amd64.exe" },
    @{ GOOS = "linux";   GOARCH = "amd64"; Name = "gophkeeper-linux-amd64" },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Name = "gophkeeper-darwin-amd64" }
)

foreach ($t in $targets) {
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $env:CGO_ENABLED = "0"
    Write-Host "building $($t.Name)"
    go build -ldflags $ldflags -o (Join-Path $out $t.Name) ./cmd/client
}

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

$manifest = @{
    version    = $version
    build_date = $date
    binaries   = @(
        @{ platform = "windows"; arch = "amd64"; filename = "gophkeeper-windows-amd64.exe" },
        @{ platform = "linux";   arch = "amd64"; filename = "gophkeeper-linux-amd64" },
        @{ platform = "darwin";  arch = "amd64"; filename = "gophkeeper-darwin-amd64" }
    )
} | ConvertTo-Json -Depth 5
Set-Content -Path (Join-Path $out "manifest.json") -Value $manifest -Encoding utf8
Write-Host "clients -> $out"
