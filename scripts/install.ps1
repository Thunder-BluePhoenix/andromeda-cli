# =============================================================================
# Andromeda CLI — Windows Installer
#
# Usage (one-liner — run from any PowerShell):
#   irm https://raw.githubusercontent.com/Thunder-BluePhoenix/andromeda-cli/main/scripts/install.ps1 | iex
#
# Or download and run manually:
#   .\install.ps1
#
# What this does:
#   1. Detects your CPU architecture
#   2. Downloads the correct andromeda.exe from GitHub releases
#   3. Installs to %LOCALAPPDATA%\Andromeda\andromeda.exe
#   4. Adds the install directory to your user PATH
# =============================================================================

$ErrorActionPreference = "Stop"

$repo       = "Thunder-BluePhoenix/andromeda-cli"
$installDir = "$env:LOCALAPPDATA\Andromeda"
$exeName    = "andromeda.exe"
$exePath    = Join-Path $installDir $exeName

# ─── Helpers ─────────────────────────────────────────────────────────────────
function Write-OK([string]$t)   { Write-Host "  [+] $t" -ForegroundColor Green }
function Write-Warn([string]$t) { Write-Host "  [!] $t" -ForegroundColor Yellow }
function Write-Err([string]$t)  { Write-Host "  [x] $t" -ForegroundColor Red; exit 1 }
function Write-Info([string]$t) { Write-Host "  $t"     -ForegroundColor White }

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  ANDROMEDA CLI — WINDOWS INSTALLER                      ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─── Detect architecture ─────────────────────────────────────────────────────
$arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
$assetName = "andromeda-windows-$arch.exe"
Write-Info "Platform   :  Windows $arch"
Write-Info "Asset      :  $assetName"

# ─── Fetch latest release from GitHub ────────────────────────────────────────
Write-Host ""
Write-Info "Fetching latest release from GitHub..."

$apiUrl  = "https://api.github.com/repos/$repo/releases/latest"
$headers = @{ "User-Agent" = "Andromeda-CLI-Installer" }

try {
    $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers
} catch {
    Write-Err "Could not reach GitHub API. Check your internet connection."
}

$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1

if (-not $asset) {
    $available = ($release.assets | Select-Object -ExpandProperty name) -join ", "
    Write-Err "Asset '$assetName' not found in release $($release.tag_name).`n  Available: $available"
}

Write-OK "Found       :  $($release.tag_name)  —  $assetName"
Write-OK "Download URL:  $($asset.browser_download_url)"

# ─── Download ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Info "Installing to: $exePath"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $exePath -UseBasicParsing
} catch {
    Write-Err "Download failed: $_"
}
Write-OK "Downloaded successfully"

# ─── Add to user PATH ────────────────────────────────────────────────────────
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if (-not $userPath) { $userPath = "" }
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    Write-OK "Added to PATH  (restart your terminal for this to take effect)"
} else {
    Write-OK "PATH already contains $installDir"
}

# ─── Done ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  ANDROMEDA CLI INSTALLED                                 ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Restart your terminal, then:" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    andromeda setup      " -ForegroundColor Cyan -NoNewline
Write-Host "— first-time setup wizard"
Write-Host "    andromeda install    " -ForegroundColor Cyan -NoNewline
Write-Host "— download the dashboard binary"
Write-Host "    andromeda start      " -ForegroundColor Cyan -NoNewline
Write-Host "— start the dashboard"
Write-Host "    andromeda --help     " -ForegroundColor Cyan -NoNewline
Write-Host "— show all commands"
Write-Host ""
