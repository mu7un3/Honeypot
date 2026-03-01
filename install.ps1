#Requires -Version 5.1
<#
.SYNOPSIS
    ML-Enhanced Honeypot — Windows Server Installer (PowerShell)
.DESCRIPTION
    Installs the honeypot and analytics dashboard as Windows services using NSSM
    (Non-Sucking Service Manager).  Requires PowerShell 5.1+ and Administrator
    privileges.
.PARAMETER NoService
    Install dependencies only; do not register Windows services.
.PARAMETER InstallDir
    Destination folder. Default: C:\honeypot
.PARAMETER DashboardPort
    Port for the Next.js dashboard. Default: 3000
.EXAMPLE
    .\install.ps1
    .\install.ps1 -NoService
    .\install.ps1 -InstallDir "D:\security\honeypot" -DashboardPort 8080
#>

[CmdletBinding()]
param(
    [switch]$NoService,
    [string]$InstallDir    = "C:\honeypot",
    [int]   $DashboardPort = 3000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colour helpers ─────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n── $msg ──" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor White }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── Admin check ────────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).`
           IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoService) {
    Write-Fail "Run PowerShell as Administrator to install services.`n       Or use -NoService for a dependency-only install."
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║    ML-Enhanced Honeypot — Windows Installer      ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# =============================================================================
# STEP 1 — Python
# =============================================================================
Write-Step "1 / 6  Python"

$pythonExe = $null
foreach ($cmd in @("python","python3","py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.(1[0-9]|[2-9]\d)") {
            $pythonExe = (Get-Command $cmd).Source
            Write-OK "Found $cmd  ($ver)"
            break
        }
    } catch { continue }
}

if (-not $pythonExe) {
    Write-Warn "Python 3.10+ not found. Attempting auto-install via winget..."
    try {
        winget install --id Python.Python.3.11 -e --source winget `
              --accept-package-agreements --accept-source-agreements
        # Refresh PATH for this session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $pythonExe = (Get-Command python -ErrorAction SilentlyContinue)?.Source
        if (-not $pythonExe) {
            Write-Fail "Python installed but not on PATH yet.`n       Close this window and re-run install.ps1 as Administrator."
        }
    } catch {
        Write-Fail "winget auto-install failed. Install Python 3.10+ from https://python.org/downloads`n       Make sure 'Add Python to PATH' is checked."
    }
}

# =============================================================================
# STEP 2 — Node.js
# =============================================================================
Write-Step "2 / 6  Node.js (web dashboard)"

$nodeOK = $false
try {
    $nodeVer = & node --version 2>&1
    $nodeMaj = [int]($nodeVer -replace "v(\d+)\..*",'$1')
    if ($nodeMaj -ge 18) { Write-OK "Node.js $nodeVer"; $nodeOK = $true }
    else { Write-Warn "Node.js $nodeVer is below v18." }
} catch {}

if (-not $nodeOK) {
    Write-Warn "Node.js 18+ not found. Attempting auto-install via winget..."
    try {
        winget install --id OpenJS.NodeJS.LTS -e --source winget `
              --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        Write-OK "Node.js installed."
    } catch {
        Write-Warn "Node.js auto-install failed. Install from https://nodejs.org (LTS)."
        Write-Warn "The terminal dashboard will still work without Node.js."
    }
}

# =============================================================================
# STEP 3 — Copy files
# =============================================================================
Write-Step "3 / 6  Installing files to $InstallDir"

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# Honeypot source
Copy-Item -Recurse -Force "$ScriptDir\honeypot\*" "$InstallDir\"

# Dashboard
$dashDest = "$InstallDir\honeypot-analytics"
if (-not (Test-Path $dashDest)) { New-Item -ItemType Directory -Path $dashDest | Out-Null }
Copy-Item -Recurse -Force "$ScriptDir\honeypot-analytics\*" "$dashDest\"

Write-OK "Files installed to $InstallDir"

# =============================================================================
# STEP 4 — Python dependencies + .env
# =============================================================================
Write-Step "4 / 6  Python dependencies"

& $pythonExe -m pip install --quiet --upgrade pip
& $pythonExe -m pip install --quiet scikit-learn numpy requests python-dotenv
Write-OK "Python packages installed."

$envFile = "$InstallDir\.env"
$envExample = "$InstallDir\.env.example"
if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Warn ".env created from template."
        Write-Warn "Edit $envFile to set email credentials before starting the honeypot."
        Start-Process notepad.exe $envFile -Wait
    }
}

# =============================================================================
# STEP 5 — Train ML models
# =============================================================================
Write-Step "5 / 6  Training ML models"

$trainData = "$InstallDir\data\honeypot_synthetic.json"
if (Test-Path $trainData) {
    $env:PYTHONPATH = $InstallDir
    try {
        & $pythonExe "$InstallDir\ml\ml_pipeline.py" train $trainData
        Write-OK "ML models trained."
    } catch {
        Write-Warn "ML training failed. Honeypot will run without ML scoring."
        Write-Warn "Re-try manually: set PYTHONPATH=$InstallDir && python $InstallDir\ml\ml_pipeline.py train $trainData"
    }
} else {
    Write-Warn "Training data not found. Skipping ML training."
}

# =============================================================================
# STEP 6 — Windows service via NSSM
# =============================================================================
Write-Step "6 / 6  Windows services"

if ($NoService) {
    Write-Warn "-NoService flag set. Skipping service registration."
    Write-Info "Start manually (run as Administrator):"
    Write-Info "  set PYTHONPATH=$InstallDir"
    Write-Info "  python $InstallDir\honeypot.py"
    Write-Info ""
    Write-Info "  cd $InstallDir\honeypot-analytics && npm install && npm run build && npm run start"
} else {

    # ── Download NSSM if not present ─────────────────────────────────────────
    $nssmExe = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
    if (-not $nssmExe) {
        Write-Info "NSSM not found. Downloading..."
        $nssmZip  = "$env:TEMP\nssm.zip"
        $nssmDir  = "$env:TEMP\nssm"
        $nssmUrl  = "https://nssm.cc/release/nssm-2.24.zip"
        try {
            Invoke-WebRequest $nssmUrl -OutFile $nssmZip -UseBasicParsing
            Expand-Archive $nssmZip -DestinationPath $nssmDir -Force
            # NSSM zip has win32/win64 subdirs
            $arch   = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
            $nssmBin = Get-ChildItem "$nssmDir" -Recurse -Filter "nssm.exe" |
                       Where-Object { $_.FullName -match $arch } |
                       Select-Object -First 1
            if (-not $nssmBin) { $nssmBin = Get-ChildItem "$nssmDir" -Recurse -Filter "nssm.exe" | Select-Object -First 1 }
            $nssmExe = "$InstallDir\nssm.exe"
            Copy-Item $nssmBin.FullName $nssmExe
            Write-OK "NSSM downloaded to $nssmExe"
        } catch {
            Write-Warn "Could not download NSSM. Falling back to sc.exe service wrapper."
            $nssmExe = $null
        }
    }

    # ── Helper: remove existing service if present ────────────────────────────
    function Remove-ServiceIfExists([string]$name) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            Write-Info "Removing existing service: $name"
            if ($nssmExe) { & $nssmExe remove $name confirm }
            else           { sc.exe delete $name | Out-Null }
            Start-Sleep 2
        }
    }

    # ──────────────────────────────────────────────────────────────────────────
    # Service 1: honeypot
    # ──────────────────────────────────────────────────────────────────────────
    Remove-ServiceIfExists "honeypot"

    if ($nssmExe) {
        & $nssmExe install honeypot $pythonExe "$InstallDir\honeypot.py"
        & $nssmExe set     honeypot AppDirectory   $InstallDir
        & $nssmExe set     honeypot AppEnvironmentExtra `
                                    "PYTHONPATH=$InstallDir" `
                                    "HONEYPOT_BASE_DIR=$InstallDir" `
                                    "HONEYPOT_LOG_FILE=$InstallDir\honeypot.log" `
                                    "HONEYPOT_MODELS_DIR=$InstallDir\models"
        & $nssmExe set     honeypot AppStdout      "$InstallDir\honeypot-stdout.log"
        & $nssmExe set     honeypot AppStderr      "$InstallDir\honeypot-stderr.log"
        & $nssmExe set     honeypot Start          SERVICE_AUTO_START
        & $nssmExe set     honeypot Description    "ML-Enhanced Honeypot (multi-port attacker trap)"
    } else {
        # Fallback: wrapper batch + sc.exe
        $wrapBat = "$InstallDir\svc_honeypot.bat"
        Set-Content $wrapBat "@echo off`r`nset PYTHONPATH=$InstallDir`r`nset HONEYPOT_BASE_DIR=$InstallDir`r`nset HONEYPOT_LOG_FILE=$InstallDir\honeypot.log`r`nset HONEYPOT_MODELS_DIR=$InstallDir\models`r`npython $InstallDir\honeypot.py"
        sc.exe create honeypot binPath= "`"$env:ComSpec`" /c `"$wrapBat`"" start= auto | Out-Null
        sc.exe description honeypot "ML-Enhanced Honeypot" | Out-Null
    }

    Write-OK "Service 'honeypot' registered."

    # ──────────────────────────────────────────────────────────────────────────
    # Service 2: honeypot-dashboard
    # ──────────────────────────────────────────────────────────────────────────
    Remove-ServiceIfExists "honeypot-dashboard"

    $npmExe = (Get-Command npm -ErrorAction SilentlyContinue)?.Source
    if ($npmExe) {
        Write-Info "Building Next.js dashboard..."
        Push-Location "$InstallDir\honeypot-analytics"
        try {
            $env:HONEYPOT_LOG_FILE = "$InstallDir\honeypot.log"
            & $npmExe install 2>&1 | Out-Null
            & $npmExe run build  2>&1 | Out-Null
            Write-OK "Dashboard built."
        } catch { Write-Warn "Dashboard build failed. Run manually: cd $InstallDir\honeypot-analytics && npm install && npm run build" }
        Pop-Location

        if ($nssmExe) {
            & $nssmExe install honeypot-dashboard $npmExe "run start"
            & $nssmExe set     honeypot-dashboard AppDirectory          "$InstallDir\honeypot-analytics"
            & $nssmExe set     honeypot-dashboard AppEnvironmentExtra   `
                                                  "NODE_ENV=production" `
                                                  "PORT=$DashboardPort" `
                                                  "HONEYPOT_LOG_FILE=$InstallDir\honeypot.log"
            & $nssmExe set     honeypot-dashboard AppStdout             "$InstallDir\dashboard-stdout.log"
            & $nssmExe set     honeypot-dashboard AppStderr             "$InstallDir\dashboard-stderr.log"
            & $nssmExe set     honeypot-dashboard Start                 SERVICE_AUTO_START
            & $nssmExe set     honeypot-dashboard Description           "Honeypot Analytics Dashboard (Next.js)"
        } else {
            $wrapDash = "$InstallDir\svc_dashboard.bat"
            Set-Content $wrapDash "@echo off`r`nset NODE_ENV=production`r`nset PORT=$DashboardPort`r`nset HONEYPOT_LOG_FILE=$InstallDir\honeypot.log`r`ncd /d $InstallDir\honeypot-analytics`r`nnpm run start"
            sc.exe create honeypot-dashboard binPath= "`"$env:ComSpec`" /c `"$wrapDash`"" start= auto | Out-Null
        }
        Write-OK "Service 'honeypot-dashboard' registered."
    } else {
        Write-Warn "npm not found — skipping dashboard service. Install Node.js then re-run."
    }

    # ── Start services ────────────────────────────────────────────────────────
    Start-Service honeypot          -ErrorAction SilentlyContinue
    Start-Service honeypot-dashboard -ErrorAction SilentlyContinue
    Write-OK "Services started."

    Write-Host ""
    Write-Host "  Service management:" -ForegroundColor Cyan
    Write-Host "    Get-Service honeypot, honeypot-dashboard"
    Write-Host "    Restart-Service honeypot"
    Write-Host "    Stop-Service honeypot"
    Write-Host "    Get-Content $InstallDir\honeypot-stdout.log -Wait  (live log)"
    Write-Host ""
    Write-Host "  Or open Services (services.msc) to manage them visually." -ForegroundColor Gray
}

# =============================================================================
# Done
# =============================================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║         INSTALLATION COMPLETE                    ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir : $InstallDir"
Write-Host "  Config      : $InstallDir\.env"
Write-Host "  Log file    : $InstallDir\honeypot.log"
Write-Host "  Dashboard   : http://localhost:$DashboardPort"
Write-Host ""
Write-Host "  ACTION REQUIRED: Edit $InstallDir\.env" -ForegroundColor Yellow
Write-Host "  Set SENDER_EMAIL, RECIPIENT_EMAIL, SENDER_PASSWORD for email alerts."
Write-Host ""
Write-Host "  To uninstall: Run uninstall.ps1 as Administrator"
Write-Host ""
