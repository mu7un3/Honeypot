#Requires -Version 5.1
<#
.SYNOPSIS
    ML-Enhanced Honeypot — Windows Uninstaller
.DESCRIPTION
    Stops and removes the honeypot Windows services and optionally deletes
    the installation directory.  Requires Administrator privileges.
.PARAMETER InstallDir
    Folder where the honeypot was installed. Default: C:\honeypot
.PARAMETER KeepFiles
    Stop/remove services but keep the installation files.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\honeypot",
    [switch]$KeepFiles
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).`
           IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Run PowerShell as Administrator." -ForegroundColor Red; exit 1
}

Write-Host ""
Write-Host "ML-Enhanced Honeypot — Uninstaller" -ForegroundColor Red
Write-Host ""

$nssmExe = if (Test-Path "$InstallDir\nssm.exe") { "$InstallDir\nssm.exe" }
           elseif (Get-Command nssm -ErrorAction SilentlyContinue) { "nssm" }
           else { $null }

foreach ($svc in @("honeypot","honeypot-dashboard")) {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s) {
        if ($s.Status -eq "Running") {
            Stop-Service $svc -Force
            Write-Host "[OK]    Service '$svc' stopped." -ForegroundColor Green
        }
        if ($nssmExe) {
            & $nssmExe remove $svc confirm 2>$null
        } else {
            sc.exe delete $svc | Out-Null
        }
        Write-Host "[OK]    Service '$svc' removed." -ForegroundColor Green
    } else {
        Write-Host "[INFO]  Service '$svc' not found, skipping." -ForegroundColor Gray
    }
}

if (-not $KeepFiles -and (Test-Path $InstallDir)) {
    $answer = Read-Host "Remove installation directory '$InstallDir'? [y/N]"
    if ($answer -match "^[Yy]$") {
        Remove-Item -Recurse -Force $InstallDir
        Write-Host "[OK]    Removed $InstallDir" -ForegroundColor Green
    } else {
        Write-Host "[INFO]  Kept $InstallDir" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Host ""
