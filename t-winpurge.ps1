<#
██╗███╗   ███╗████████╗
██║████╗ ████║╚══██╔══╝
██║██╔████╔██║   ██║   
██║██║╚██╔╝██║   ██║   
██║██║ ╚═╝ ██║   ██║   
╚═╝╚═╝     ╚═╝   ╚═╝   
      I M T
Integrity • Morals • Trust

T-winpurge.ps1 - Interactive Uninstall Orchestrator v2.1
Author: Tony Khoriaty
Purpose: Full uninstall with inspection, confirmation, service control, and logging
#>

param (
    [switch]$Silent
)

# Prompt for log folder (with default fallback)
$logFolder = Read-Host "Enter path for log folder (default: A:\Logs)"
if ([string]::IsNullOrWhiteSpace($logFolder)) { $logFolder = "A:\Logs" }

if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder | Out-Null
}

# Time-stamped log file
$logFile = Join-Path $logFolder ("T-winpurge_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Log($message) {
    Add-Content $logFile "$(Get-Date): $message"
}

function Confirm($message) {
    if ($Silent) { return $true }
    return (Read-Host "$message (Y/N)") -eq "Y"
}

if ($Silent) {
    Write-Host "⚙️ Silent mode enabled — all confirmations auto-approved."
    Log "Silent mode enabled."
}

function Get-InstalledApps {
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $apps = @()
    foreach ($key in $uninstallKeys) {
        if (Test-Path $key) {
            Get-ChildItem $key | ForEach-Object {
                $app = Get-ItemProperty $_.PSPath
                if ($app.DisplayName -and $app.UninstallString) {
                    $apps += [PSCustomObject]@{
                        Name = $app.DisplayName
                        Version = $app.DisplayVersion
                        UninstallString = $app.UninstallString
                        RegistryPath = $_.PSPath
                    }
                }
            }
        }
    }
    return $apps
}

function Export-AppsToJson($apps) {
    $jsonPath = Join-Path $logFolder "InstalledApps_$(Get-Date -Format yyyyMMdd_HHmm).json"
    $apps | ConvertTo-Json -Depth 3 | Out-File $jsonPath
    Write-Host "📦 Exported installed apps to: $jsonPath"
    Log "Exported installed apps to JSON."
}

function Inspect-And-Delete($Path, $Type = "Folder") {
    if (Test-Path $Path) {
        Write-Host "`n[$Type] Found: $Path"
        Start-Process "explorer.exe" -ArgumentList "`"$Path`""
        Start-Sleep -Seconds 2
        if (Confirm "Delete this $Type after inspection?") {
            try {
                Remove-Item $Path -Recurse -Force -ErrorAction Stop
                Write-Host "✅ Deleted: $Path"
                Log "Deleted $Type → $Path"
            } catch {
                Write-Host "❌ Error deleting $Path: $($_.Exception.Message)"
                Log "ERROR deleting $Type → $Path → $($_.Exception.Message)"
            }
        } else {
            Write-Host "⏭️ Skipped: $Path"
            Log "Skipped $Type → $Path"
        }
    }
}

function Confirm-And-DeleteRegistry($KeyPath) {
    if (Test-Path $KeyPath) {
        $hive = ($KeyPath -split ":")[0]
        $key = ($KeyPath -split ":")[1]
        if (Confirm "Delete registry key Hive: $hive, Key: $key?") {
            try {
                Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
                Write-Host "✅ Deleted Registry: $KeyPath"
                Log "Deleted Registry → Hive: $hive, Key: $key"
            } catch {
                Write-Host "❌ Error deleting registry: $($_.Exception.Message)"
                Log "ERROR deleting Registry → $KeyPath → $($_.Exception.Message)"
            }
        } else {
            Write-Host "⏭️ Skipped Registry: $KeyPath"
            Log "Skipped Registry → $KeyPath"
        }
    }
}

function Stop-RelatedServices($services) {
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Stopped") {
            if (Confirm "Stop service $svc?") {
                try {
                    Stop-Service -Name $svc -Force
                    Set-Service -Name $svc -StartupType Disabled
                    Write-Host "🛑 Stopped service: $svc"
                    Log "Stopped service → $svc"
                } catch {
                    Write-Host "❌ Error stopping service: $($_.Exception.Message)"
                    Log "ERROR stopping service → $svc → $($_.Exception.Message)"
                }
            }
        }
    }
}

function Run-UninstallFlow($app) {
    Write-Host "`n🎯 Selected: $($app.Name) - $($app.Version)"
    Write-Host "🧨 Uninstall command: $($app.UninstallString)"
    if (Confirm "Run this uninstall command?") {
        try {
            if ($app.UninstallString -match "msiexec") {
                Start-Process "msiexec.exe" -ArgumentList "/x $($app.UninstallString -replace 'msiexec /x ', '') /quiet"
            } else {
                Start-Process "cmd.exe" -ArgumentList "/c `"$($app.UninstallString)`""
            }
            Log "Uninstall triggered → $($app.Name)"
        } catch {
            Write-Host "❌ Error running uninstall: $($_.Exception.Message)"
            Log "ERROR uninstalling → $($app.Name) → $($_.Exception.Message)"
        }
    }

    # Optional known folders to inspect
    $knownFolders = @(
        "$env:USERPROFILE\.android",
        "$env:LOCALAPPDATA\Android",
        "$env:USERPROFILE\.AndroidStudioBeta2025",
        "$env:APPDATA\Google"
    )
    foreach ($folder in $knownFolders) {
        Inspect-And-Delete $folder
    }

    Confirm-And-DeleteRegistry $app.RegistryPath

    # Optional runtime service input
    $svcInput = Read-Host "Enter related services to stop (comma-separated, or leave empty)"
    if ($svcInput) {
        Stop-RelatedServices ($svcInput -split ",")
    }
}

# === MAIN FLOW ===
Write-Host "`n🧠 T-winpurge v2.1: Interactive Uninstall Orchestrator"
Log "--- Uninstall Session Started ---"

$apps = Get-InstalledApps
Export-AppsToJson $apps

for ($i = 0; $i -lt $apps.Count; $i++) {
    Write-Host "$i. $($apps[$i].Name) - $($apps[$i].Version)"
}

$appIndex = Read-Host "Enter the number of the app to uninstall"
if ($appIndex -match '^\d+$' -and $appIndex -lt $apps.Count) {
    $selectedApp = $apps[$appIndex]
    Run-UninstallFlow $selectedApp
} else {
    Write-Host "❌ Invalid selection. Exiting."
}

Log "--- Uninstall Session Completed ---"

Write-Host "`n✅ Session complete. Log saved to $logFile"
Write-Host "📋 Summary:"
Get-Content $logFile | Select-String "Deleted|ERROR|Skipped" | ForEach-Object { $_.Line }
