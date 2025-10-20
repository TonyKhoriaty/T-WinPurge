<#
██╗███╗   ███╗████████╗
██║████╗ ████║╚══██╔══╝
██║██╔████╔██║   ██║   
██║██║╚██╔╝██║   ██║   
██║██║ ╚═╝ ██║   ██║   
╚═╝╚═╝     ╚═╝   ╚═╝   
      I M T
Integrity • Morals • Trust

Purpose: Full uninstall with inspection, confirmation, service control, and logging
#>

param (
    [switch]$Silent,
    [switch]$DryRun
)

# ====== CONFIG ======
$MaxDepth = 6
$LogRootDefault = "A:\Logs"
$SafeExcludeRoots = @("$env:SystemRoot", "$env:ProgramFiles", "$env:ProgramFiles(x86)")
# ====================

# Prompt for log folder
$logFolder = Read-Host "Enter path for log folder (default: $LogRootDefault)"
if ([string]::IsNullOrWhiteSpace($logFolder)) { $logFolder = $LogRootDefault }

if (-not (Test-Path $logFolder)) {
    try {
        New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
    } catch {
        Write-Host "❌ Failed to create log folder: $($_.Exception.Message)"
        exit 1
    }
}

$logFile = Join-Path $logFolder "T-winpurge.log"
function Log($message) {
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') : $message"
}

if ($DryRun) { Write-Host "🧪 Dry-run mode enabled — no deletions or service stops will be performed."; Log "Dry-run mode enabled." }
if ($Silent) { Write-Host "⚙️ Silent mode enabled — confirmations auto-approved."; Log "Silent mode enabled." }

function Confirm($message) {
    if ($DryRun) { return $true }
    if ($Silent) { return $true }
    return ((Read-Host "$message (Y/N)") -match '^[Yy]$')
}

# ---------------------------
# Enhanced app detection
# ---------------------------
function Get-InstalledApps {
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $apps = @()

    foreach ($key in $uninstallKeys) {
        if (Test-Path $key) {
            Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props -and $props.DisplayName) {
                    $apps += [PSCustomObject]@{
                        Name            = $props.DisplayName
                        Version         = $props.DisplayVersion
                        Publisher       = $props.Publisher
                        InstallDate     = $props.InstallDate
                        InstallLocation = if ($props.PSObject.Properties.Match("InstallLocation")) { $props.InstallLocation } else { $null }
                        UninstallString = $props.UninstallString
                        RegistryPath    = $_.PSPath
                    }
                }
            }
        }
    }

    # MSI-installed apps
    $msiKey = "HKLM:\SOFTWARE\Classes\Installer\Products"
    if (Test-Path $msiKey) {
        Get-ChildItem $msiKey -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($props -and $props.ProductName) {
                $apps += [PSCustomObject]@{
                    Name            = $props.ProductName
                    Version         = $props.Version
                    Publisher       = $props.Publisher
                    InstallDate     = $null
                    InstallLocation = $null
                    UninstallString = $null
                    RegistryPath    = $_.PSPath
                }
            }
        }
    }

    return $apps
}

function Export-AppsToJson($apps) {
    $jsonPath = Join-Path $logFolder "InstalledApps.json"
    try {
        $apps | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "📦 Exported installed apps to: $jsonPath"
        Log "Exported installed apps to JSON → $jsonPath"
    } catch {
        Write-Host "❌ Failed to export JSON: $($_.Exception.Message)"
        Log "ERROR exporting apps to JSON → $($_.Exception.Message)"
    }
}

# ---------------------------
# Safe Inspect-And-Delete
# ---------------------------
function Inspect-And-Delete([string]$Path, [string]$Type = "Folder") {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path $Path)) { return }

    Write-Host "`n[$Type] Found: $Path"

    if (-not $Silent -and -not $DryRun) {
        try { Start-Process "explorer.exe" -ArgumentList "`"$Path`"" -ErrorAction SilentlyContinue } catch {}
        Start-Sleep -Seconds 2
    }

    if ($DryRun) {
        Write-Host ("🧪 [DRY-RUN] Would delete ${Type}: ${Path}")
        Log ("[DRY-RUN] Would delete ${Type}: ${Path}")
        return
    }

    if (Confirm "Delete this $Type after inspection?") {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Host ("✅ Deleted: ${Path}")
            Log ("[LEFTOVER] Deleted ${Type}: ${Path}")
        } catch {
            Write-Host ("❌ Error deleting ${Path}: $($_.Exception.Message)")
            Log ("ERROR deleting ${Type}: ${Path} → $($_.Exception.Message)")
        }
    } else {
        Write-Host ("⏭️ Skipped: ${Path}")
        Log ("Skipped ${Type}: ${Path}")
    }
}

# ---------------------------
# Registry deletion (safe)
# ---------------------------
function Confirm-And-DeleteRegistry([string]$KeyPath) {
    if ([string]::IsNullOrWhiteSpace($KeyPath)) { 
        Write-Host "⚠️ No registry key path provided. Skipping registry deletion."
        Log "SKIPPED Registry → empty path"
        return
    }
    if (Test-Path $KeyPath) {
        $display = $KeyPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
        if ($DryRun) {
            Write-Host ("🧪 [DRY-RUN] Would delete registry key: ${display}")
            Log ("[DRY-RUN] Would delete registry key → ${display}")
            return
        }
        if (Confirm "Delete registry key: $display ?") {
            try {
                Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
                Write-Host ("✅ Deleted Registry: ${display}")
                Log ("Deleted Registry → ${display}")
            } catch {
                Write-Host ("❌ Error deleting registry: $($_.Exception.Message)")
                Log ("ERROR deleting Registry → ${display} → $($_.Exception.Message)")
            }
        } else {
            Write-Host ("⏭️ Skipped Registry: ${display}")
            Log ("Skipped Registry → ${display}")
        }
    } else {
        Write-Host ("ℹ️ Registry path not found: ${KeyPath}")
        Log ("SKIPPED Registry → NotFound: ${KeyPath}")
    }
}

# ---------------------------
# Services stop helper
# ---------------------------
function Stop-RelatedServices($services) {
    foreach ($svc in $services) {
        $svcTrim = $svc.Trim()
        if ([string]::IsNullOrWhiteSpace($svcTrim)) { continue }
        try {
            $service = Get-Service -Name $svcTrim -ErrorAction Stop
        } catch {
            Write-Host ("⚠️ Cannot query service ${svcTrim}: $($_.Exception.Message)")
            Log ("SKIPPED ServiceQuery → ${svcTrim} → $($_.Exception.Message)")
            continue
        }
        if ($service -and $service.Status -ne "Stopped") {
            if ($DryRun) {
                Write-Host ("🧪 [DRY-RUN] Would stop service: ${svcTrim}")
                Log ("[DRY-RUN] Would stop service → ${svcTrim}")
                continue
            }
            if (Confirm "Stop service $svcTrim?") {
                try {
                    Stop-Service -Name $svcTrim -Force -ErrorAction Stop
                    Set-Service -Name $svcTrim -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Host ("🛑 Stopped service: ${svcTrim}")
                    Log ("Stopped service → ${svcTrim}")
                } catch {
                    Write-Host ("❌ Error stopping service: $($_.Exception.Message)")
                    Log ("ERROR stopping service → ${svcTrim} → $($_.Exception.Message)")
                }
            }
        }
    }
}

# ---------------------------
# Helper: extract install path from uninstall string
# ---------------------------
function Get-InstallPathFromUninstallString($uninstallString) {
    if (-not $uninstallString) { return $null }
    $s = $uninstallString -replace '"',''
    try {
        if (Test-Path $s) {
            return (Split-Path -Path $s -Parent)
        }
        $parts = $s -split '\s+'
        $candidate = $parts[0]
        if (Test-Path $candidate) {
            return (Split-Path -Path $candidate -Parent)
        }
    } catch {}
    return $null
}

# ---------------------------
# Recursive search with max depth
# ---------------------------
function Find-RelatedLeftovers($appName, [string[]]$roots, [int]$maxDepth) {
    $found = @()
    $nameRegex = [regex]::Escape($appName)
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }

        $skipRoot = $false
        foreach ($ex in $SafeExcludeRoots) {
            if ($root -like "$ex*") { $skipRoot = $true }
        }
        foreach ($r in $roots) {
            if ($r -and ($r -eq $root) -and ($r -ne $null)) { $skipRoot = $false; break }
        }
        if ($skipRoot -and ($roots -notcontains $root)) { continue }

        $stack = @()
        try {
            $rootItem = Get-Item $root -Force -ErrorAction SilentlyContinue
            if (-not $rootItem) { continue }
            $stack += @{ Path = $rootItem.FullName; Depth = 0 }
        } catch { continue }

        while ($stack.Count -gt 0) {
            $entry = $stack[-1]; $stack = $stack[0..($stack.Count-2)]
            $currentPath = $entry.Path; $depth = $entry.Depth
            try {
                $attr = (Get-Item $currentPath -Force -ErrorAction SilentlyContinue).Attributes
                if ($attr -band [IO.FileAttributes]::ReparsePoint) { continue }
            } catch {}

            if ($currentPath -match $nameRegex) { $found += $currentPath }
            if ($depth -ge $maxDepth) { continue }

            try {
                Get-ChildItem -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.PSIsContainer) {
                        $childPath = $_.FullName
                        $stack += @{ Path = $childPath; Depth = ($depth + 1) }
                        if ($childPath -match $nameRegex) { $found += $childPath }
                    } else {
                        $filePath = $_.FullName
                        if ($filePath -match $nameRegex) { $found += $filePath }
                    }
                }
            } catch { continue }
        }
    }
    return $found | Sort-Object -Unique
}

# ---------------------------
# Registry purge helper
# ---------------------------
function Purge-AppRegistry($appName) {
    $searchKeys = @(
        "HKCU:\Software",
        "HKLM:\Software",
        "HKLM:\Software\WOW6432Node"
    )

    foreach ($key in $searchKeys) {
        try {
            Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSChildName -match [regex]::Escape($appName)) {
                    Confirm-And-DeleteRegistry $_.PSPath
                }
            }
        } catch { Log ("ERROR scanning registry root ${key} → $($_.Exception.Message)"); continue }
    }
}

# ---------------------------
# Uninstall + dynamic purge flow
# ---------------------------
function Run-UninstallFlow($app) {
    Write-Host "`n🎯 Selected: $($app.Name) - $($app.Version)"
    Write-Host "🧨 Uninstall command: $($app.UninstallString)"

    if ($app.UninstallString) {
        if ($DryRun) {
            Write-Host ("🧪 [DRY-RUN] Would run uninstall command: $($app.UninstallString)")
            Log ("[DRY-RUN] Would run uninstall → $($app.Name)")
        } else {
            if (Confirm "Run this uninstall command?") {
                try {
                    if ($app.UninstallString -and ($app.UninstallString -match "msiexec")) {
                        Start-Process "msiexec.exe" -ArgumentList "/x $($app.UninstallString -replace '.*{','{') /quiet" -NoNewWindow
                    } else {
                        Start-Process "cmd.exe" -ArgumentList "/c `"$($app.UninstallString)`"" -NoNewWindow
                    }
                    Log ("Uninstall triggered → $($app.Name)")
                } catch {
                    Write-Host ("❌ Error running uninstall: $($_.Exception.Message)")
                    Log ("ERROR uninstalling → $($app.Name) → $($_.Exception.Message)")
                }
            } else {
                Write-Host "⏭️ User declined to run uninstall command."
                Log ("User declined uninstall → $($app.Name)")
            }
        }
    } else {
        Write-Host "⚠️ No uninstall command found for this entry. You may need to uninstall manually."
        Log ("No uninstall string for → $($app.Name) (Registry: $($app.RegistryPath))")
    }

    if ($app.RegistryPath -and -not [string]::IsNullOrWhiteSpace($app.RegistryPath)) {
        $regPath = $app.RegistryPath
        if ($regPath -notmatch 'Microsoft\.PowerShell\.Core\\Registry::') {
            $regPath = "Microsoft.PowerShell.Core\Registry::" + ($app.RegistryPath -replace '^HKLM:','HKLM:\' -replace '^HKCU:','HKCU:\')
        }
        Confirm-And-DeleteRegistry $regPath
    } else {
        Write-Host "ℹ️ No explicit registry uninstall path available; scanning registry for related keys."
        Log ("SKIPPED explicit registry delete → none for $($app.Name)")
        Purge-AppRegistry $app.Name
    }

    $roots = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, "C:\ProgramData")
    $installPath = $app.InstallLocation
    if (-not $installPath) { $installPath = Get-InstallPathFromUninstallString $app.UninstallString }
    if ($installPath -and (Test-Path $installPath)) { $roots = ,$installPath + ($roots | Where-Object { $_ -ne $installPath }) }

    Write-Host "`n🔎 Scanning for leftovers related to: $($app.Name)..."
    $leftovers = Find-RelatedLeftovers $app.Name $roots $MaxDepth

    if (-not $leftovers -or $leftovers.Count -eq 0) {
        Write-Host "✅ No obvious leftover files/folders found for $($app.Name)."
        Log ("No leftovers found → $($app.Name)")
    } else {
        Write-Host "`nFound $($leftovers.Count) possible leftover items related to '$($app.Name)'."
        Log ("Found $($leftovers.Count) leftovers → $($app.Name)")
        foreach ($item in $leftovers) {
            $type = "File"
            try { if (Test-Path $item -PathType Container) { $type = "Folder" } } catch {}
            Inspect-And-Delete $item $type
        }
    }

    try {
        $svcList = @()
        try {
            $allSvcs = Get-Service -ErrorAction Stop
            $svcList = $allSvcs | Where-Object { $_.Name -match [regex]::Escape($app.Name) -or $_.DisplayName -match [regex]::Escape($app.Name) }
        } catch {
            try { $svcList = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match [regex]::Escape($app.Name) -or $_.DisplayName -match [regex]::Escape($app.Name) } } catch { $svcList = @() }
        }
        if ($svcList -and $svcList.Count -gt 0) { Stop-RelatedServices ($svcList.Name) }
        else { Write-Host "ℹ️ No services found that reference '$($app.Name)'."; Log ("No related services → $($app.Name)") }
    } catch { Write-Host ("⚠️ Skipping service check due to error: $($_.Exception.Message)"); Log ("ERROR service scan → $($_.Exception.Message)") }
}

# ---------------------------
# MAIN FLOW
# ---------------------------
Write-Host "`n🧠 T-winpurge v3.4: Interactive Uninstall Orchestrator + Auto-Purge"
Log "--- Uninstall Session Started ---"

$apps = Get-InstalledApps
Export-AppsToJson $apps

for ($i = 0; $i -lt $apps.Count; $i++) {
    Write-Host "$i. $($apps[$i].Name) - $($apps[$i].Version)"
}

$appIndex = Read-Host "Enter the number of the app to uninstall (or type 'deep' to run WMI scan first)"
if ($appIndex -eq "deep") {
    try {
        Write-Host "🔎 Running WMI (Win32_Product) deep scan — this may be slow..."
        Log "WMI deep scan started by user."
        $wmiApps = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue
        foreach ($w in $wmiApps) {
            $apps += [PSCustomObject]@{
                Name            = $w.Name
                Version         = $w.Version
                Publisher       = $w.Vendor
                InstallDate     = $w.InstallDate
                InstallLocation = $null
                UninstallString = $w.IdentifyingNumber
                RegistryPath    = "Win32_Product"
            }
        }
        Export-AppsToJson $apps
        for ($i = 0; $i -lt $apps.Count; $i++) { Write-Host "$i. $($apps[$i].Name) - $($apps[$i].Version)" }
        $appIndex = Read-Host "Enter the number of the app to uninstall"
    } catch {
        Write-Host ("⚠️ WMI deep scan failed or aborted: $($_.Exception.Message)")
        Log ("ERROR WMI deep scan → $($_.Exception.Message)")
    }
}

if ($appIndex -match '^\d+$' -and [int]$appIndex -ge 0 -and [int]$appIndex -lt $apps.Count) {
    $selectedApp = $apps[[int]$appIndex]

    Write-Host ""
    Write-Host ("⚠️  You selected: $($selectedApp.Name) - $($selectedApp.Version)")
    Write-Host "To confirm uninstall, type the app name exactly (or type DELETE)."
    $typed = Read-Host "Type confirmation"

    if ($typed -eq "DELETE" -or $typed -ieq $selectedApp.Name) {
        Write-Host ("🧹 Proceeding to uninstall → $($selectedApp.Name)")
        Log ("Confirmed uninstall → $($selectedApp.Name)")
        Run-UninstallFlow $selectedApp
    } else {
        Write-Host "⏭️  Uninstall aborted — confirmation did not match."
        Log ("User aborted uninstall due to confirmation mismatch → $($selectedApp.Name)")
    }
} else {
    Write-Host "❌ Invalid selection or no action selected. Exiting."
    Log "Invalid selection or exited by user."
}

Log "--- Uninstall Session Completed ---"
Write-Host ("`n✅ Session complete. Log saved to ${logFile}")
