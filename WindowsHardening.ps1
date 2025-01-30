# Here's the corrected version with proper PowerShell syntax:
<#
.SYNOPSIS
    Windows Hardening Script (Blacklist-based) with optional security updates.

.DESCRIPTION
    - Reads a JSON config file containing:
      1) A blacklist of unauthorized programs to remove.
      2) UAC settings.
      3) Optional firewall rule definitions.
      4) Whether or not to apply security updates.
    - Uninstalls blacklisted programs found on the system.
    - Applies UAC settings to the registry.
    - Configures optional firewall rules.
    - Installs Windows security updates if specified.

.NOTES
    Author:        Ethan Hulse
    Created:       2025-01-29
    Version:       1.5.4

    DISCLAIMER:
    - Always test thoroughly in a lab or staging environment.
    - Removing programs, changing registry settings, or installing updates can impact system stability.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

# ---------------------------------------------------
# 1. Validate and Load Configuration
# ---------------------------------------------------
if (-not (Test-Path -Path $ConfigPath)) {
    Write-Error "Config file not found at $ConfigPath. Script will exit."
    exit 1
}

try {
    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    Write-Host "`n[INFO] Configuration loaded from $ConfigPath"
} catch {
    Write-Error "Failed to read or parse JSON config: $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------
# 2. Remove Blacklisted Programs
# ---------------------------------------------------
if ($null -ne $Config.BlacklistedPrograms -and @($Config.BlacklistedPrograms).Count -gt 0) {
    Write-Host "`n[INFO] Checking for blacklisted programs..."

    # Using Get-Package is more reliable than Get-WmiObject
    $installedApps = Get-Package -ErrorAction SilentlyContinue

    foreach ($blacklisted in $Config.BlacklistedPrograms) {
        $foundApps = $installedApps | Where-Object { $_.Name -like "*$blacklisted*" }

        foreach ($app in $foundApps) {
            Write-Host "[WARNING] Found blacklisted app: $($app.Name). Attempting to remove..."
            try {
                $app | Uninstall-Package -Force -ErrorAction Stop
                Write-Host "[INFO] Successfully removed: $($app.Name)"
            } catch {
                Write-Warning "[ERROR] Failed to remove $($app.Name): $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Host "[INFO] No blacklisted programs specified"
}

# ---------------------------------------------------
# 3. Apply UAC Settings
# ---------------------------------------------------
$uacRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
if ($null -ne $Config.UACSettings) {
    Write-Host "`n[INFO] Applying UAC settings..."
    
    if (-not (Test-Path -Path $uacRegistryPath)) {
        New-Item -Path $uacRegistryPath -Force | Out-Null
    }

    foreach ($setting in $Config.UACSettings.PSObject.Properties) {
        $settingName = $setting.Name
        $desiredValue = $setting.Value

        try {
            $currentValue = Get-ItemProperty -Path $uacRegistryPath -Name $settingName -ErrorAction SilentlyContinue
            
            if ($null -eq $currentValue) {
                Write-Host " - Creating ${settingName} with value $desiredValue"
                New-ItemProperty -Path $uacRegistryPath -Name $settingName -Value $desiredValue -PropertyType DWORD -Force | Out-Null
            } else {
                Write-Host " - Current ${settingName} = $($currentValue.$settingName); changing to $desiredValue"
                Set-ItemProperty -Path $uacRegistryPath -Name $settingName -Value $desiredValue -Force
            }
            Write-Host "   -> Successfully set ${settingName} to $desiredValue"
        } catch {
            Write-Warning "[WARNING] Failed to set ${settingName}: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[INFO] No UAC settings found in config"
}

# ---------------------------------------------------
# 3.5 Check Autorun Entries
# ---------------------------------------------------
Write-Host "`n[INFO] Checking for unauthorized autorun entries..."

$autorunRegistryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $autorunRegistryPaths) {
    if (Test-Path -Path $path) {
        $autorunEntries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        
        if ($null -ne $autorunEntries) {
            $propertiesToSkip = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
            
            foreach ($entry in $autorunEntries.PSObject.Properties) {
                if ($entry.Name -notin $propertiesToSkip) {
                    $exePath = $entry.Value
                    foreach ($blacklisted in $Config.BlacklistedPrograms) {
                        if ($exePath -like "*$blacklisted*") {
                            Write-Host "[WARNING] Found blacklisted autorun entry: $($entry.Name) -> $exePath"
                            try {
                                Remove-ItemProperty -Path $path -Name $entry.Name -Force -ErrorAction Stop
                                Write-Host "[INFO] Removed autorun entry: $($entry.Name)"
                            } catch {
                                Write-Warning "[ERROR] Failed to remove autorun entry $($entry.Name): $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
    }
}

foreach ($folder in $startupFolders) {
    if (Test-Path -Path $folder) {
        $startupFiles = Get-ChildItem -Path $folder -Filter "*.lnk" -ErrorAction SilentlyContinue
        
        foreach ($file in $startupFiles) {
            foreach ($blacklisted in $Config.BlacklistedPrograms) {
                if ($file.Name -like "*$blacklisted*") {
                    Write-Host "[WARNING] Found blacklisted startup shortcut: $($file.Name)"
                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        Write-Host "[INFO] Removed startup shortcut: $($file.Name)"
                    } catch {
                        Write-Warning "[ERROR] Failed to remove startup shortcut $($file.Name): $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

Write-Host "[INFO] Autorun entry check completed"

# ---------------------------------------------------
# 4. Optional Firewall Rule Configuration
# ---------------------------------------------------
if ($null -ne $Config.FirewallRules -and @($Config.FirewallRules).Count -gt 0) {
    Write-Host "`n[INFO] Applying firewall rules..."
    
    foreach ($rule in $Config.FirewallRules) {
        $firewallParams = @{
            DisplayName = $rule.Name
            Direction  = $rule.Direction
            Action     = $rule.Action
            Protocol   = $rule.Protocol
            LocalPort  = $rule.Port
            Enabled    = 'True'
        }

        Write-Host " - Creating/Updating firewall rule '$($rule.Name)' for port $($rule.Port) ($($rule.Protocol))"
        
        try {
            $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
            
            if ($null -ne $existingRule) {
                Set-NetFirewallRule -DisplayName $rule.Name @firewallParams
                Write-Host "   -> Updated existing rule: $($rule.Name)"
            } else {
                New-NetFirewallRule @firewallParams
                Write-Host "   -> Created new rule: $($rule.Name)"
            }
        } catch {
            Write-Warning "[WARNING] Failed to process firewall rule '$($rule.Name)': $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[INFO] No firewall rules to apply"
}

# ---------------------------------------------------
# 5. (Optional) Install Security Updates
# ---------------------------------------------------
if ($Config.ApplySecurityUpdates -eq $true) {
    Write-Host "`n[INFO] Applying Windows security updates..."
    
    try {
        # Using Start-Process with proper error handling
        $processes = @(
            @{Name = "Scan"; Args = "StartScan"},
            @{Name = "Download"; Args = "StartDownload"},
            @{Name = "Install"; Args = "StartInstall"}
        )

        foreach ($process in $processes) {
            Write-Host " -> Starting update $($process.Name.ToLower())..."
            $proc = Start-Process -FilePath "UsoClient.exe" -ArgumentList $process.Args -NoNewWindow -Wait -PassThru
            
            if ($proc.ExitCode -ne 0) {
                Write-Warning "[WARNING] UsoClient $($process.Name) completed with exit code: $($proc.ExitCode)"
            }
        }

        Write-Host "Updates have been initiated. The process may continue in the background."
        Write-Host "Some updates may require a reboot. Manual or scheduled reboot may be needed."
    } catch {
        Write-Warning "[WARNING] Failed to process Windows updates: $($_.Exception.Message)"
    }
} else {
    Write-Host "[INFO] Skipping security updates as per config"
}

Write-Host "`n[INFO] Windows Hardening Script Completed Successfully"
