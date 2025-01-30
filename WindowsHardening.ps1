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
    Author:        Example Author
    Created:       2025-01-29
    Version:       1.0

    DISCLAIMER:
    - Always test thoroughly in a lab or staging environment.
    - Removing programs, changing registry settings, or installing updates can impact system stability.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

# ---------------------------------------------------
# 1. Validate and Load Configuration
# ---------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config file not found at $ConfigPath. Script will exit."
    return
}

try {
    $ConfigRaw = Get-Content -Path $ConfigPath -Raw
    $Config = $ConfigRaw | ConvertFrom-Json
    Write-Host "`n[INFO] Configuration loaded from $ConfigPath."
} catch {
    Write-Error "Failed to read or parse JSON config: $($_.Exception.Message)"
    return
}

# ---------------------------------------------------
# 2. Remove Blacklisted Programs
# ---------------------------------------------------
if ($Config.BlacklistedPrograms -and $Config.BlacklistedPrograms.Count -gt 0) {
    Write-Host "`n[INFO] Checking for blacklisted programs..."

    # Potentially slow approach; use with caution
    $installedApps = Get-WmiObject -Class Win32_Product

    foreach ($blacklisted in $Config.BlacklistedPrograms) {
        # We use a wildcard match for partial matches, e.g. "Steam" => "Steam Client"
        $foundApps = $installedApps | Where-Object { $_.Name -like "*$blacklisted*" }

        foreach ($app in $foundApps) {
            Write-Host "[WARNING] Found blacklisted app: $($app.Name). Attempting to remove..."
            try {
                $result = $app.Uninstall()
                if ($result.ReturnValue -eq 0) {
                    Write-Host "[INFO] Successfully removed: $($app.Name)."
                } else {
                    Write-Warning "[WARN] Failed to remove $($app.Name). Return code: $($result.ReturnValue)"
                }
            } catch {
                Write-Warning "[ERROR] Exception while uninstalling $($app.Name): $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Host "[INFO] No blacklisted programs specified."
}

# ---------------------------------------------------
# 3. Apply UAC Settings
# ---------------------------------------------------
$uacRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
if ($Config.UACSettings) {
    Write-Host "`n[INFO] Applying UAC settings..."
    foreach ($key in $Config.UACSettings.PSObject.Properties) {
        $settingName = $key.Name
        $desiredValue = $key.Value

        try {
            $currentValue = (Get-ItemProperty -Path $uacRegistryPath -Name $settingName -ErrorAction SilentlyContinue).$settingName
            if ($null -eq $currentValue) {
                Write-Host " - Creating $settingName with value $desiredValue."
            } else {
                Write-Host " - Current $settingName = $currentValue; changing to $desiredValue."
            }

            Set-ItemProperty -Path $uacRegistryPath -Name $settingName -Value $desiredValue -Force
            Write-Host "   -> Successfully set $settingName to $desiredValue."
        } catch {
            Write-Warning "[WARNING] Failed to set $settingName: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[INFO] No UAC settings found in config."
}
# ---------------------------------------------------
# 3.5 Check Autorun Entries
# ---------------------------------------------------
Write-Host "`n[INFO] Checking for unauthorized autorun entries..."

# Common autorun registry locations
$autorunRegistryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

# Startup folder paths
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

# Check registry autoruns
foreach ($path in $autorunRegistryPaths) {
    if (Test-Path $path) {
        $autorunEntries = Get-ItemProperty -Path $path
        foreach ($entry in $autorunEntries.PSObject.Properties) {
            if ($entry.Name -ne "PSPath" -and $entry.Name -ne "PSParentPath" -and $entry.Name -ne "PSChildName" -and $entry.Name -ne "PSDrive" -and $entry.Name -ne "PSProvider") {
                $exePath = $entry.Value
                foreach ($blacklisted in $Config.BlacklistedPrograms) {
                    if ($exePath -like "*$blacklisted*") {
                        Write-Host "[WARNING] Found blacklisted autorun entry: $entry.Name -> $exePath. Removing..."
                        try {
                            Remove-ItemProperty -Path $path -Name $entry.Name -Force
                            Write-Host "[INFO] Removed autorun entry: $entry.Name."
                        } catch {
                            Write-Warning "[ERROR] Failed to remove autorun entry $entry.Name: $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
    }
}

# Check Startup folders
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        $startupFiles = Get-ChildItem -Path $folder -Filter "*.lnk"
        foreach ($file in $startupFiles) {
            foreach ($blacklisted in $Config.BlacklistedPrograms) {
                if ($file.Name -like "*$blacklisted*") {
                    Write-Host "[WARNING] Found blacklisted startup shortcut: $file. Removing..."
                    try {
                        Remove-Item -Path $file.FullName -Force
                        Write-Host "[INFO] Removed startup shortcut: $file."
                    } catch {
                        Write-Warning "[ERROR] Failed to remove startup shortcut $file: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

Write-Host "[INFO] Autorun entry check completed."
# ---------------------------------------------------
# 4. Optional Firewall Rule Configuration
# ---------------------------------------------------
if ($Config.FirewallRules -and $Config.FirewallRules.Count -gt 0) {
    Write-Host "`n[INFO] Applying firewall rules..."
    foreach ($rule in $Config.FirewallRules) {
        # Each rule is an object with Name, Protocol, Port, Action, Direction, etc.
        # Example: { "Name": "DisableInboundSMBv1", "Protocol": "TCP", "Port": 445, "Action": "Block", "Direction": "Inbound" }

        $Name      = $rule.Name
        $Protocol  = $rule.Protocol
        $Port      = $rule.Port
        $Action    = $rule.Action
        $Direction = $rule.Direction

        Write-Host " - Creating/Updating firewall rule '$Name' for port $Port ($Protocol)."
        try {
            # If rule already exists, update it. Otherwise, create it.
            # You can refine this logic to handle existing rules more gracefully.
            $existingRule = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
            if ($null -ne $existingRule) {
                # Update existing rule
                Set-NetFirewallRule -DisplayName $Name -Action $Action -Direction $Direction -Protocol $Protocol -LocalPort $Port
                Write-Host "   -> Updated existing rule: $Name"
            } else {
                # Create new rule
                New-NetFirewallRule -DisplayName $Name -Action $Action -Direction $Direction -Protocol $Protocol -LocalPort $Port
                Write-Host "   -> Created new rule: $Name"
            }
        } catch {
            Write-Warning "[WARNING] Failed to process firewall rule '$Name': $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[INFO] No firewall rules to apply."
}

# ---------------------------------------------------
# 5. (Optional) Install Security Updates
# ---------------------------------------------------
if ($Config.ApplySecurityUpdates -eq $true) {
    Write-Host "`n[INFO] Applying Windows security updates..."
    
    # Approach A: Use built-in UsoClient (Windows 10+)
    # This approach triggers an update scan, then download, then install. 
    # It does NOT provide interactive progress in the console. 
    # On some Windows versions, UsoClient might not be fully supported. 
    # 
    # By design:
    #   UsoClient StartScan       -> Checks for updates
    #   UsoClient StartDownload   -> Downloads updates
    #   UsoClient StartInstall    -> Installs downloaded updates
    #   UsoClient ScanInstallWait -> Combined approach that scans and installs
    
    try {
        Write-Host " -> Starting update scan..."
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan" -NoNewWindow -Wait
        Write-Host " -> Downloading updates..."
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartDownload" -NoNewWindow -Wait
        Write-Host " -> Installing updates..."
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartInstall" -NoNewWindow -Wait

        Write-Host "Updates have been initiated. The process may continue in the background."
        Write-Host "Some updates may require a reboot. Manual or scheduled reboot may be needed."
    } catch {
        Write-Warning "[WARNING] UsoClient commands might not be supported on all Windows versions. Error: $($_.Exception.Message)"
    }

    # Approach B (Optional): Use PSWindowsUpdate module
    # This requires the 'PSWindowsUpdate' module, which may not be installed by default on older systems.
    # Uncomment below if you prefer PSWindowsUpdate, and comment out UsoClient lines above.
    #
    # try {
    #     if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
    #         Write-Host " -> PSWindowsUpdate module not found, installing from PSGallery..."
    #         Install-Module PSWindowsUpdate -Force -Scope CurrentUser
    #     }
    #     Import-Module PSWindowsUpdate -Force
    #
    #     Write-Host " -> Checking and installing all available updates..."
    #     Install-WindowsUpdate -AcceptAll -AutoReboot -IgnoreReboot
    # } catch {
    #     Write-Warning "[WARNING] Could not install or load PSWindowsUpdate: $($_.Exception.Message)"
    # }

} else {
    Write-Host "[INFO] Skipping security updates as per config."
}

Write-Host "`n[INFO] Windows Hardening Script Completed Successfully."
