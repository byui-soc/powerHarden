<#
.SYNOPSIS
    Windows Hardening Script using a JSON config file.

.DESCRIPTION
    This script reads from a JSON configuration file that contains:
    1) A list of unauthorized programs to remove.
    2) Desired UAC settings to configure in the registry.

.NOTES
    Author:  Your Name
    Created: 2025-01-29
    Version: 1.0

    DISCLAIMER:
    Always test thoroughly in a lab or staging environment. Improper changes can break system functionality. 
    Adjust the methods of removing software or enumerating installed applications as necessary.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

# -------------------------
# 1. Import JSON Config
# -------------------------
try {
    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Config file not found at path: $ConfigPath. Exiting."
        return
    }

    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    Write-Host "Successfully loaded configuration from $ConfigPath."
} catch {
    Write-Error "Failed to read or parse JSON config file: $_. Exception: $($_.Exception.Message)"
    return
}

# -------------------------
# 2. Remove Unauthorized Programs
# -------------------------
$unauthorizedPrograms = $Config.UnauthorizedPrograms
if ($unauthorizedPrograms -and $unauthorizedPrograms.Count -gt 0) {
    Write-Host "`n--- Checking for unauthorized programs ---"

    # This method uses Win32_Product, which can be slow and occasionally incomplete.
    # Consider enumerating from registry or other sources if needed.
    $installedApps = Get-WmiObject -Class Win32_Product

    foreach ($blockedApp in $unauthorizedPrograms) {
        # Search by Name. Adjust property or match logic if needed.
        $foundApp = $installedApps | Where-Object { $_.Name -like "*$blockedApp*" }
        if ($foundApp) {
            Write-Host "Found unauthorized program: $($foundApp.Name). Attempting to remove..."

            try {
                $uninstallResult = $foundApp.Uninstall()
                if ($uninstallResult.ReturnValue -eq 0) {
                    Write-Host "Successfully removed: $($foundApp.Name)"
                } else {
                    Write-Warning "Failed to remove: $($foundApp.Name). Return code: $($uninstallResult.ReturnValue)"
                }
            } catch {
                Write-Warning "Error uninstalling $($foundApp.Name): $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "Unauthorized program '$blockedApp' not found on this system."
        }
    }
} else {
    Write-Host "No unauthorized programs listed in config."
}

# -------------------------
# 3. Enumerate & Change UAC Rules
# -------------------------
# UAC Registry path
$uacRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

Write-Host "`n--- Applying UAC settings ---"
if ($Config.UACSettings) {
    $UACSettings = $Config.UACSettings | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

    foreach ($setting in $UACSettings) {
        $value = $Config.UACSettings.$setting
        $currentValue = (Get-ItemProperty -Path $uacRegistryPath -Name $setting -ErrorAction SilentlyContinue).$setting

        if ($null -eq $currentValue) {
            # If the value doesn't exist, it will be created
            Write-Host "Setting $setting does not exist. Creating and setting it to: $value"
        } else {
            Write-Host "Current $setting is '$currentValue'. Changing to '$value'..."
        }

        try {
            Set-ItemProperty -Path $uacRegistryPath -Name $setting -Value $value -Force
            Write-Host "Successfully set $setting to $value."
        } catch {
            Write-Warning "Could not set $setting to $value. Error: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "No UAC settings found in config to apply."
}

Write-Host "`n--- Windows Hardening Script Completed ---"
