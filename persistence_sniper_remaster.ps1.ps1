# Configure script execution to allow locally sourced PowerShell scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Define paths for importing the PersistenceSniper module
$zip_file_path          = "C:\PersistenceSniper.zip"
$forensic_analysis_path = "C:\mmsoc"
$modulePath             = "PersistenceSniper\PersistenceSniper.psd1"
$fullModulePath         = Join-Path $forensic_analysis_path $modulePath

# Enable scanning for each persistence method
$runAndRunOnce_enabled    = $true
$scheduledTasks_enabled   = $true
$startupPrograms_enabled  = $true

# Trusted publisher CNs (excluded only if signature status is "Valid")
$trustedSigners = @(
    'Microsoft Corporation',
    'Microsoft Windows',
    'Microsoft Windows Hardware Compatibility Publisher',
    'Samsung Electronics CO., LTD.',
    'Valve Corp.',
    'Spotify AB',
    'Intel Corporation',
    'Google LLC',
    'NVIDIA Corporation',
    'Adobe Inc.',
    'Mozilla Corporation',
    'Cisco Systems, Inc.',
    'Oracle Corporation',
    'Realtek Semiconductor Corp.',
    'Logitech Inc',
    'Slack Technologies',
    'Palo Alto Networks',
    'CyberArk Software Ltd.',
    'Zoom Video Communications',
    'Global Relay Communications Inc.',
    'Adobe Systems Incorporated',
    'Omnissa',
    'Okta',
    'Dell Technologies Inc.',
    'Corel Corporation',
    'Box',
    'Cisco WebEx LLC',
    'Microsoft Windows Publisher'
)

# Scheduled task path exclusions (used only if signature status is "Valid")
$excludedKeywords_ScheduledTasks = @(
    '\Microsoft\',
    '\MicrosoftEdgeUpdate',
    '\OneDrive',
    '\Adobe Acrobat Update Task',
    '\GoogleUpdater',
    '\Mozilla\Firefox',
    '\NVIDIA App SelfUpdate',
    '\NahimicTask',
    '\Mozilla Firefox Default Browser Agent',
    '\Firefox Background Update',
    '\ARM\AdobeARM.exe',
    '\VMware\'
)

# Extract and import the module safely
try {
    Expand-Archive -Path $zip_file_path -DestinationPath $forensic_analysis_path -Force
    Import-Module $fullModulePath -Force
} catch {
    return
}

# Initialize containers and formatting tools
$runResults      = @()
$taskResults     = @()
$startupResults  = @()
$runFindings     = ''
$taskFindings    = ''
$startupFindings = ''
$runExceeded     = $false
$taskExceeded    = $false
$startupExceeded = $false
$linebreak       = "`n"
$doublebreak     = "`n`n"

# RunAndRunOnce registry keys
if ($runAndRunOnce_enabled) {
    $rawRun = Find-AllPersistence -PersistenceMethod RunAndRunOnce
    foreach ($item in $rawRun) {
        $status = ($item.Signature -match 'Status\s*=\s*([^,]+)') ? $matches[1].Trim() : 'Unknown'
        $cn     = ($item.Signature -match 'CN\s*=\s*("?[^",]+)')   ? $matches[1].Trim('"') : 'Unknown'

        if ($trustedSigners -contains $cn -and $status -eq 'Valid') { continue }

        $runResults += [PSCustomObject]@{
            Path    = $item.Path
            Value   = $item.Value
            Status  = $status
            Signer  = $cn
        }
    }

    $runEntries   = $runResults | ForEach-Object {
        @("PATH: $($_.Path)", "→ $($_.Value)", "→ Status = $($_.Status)", "→ Signer = $($_.Signer)") -join $linebreak
    }

    $runFindings  = $runEntries -join $doublebreak
    $runExceeded  = $runFindings.Length -gt 2000
}

# ScheduledTasks with signature-first exclusion logic
if ($scheduledTasks_enabled) {
    $rawTasks = Find-AllPersistence -PersistenceMethod ScheduledTasks
    foreach ($item in $rawTasks) {
        $path  = $item.Path
        $value = $item.Value

        if ($value -and $value.Trim() -ne '') {
            $status = ($item.Signature -match 'Status\s*=\s*([^,]+)') ? $matches[1].Trim() : 'Unknown'
            $cn     = ($item.Signature -match 'CN\s*=\s*("?[^",]+)')   ? $matches[1].Trim('"') : 'Unknown'

            $excludeMatch  = $excludedKeywords_ScheduledTasks | Where-Object { $path -like "*$_*" }
            $shouldExclude = ($trustedSigners -contains $cn -and $status -eq 'Valid' -and $excludeMatch)
            if ($shouldExclude) { continue }

            $taskResults += [PSCustomObject]@{
                Path    = $path
                Value   = $value
                Status  = $status
                Signer  = $cn
            }
        }
    }

    $taskEntries   = $taskResults | ForEach-Object {
        @("PATH: $($_.Path)", "→ $($_.Value)", "→ Status = $($_.Status)", "→ Signer = $($_.Signer)") -join $linebreak
    }

    $taskFindings  = $taskEntries -join $doublebreak
    $taskExceeded  = $taskFindings.Length -gt 2000
}

# Startup registry and folders
if ($startupPrograms_enabled) {
    $rawStartup = Find-AllPersistence -PersistenceMethod StartupPrograms
    foreach ($item in $rawStartup) {
        $status = ($item.Signature -match 'Status\s*=\s*([^,]+)') ? $matches[1].Trim() : 'Unknown'
        $cn     = ($item.Signature -match 'CN\s*=\s*("?[^",]+)')   ? $matches[1].Trim('"') : 'Unknown'

        if ($trustedSigners -contains $cn -and $status -eq 'Valid') { continue }

        $startupResults += [PSCustomObject]@{
            Path    = $item.Path
            Value   = $item.Value
            Status  = $status
            Signer  = $cn
        }
    }

    $startupEntries   = $startupResults | ForEach-Object {
        @("PATH: $($_.Path)", "→ $($_.Value)", "→ Status = $($_.Status)", "→ Signer = $($_.Signer)") -join $linebreak
    }

    $startupFindings  = $startupEntries -join $doublebreak
    $startupExceeded  = $startupFindings.Length -gt 2000
}

# Evaluate overall payload size
$totalLength      = ($runFindings.Length + $taskFindings.Length + $startupFindings.Length)
$combinedExceeded = $totalLength -gt 2000

# Build structured JSON object
$json_output = [PSCustomObject]@{
    RunAndRunOnce = @{
        enabled           = $runAndRunOnce_enabled
        findings          = $runFindings
        findings_exceeded = $runExceeded
        results           = $runResults
    }
    ScheduledTasks = @{
        enabled           = $scheduledTasks_enabled
        findings          = $taskFindings
        findings_exceeded = $taskExceeded
        results           = $taskResults
    }
    StartupPrograms = @{
        enabled           = $startupPrograms_enabled
        findings          = $startupFindings
        findings_exceeded = $startupExceeded
        results           = $startupResults
    }
    OutputMonitor = @{
        RunAndRunOnce_Exceeded    = $runExceeded
        ScheduledTasks_Exceeded   = $taskExceeded
        StartupPrograms_Exceeded  = $startupExceeded
        CombinedExceeded          = $combinedExceeded
    }
}

# Output JSON with nested depth support
$json_output | ConvertTo-Json -Depth 4
