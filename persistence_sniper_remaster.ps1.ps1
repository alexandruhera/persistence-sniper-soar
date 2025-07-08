Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Module setup
$zip_file_path          = "C:\PersistenceSniper.zip"
$forensic_analysis_path = "C:\mmsoc"
$modulePath             = "PersistenceSniper-main\PersistenceSniper\PersistenceSniper.psd1"
$fullModulePath         = Join-Path $forensic_analysis_path $modulePath

# Technique toggles
$runAndRunOnce_enabled    = $true
$scheduledTasks_enabled   = $true
$startupPrograms_enabled  = $true

# Trusted publishers (used for exclusion only if signature is valid)
$trustedSigners = @(
    'Microsoft Corporation','Microsoft Windows','Microsoft Windows Hardware Compatibility Publisher',
    'Samsung Electronics CO., LTD.','Valve Corp.','Spotify AB','Intel Corporation','Google LLC',
    'NVIDIA Corporation','Adobe Inc.','Mozilla Corporation','Cisco Systems, Inc.','Oracle Corporation',
    'Realtek Semiconductor Corp.','Logitech Inc','Slack Technologies','Palo Alto Networks',
    'CyberArk Software Ltd.','Zoom Video Communications','Global Relay Communications Inc.',
    'Adobe Systems Incorporated','Omnissa','Okta','Dell Technologies Inc.',
    'Corel Corporation','Box','Cisco WebEx LLC', 'Microsoft Windows Publisher'
)

# ScheduledTasks path exclusions (used only if signature is valid)
$excludedKeywords_ScheduledTasks = @(
    '\Microsoft\','\MicrosoftEdgeUpdate','\OneDrive','\Adobe Acrobat Update Task','\GoogleUpdater',
    '\Mozilla\Firefox','\NVIDIA App SelfUpdate','\NahimicTask','\Mozilla Firefox Default Browser Agent',
    '\Firefox Background Update','\ARM\AdobeARM.exe','\MMStart-*','\VMware\'
)

# Import scanning module
try {
    Expand-Archive -Path $zip_file_path -DestinationPath $forensic_analysis_path -Force
    Import-Module $fullModulePath -Force
} catch {
    return
}

# Initialize containers
$runResults     = @()
$taskResults    = @()
$startupResults = @()
$runFindings     = ''
$taskFindings    = ''
$startupFindings = ''
$runExceeded     = $false
$taskExceeded    = $false
$startupExceeded = $false

# Line breaks
$linebreak   = "`n"
$doublebreak = "`n`n"

# Run and RunOnce keys
if ($runAndRunOnce_enabled) {
    $rawRun = Find-AllPersistence -PersistenceMethod RunAndRunOnce
    foreach ($item in $rawRun) {
        if ($item.Signature -match 'Status\s*=\s*([^,]+)') {
            $status = $matches[1].Trim()
        } else {
            $status = 'Unknown'
        }

        if ($item.Signature -match 'CN\s*=\s*("?[^",]+)') {
            $cn = $matches[1].Trim('"')
        } else {
            $cn = 'Unknown'
        }

        if ($trustedSigners -contains $cn -and $status -eq 'Valid') { continue }

        $runResults += [PSCustomObject]@{
            Path    = $item.Path
            Value   = $item.Value.Trim()
            Status  = $status
            Signer  = $cn
        }
    }

    $runEntries  = $runResults | ForEach-Object {
        @("PATH: $($_.Path)", "→ $($_.Value)", "→ Status = $($_.Status)", "→ Signer = $($_.Signer)") -join $linebreak
    }
    $runFindings = $runEntries -join $doublebreak
    $runExceeded = $runFindings.Length -gt 2000
}

# ScheduledTasks with signature-first exclusion logic
if ($scheduledTasks_enabled) {
    $rawTasks = Find-AllPersistence -PersistenceMethod ScheduledTasks
    foreach ($item in $rawTasks) {
        $path  = $item.Path
        $value = $item.Value

        if ($value -and $value.Trim() -ne '') {
            if ($item.Signature -match 'Status\s*=\s*([^,]+)') {
                $status = $matches[1].Trim()
            } else {
                $status = 'Unknown'
            }

            if ($item.Signature -match 'CN\s*=\s*("?[^",]+)') {
                $cn = $matches[1].Trim('"')
            } else {
                $cn = 'Unknown'
            }

            $excludeMatch  = $excludedKeywords_ScheduledTasks | Where-Object { $path -like "*$_*" }
            $shouldExclude = ($trustedSigners -contains $cn -and $status -eq 'Valid' -and $excludeMatch)
            if ($shouldExclude) { continue }

            $taskResults += [PSCustomObject]@{
                Path    = $path
                Value   = $value.Trim()
                Status  = $status
                Signer  = $cn
            }
        }
    }

    $taskEntries  = $taskResults | ForEach-Object {
        @("PATH: $($_.Path)", "→ $($_.Value)", "→ Status = $($_.Status)", "→ Signer = $($_.Signer)") -join $linebreak
    }
    $taskFindings = $taskEntries -join $doublebreak
    $taskExceeded = $taskFindings.Length -gt 2000
}

# Startup folder and registry entries
if ($startupPrograms_enabled) {
    $rawStartup = Find-AllPersistence -PersistenceMethod StartupPrograms
    foreach ($item in $rawStartup) {
        if ($item.Signature -match 'Status\s*=\s*([^,]+)') {
            $status = $matches[1].Trim()
        } else {
            $status = 'Unknown'
        }

        if ($item.Signature -match 'CN\s*=\s*("?[^",]+)') {
            $cn = $matches[1].Trim('"')
        } else {
            $cn = 'Unknown'
        }

        if ($trustedSigners -contains $cn -and $status -eq 'Valid') { continue }

        $startupResults += [PSCustomObject]@{
            Path    = $item.Path
            Value   = $item.Value.Trim()
            Status  = $status
            Signer  = $cn
        }
    }

    $startupEntries  = $startupResults | ForEach-Object {
        @("PATH: $($_.Path)", "→ $($_.Value)", "→ Status = $($_.Status)", "→ Signer = $($_.Signer)") -join $linebreak
    }
    $startupFindings = $startupEntries -join $doublebreak
    $startupExceeded = $startupFindings.Length -gt 2000
}

# Combined output size check
$totalLength      = ($runFindings.Length + $taskFindings.Length + $startupFindings.Length)
$combinedExceeded = $totalLength -gt 2000

# Structured final output
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

# Output results as JSON
$json_output | ConvertTo-Json -Depth 4
