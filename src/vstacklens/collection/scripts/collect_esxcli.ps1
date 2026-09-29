# Private stdin/stdout JSON protocol. Fixed read-only command allowlist.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$connection = $null
$result = @{ schema_version = 1; hosts = @(); vcenter_logs = @(); warnings = @(); log_file_attempt_count = 0; log_bytes_used = 0 }
$defaultLogKeys = @('vmkernel', 'hostd', 'vpxa', 'vobd', 'syslog', 'vsan')
$script:LogFileAttemptCount = 0
$script:LogBytesUsed = 0
function Start-LogRead($log) {
    if (($request.PSObject.Properties.Name -contains 'max_log_files') -and $script:LogFileAttemptCount -ge [int]$request.max_log_files) {
        $log.status = 'file_limit_reached'; $log.reason = 'max_log_files'; return $false
    }
    if (($request.PSObject.Properties.Name -contains 'max_log_file_bytes') -and [int]$request.max_log_file_bytes -le 0) {
        $log.status = 'file_size_limit_reached'; $log.reason = 'max_log_file_bytes'; return $false
    }
    if (($request.PSObject.Properties.Name -contains 'max_log_total_bytes') -and $script:LogBytesUsed -ge [int]$request.max_log_total_bytes) {
        $log.status = 'total_size_limit_reached'; $log.reason = 'max_log_total_bytes'; $log.truncated = $true; $log.truncation_reason = 'total_size_limit'; return $false
    }
    $script:LogFileAttemptCount++
    return $true
}
function Limit-LogLines($values, $log) {
    $lines = New-Object System.Collections.Generic.List[string]
    $fileBytes = 0
    $maxFileBytes = if ($request.PSObject.Properties.Name -contains 'max_log_file_bytes') { [int]$request.max_log_file_bytes } else { [int]::MaxValue }
    $maxTotalBytes = if ($request.PSObject.Properties.Name -contains 'max_log_total_bytes') { [int]$request.max_log_total_bytes } else { [int]::MaxValue }
    foreach ($candidate in $values) {
        if ($lines.Count -ge [int]$request.max_log_lines) { $log.truncated = $true; $log.truncation_reason = 'line_count_limit'; break }
        $line = [string]$candidate
        if ($line.Length -gt [int]$request.max_log_line_chars) { $line = $line.Substring(0, [int]$request.max_log_line_chars); $log.truncated = $true; $log.truncation_reason = 'line_character_limit' }
        $remainingFile = $maxFileBytes - $fileBytes
        $remainingTotal = $maxTotalBytes - $script:LogBytesUsed
        $remaining = [Math]::Min($remainingFile, $remainingTotal)
        if ($remaining -le 0) {
            $log.truncated = $true
            $log.truncation_reason = if ($remainingTotal -le 0) { 'total_size_limit' } else { 'file_size_limit' }
            break
        }
        while ($line.Length -gt 0 -and [Text.Encoding]::UTF8.GetByteCount($line) -gt $remaining) { $line = $line.Substring(0, $line.Length - 1) }
        if ([Text.Encoding]::UTF8.GetByteCount([string]$candidate) -gt [Text.Encoding]::UTF8.GetByteCount($line)) {
            $log.truncated = $true
            $log.truncation_reason = if ($remainingTotal -le $remainingFile) { 'total_size_limit' } else { 'file_size_limit' }
        }
        $lineBytes = [Text.Encoding]::UTF8.GetByteCount($line)
        if ($lineBytes -gt 0) { $lines.Add($line); $fileBytes += $lineBytes; $script:LogBytesUsed += $lineBytes }
        if ($lineBytes -lt [Text.Encoding]::UTF8.GetByteCount([string]$candidate)) { break }
    }
    if ($lines.Count -lt @($values).Count -and $lines.Count -ge [int]$request.max_log_lines) { $log.truncated = $true; $log.truncation_reason = 'line_count_limit' }
    $log.retained_bytes = $fileBytes
    return @($lines)
}
function Read-Command($commands, $key, [scriptblock]$action) {
    if ($script:HostDeadline -and [DateTime]::UtcNow -gt $script:HostDeadline) {
        $commands[$key] = @{status='timeout';data=@()}
        return
    }
    for ($attempt = 0; $attempt -lt [int]$request.retry_attempts; $attempt++) {
        try {
            $commands[$key] = @{status='ok'; data=@(& $action)}
            return
        } catch {
            $message = $_.Exception.Message
            $kind = if ($message -match 'NoPermission|permission|privilege|denied') {'permission_denied'} elseif ($message -match 'timed out|timeout|temporar') {'timeout'} else {'command_unavailable'}
            if ($kind -eq 'timeout' -and $attempt -lt ([int]$request.retry_attempts - 1)) { Start-Sleep -Milliseconds 500; continue }
            $commands[$key] = @{status=$kind; data=@()}
            return
        } finally { Start-Sleep -Milliseconds 100 }
    }
}
try {
    Import-Module VMware.VimAutomation.Core -ErrorAction Stop | Out-Null
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP $false -WebOperationTimeoutSeconds ([int]$request.request_timeout) -Scope Session -Confirm:$false | Out-Null
    if ($request.probe_only) {
        [Console]::Out.Write('{"schema_version":1,"hosts":[],"vcenter_logs":[],"runtime_status":"ready"}')
        exit 0
    }
    $secret = ConvertTo-SecureString ([string]$request.password) -AsPlainText -Force
    $credential = [PSCredential]::new([string]$request.username, $secret)
    $request.password = $null
    $connection = Connect-VIServer -Server $request.server -Credential $credential -NotDefault -ErrorAction Stop
    $vcLogKeys = if ($request.PSObject.Properties.Name -contains 'vcenter_log_keys') { @($request.vcenter_log_keys) } else { @('vpxd') }
    foreach ($category in $vcLogKeys) {
        $started = [DateTime]::UtcNow.ToString('o')
        $log = @{key=[string]$category; status='no_logs'; lines=@(); truncated=$false; reason=$null; source='PowerCLI.Get-Log'; started_at=$started}
        try {
            $types = @(Get-LogType -Server $connection -ErrorAction Stop)
            $descriptor = $types | Where-Object { (([string]$_.Key + ' ' + [string]$_.FileName + ' ' + [string]$_.Creator) -match [regex]::Escape([string]$category)) } | Select-Object -First 1
            if ($descriptor) {
                $key = [string]$descriptor.Key
                if (Start-LogRead $log) {
                    $rawItems = @(Get-Log -Server $connection -Key $key -StartLineNum 1 -NumLines ([int]$request.max_log_lines) -ErrorAction Stop)
                    $candidates = New-Object System.Collections.Generic.List[string]
                    foreach ($item in $rawItems) {
                        if ($null -ne $item.Entries) { foreach ($candidate in @($item.Entries)) { $candidates.Add([string]$candidate) } }
                        elseif ($null -ne $item.Data) { foreach ($candidate in @($item.Data)) { $candidates.Add([string]$candidate) } }
                        else { $candidates.Add([string]$item) }
                    }
                    $log.lines = @(Limit-LogLines @($candidates) $log)
                    $log.status = if($log.lines.Count){'ok'}else{'empty'}
                    $log.key=$key; $log.file_name=[string]$descriptor.FileName
                }
            }
        } catch {
            $message=$_.Exception.Message
            $log.status=if($message -match 'NoPermission|permission|privilege|denied'){'permission_denied'}elseif($message -match 'timed out|timeout|temporar'){'timeout'}elseif($message -match 'not found|unknown|invalid'){'interface_unavailable'}else{'error'}
            $log.reason=$log.status
        }
        $log.finished_at=[DateTime]::UtcNow.ToString('o')
        $result.vcenter_logs += $log
    }
    foreach ($item in $request.hosts) {
        $script:HostDeadline = [DateTime]::UtcNow.AddSeconds([double]$request.host_timeout)
        $commands = @{}
        try {
        $hostObject = Get-VMHost -Id ("HostSystem-" + $item.id) -Server $connection -ErrorAction Stop
            if ($request.include_esxcli -ne $false) {
                try {
                    $esxcli = Get-EsxCli -VMHost $hostObject -Server $connection -V2 -ErrorAction Stop
                    Read-Command $commands 'storage.san.sas.list' { $esxcli.storage.san.sas.list.Invoke() }
                    Read-Command $commands 'storage.san.fc.list' { $esxcli.storage.san.fc.list.Invoke() }
                    Read-Command $commands 'storage.core.adapter.list' { $esxcli.storage.core.adapter.list.Invoke() }
                    Read-Command $commands 'network.nic.list' { $esxcli.network.nic.list.Invoke() }
                    Read-Command $commands 'software.vib.list' { $esxcli.software.vib.list.Invoke() }
                    Read-Command $commands 'storage.core.device.list' { $esxcli.storage.core.device.list.Invoke() }
                    Read-Command $commands 'vsan.storage.list' { $esxcli.vsan.storage.list.Invoke() }
                    foreach ($nic in $commands['network.nic.list'].data) {
                        $nicName = [string]$nic.Name
                        Read-Command $commands ("network.nic.get:" + $nicName) { $esxcli.network.nic.get.Invoke(@{nicname=$nicName}) }
                    }
                } catch {
                    $result.warnings += @{host=$item.name; status='esxcli_unavailable'}
                }
            }
            $logs = @()
        $hostLogProperty = if ($request.PSObject.Properties.Name -contains 'log_keys_by_host' -and $request.log_keys_by_host) { $request.log_keys_by_host.PSObject.Properties | Where-Object { $_.Name -eq [string]$item.id } | Select-Object -First 1 } else { $null }
        $logKeys = if ($hostLogProperty) { @($hostLogProperty.Value) } elseif ($request.PSObject.Properties.Name -contains 'log_keys') { @($request.log_keys) } else { $defaultLogKeys }
        foreach ($logKey in $logKeys) {
                if ([DateTime]::UtcNow -gt $script:HostDeadline) {
                    $logs += @{key=[string]$logKey; status='timeout'; lines=@(); truncated=$false; reason='host_timeout'; source='PowerCLI.Get-Log'; started_at=[DateTime]::UtcNow.ToString('o'); finished_at=[DateTime]::UtcNow.ToString('o')}
                    continue
                }
                $logStart = [DateTime]::UtcNow.ToString('o')
                $log = @{key=[string]$logKey; status='unknown'; lines=@(); truncated=$false; reason=$null; source='PowerCLI.Get-Log'; started_at=$logStart}
                try {
                    if (Start-LogRead $log) {
                        $rawItems = @(Get-Log -VMHost $hostObject -Key ([string]$logKey) -StartLineNum 1 -NumLines ([int]$request.max_log_lines) -ErrorAction Stop)
                        $candidates = New-Object System.Collections.Generic.List[string]
                        foreach ($item in $rawItems) {
                            if ($null -ne $item.Entries) { foreach ($candidate in @($item.Entries)) { $candidates.Add([string]$candidate) } }
                            elseif ($null -ne $item.Data) { foreach ($candidate in @($item.Data)) { $candidates.Add([string]$candidate) } }
                            else { $candidates.Add([string]$item) }
                        }
                        $log.lines = @(Limit-LogLines @($candidates) $log)
                        $log.status = if ($log.lines.Count) { 'ok' } else { 'empty' }
                    }
                } catch {
                    $message = $_.Exception.Message
                    $log.status = if ($message -match 'NoPermission|permission|privilege|denied') { 'permission_denied' } elseif ($message -match 'timed out|timeout|temporar') { 'timeout' } elseif ($message -match 'not found|unknown|invalid') { 'interface_unavailable' } else { 'error' }
                    $log.reason = $log.status
                }
                $log.finished_at = [DateTime]::UtcNow.ToString('o')
                $logs += $log
            }
        } catch {
            $result.warnings += @{host=$item.name; status='esxcli_host_failed'}
        }
        $result.hosts += @{id=$item.id; commands=$commands; logs=$logs}
    }
    $result.log_file_attempt_count = $script:LogFileAttemptCount
    $result.log_bytes_used = $script:LogBytesUsed
    [Console]::Out.Write(($result | ConvertTo-Json -Depth 30 -Compress))
} catch {
    [Console]::Error.Write('PowerCLI collection failed')
    exit 2
} finally {
    if ($null -ne $connection) { try { Disconnect-VIServer -Server $connection -Confirm:$false | Out-Null } catch {} }
    $credential = $null
    $secret = $null
}
