[CmdletBinding()]
param(
    [switch]$Pretty
)

# Read-only Windows host audit.
# Never changes system state: only queries services, tasks, registry,
# disks, event logs and TCP listeners, then emits ONE JSON object on stdout.
# Exit code 0 when JSON was produced, 1 when it could not be produced.
# Windows PowerShell 5.1 compatible. No external modules required.

$ErrorActionPreference = 'SilentlyContinue'

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Detail,
        $Evidence
    )
    if ($null -eq $Evidence) { $Evidence = @{} }
    return [pscustomobject]@{
        check    = $Check
        severity = $Severity
        detail   = $Detail
        evidence = $Evidence
    }
}

function New-Unavailable {
    param(
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return (New-Finding -Check $Check -Severity 'info' -Detail "check unavailable: $Reason" -Evidence @{})
}

# S1: services configured automatic that are not running.
function Test-AutoServiceStopped {
    $id = 'auto_service_stopped'
    try {
        $stopped = @(Get-WmiObject -Class Win32_Service -Filter "StartMode='Auto' AND State!='Running'" -ErrorAction Stop)
        if ($stopped.Count -eq 0) {
            return (New-Finding -Check $id -Severity 'info' -Detail 'No stopped automatic services.' -Evidence ([pscustomobject]@{ stopped_count = 0 }))
        }
        $names = @($stopped | ForEach-Object { "$($_.Name) [$($_.State)]" })
        $truncated = $false
        if ($names.Count -gt 50) { $names = $names[0..49]; $truncated = $true }
        $evidence = [pscustomobject]@{
            stopped_count = $stopped.Count
            services      = $names
            truncated     = $truncated
        }
        return (New-Finding -Check $id -Severity 'warning' -Detail "$($stopped.Count) automatic service(s) not running." -Evidence $evidence)
    } catch {
        return (New-Unavailable -Check $id -Reason $_.Exception.Message)
    }
}

# S2: scheduled tasks whose last run returned a non-zero exit code.
function Test-ScheduledTaskFailed {
    $id = 'scheduled_task_failed'
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        $failed = @()
        foreach ($t in $tasks) {
            try {
                $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop
                if ($info.LastTaskResult -ne 0) {
                    $failed += ("{0}{1} (0x{2:X8})" -f $t.TaskPath, $t.TaskName, $info.LastTaskResult)
                }
            } catch { }
        }
        if ($failed.Count -eq 0) {
            return (New-Finding -Check $id -Severity 'info' -Detail 'No scheduled tasks with a non-zero last result.' -Evidence ([pscustomobject]@{ failed_count = 0 }))
        }
        $shown = $failed
        $truncated = $false
        if ($shown.Count -gt 25) { $shown = $shown[0..24]; $truncated = $true }
        $evidence = [pscustomobject]@{
            failed_count = $failed.Count
            tasks        = $shown
            truncated    = $truncated
        }
        return (New-Finding -Check $id -Severity 'warning' -Detail "$($failed.Count) scheduled task(s) with non-zero LastTaskResult." -Evidence $evidence)
    } catch {
        return (New-Unavailable -Check $id -Reason $_.Exception.Message)
    }
}

# S3: pending reboot signals (CBS RebootPending key or PendingFileRenameOperations).
function Test-RebootPending {
    $id = 'reboot_pending'
    try {
        $cbs = Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop
        $renamePending = $false
        $renameCount = 0
        try {
            $prop = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction Stop
            $vals = @($prop.PendingFileRenameOperations) | Where-Object { $_ -ne $null -and "$_".Trim() -ne '' }
            $renameCount = @($vals).Count
            $renamePending = $renameCount -gt 0
        } catch {
            $renamePending = $false
            $renameCount = 0
        }
        $evidence = [pscustomobject]@{
            cbs_reboot_pending             = [bool]$cbs
            pending_file_rename_operations = [bool]$renamePending
            pending_file_rename_count      = $renameCount
        }
        if ($cbs -or $renamePending) {
            return (New-Finding -Check $id -Severity 'warning' -Detail 'A reboot is pending.' -Evidence $evidence)
        }
        return (New-Finding -Check $id -Severity 'info' -Detail 'No reboot pending.' -Evidence $evidence)
    } catch {
        return (New-Unavailable -Check $id -Reason $_.Exception.Message)
    }
}

# S4: fixed logical disks with less than 15 percent free space.
function Test-DiskLow {
    $id = 'disk_low'
    try {
        $disks = @(Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
        $low = @()
        $all = @()
        foreach ($d in $disks) {
            $size = [double]$d.Size
            if ($size -gt 0) {
                $pct = [math]::Round(([double]$d.FreeSpace / $size) * 100, 1)
                $all += ("{0} {1}% free" -f $d.DeviceID, $pct)
                if ($pct -lt 15) {
                    $low += [pscustomobject]@{
                        drive        = $d.DeviceID
                        free_gb      = [math]::Round([double]$d.FreeSpace / 1GB, 2)
                        size_gb      = [math]::Round($size / 1GB, 2)
                        free_percent = $pct
                    }
                }
            }
        }
        if ($low.Count -eq 0) {
            return (New-Finding -Check $id -Severity 'info' -Detail 'All fixed disks have >= 15% free space.' -Evidence ([pscustomobject]@{ low_count = 0; disks = $all }))
        }
        $evidence = [pscustomobject]@{ low_count = $low.Count; disks = $low }
        return (New-Finding -Check $id -Severity 'critical' -Detail "$($low.Count) disk(s) below 15% free space." -Evidence $evidence)
    } catch {
        return (New-Unavailable -Check $id -Reason $_.Exception.Message)
    }
}

# S5: count of System log entries with Level 1-2 (critical/error) in the last 24h.
function Test-ErrorEvents24h {
    $id = 'error_events_24h'
    try {
        $since = (Get-Date).AddHours(-24)
        $count = 0
        try {
            $count = @((Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $since } -ErrorAction Stop)).Count
        } catch {
            if ("$($_.Exception.Message)" -match 'No events were found') { $count = 0 }
            else { throw }
        }
        $evidence = [pscustomobject]@{
            error_count  = $count
            window_hours = 24
            since        = $since.ToUniversalTime().ToString('o')
        }
        if ($count -eq 0) {
            return (New-Finding -Check $id -Severity 'info' -Detail 'No critical/error System events in the last 24h.' -Evidence $evidence)
        }
        return (New-Finding -Check $id -Severity 'warning' -Detail "$count critical/error System event(s) in the last 24h." -Evidence $evidence)
    } catch {
        return (New-Unavailable -Check $id -Reason $_.Exception.Message)
    }
}

# S6: TCP LISTENING ports with >1 owning PID or an unresolvable owner PID.
function Test-PortNoOwner {
    $id = 'port_no_owner'
    try {
        $conns = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $orphans = @()
        $groups = @($conns | Group-Object -Property LocalPort)
        foreach ($g in $groups) {
            $pids = @($g.Group | Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique)
            $dead = @()
            foreach ($owner in $pids) {
                try { $null = Get-Process -Id $owner -ErrorAction Stop }
                catch { $dead += $owner }
            }
            if ($pids.Count -gt 1 -or $dead.Count -gt 0) {
                $orphans += [pscustomobject]@{
                    port              = [int]$g.Name
                    pids              = $pids
                    unresolvable_pids = $dead
                }
            }
        }
        if ($orphans.Count -eq 0) {
            return (New-Finding -Check $id -Severity 'info' -Detail 'All listening ports resolve to a single live owner process.' -Evidence ([pscustomobject]@{ listener_count = $conns.Count; orphan_count = 0 }))
        }
        $evidence = [pscustomobject]@{ listener_count = $conns.Count; orphan_count = $orphans.Count; orphans = $orphans }
        return (New-Finding -Check $id -Severity 'warning' -Detail "$($orphans.Count) listening port(s) with shared or unresolvable owner PID." -Evidence $evidence)
    } catch {
        return (New-Unavailable -Check $id -Reason $_.Exception.Message)
    }
}

try {
    $osName = 'unknown'
    $uptimeHours = 0
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.Caption) { $osName = $os.Caption }
        $uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2)
    } catch { }

    $computerName = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($computerName)) { $computerName = 'unknown' }

    $findings = @(
        (Test-AutoServiceStopped)
        (Test-ScheduledTaskFailed)
        (Test-RebootPending)
        (Test-DiskLow)
        (Test-ErrorEvents24h)
        (Test-PortNoOwner)
    )

    $critical = @($findings | Where-Object { $_.severity -eq 'critical' }).Count
    $warning = @($findings | Where-Object { $_.severity -eq 'warning' }).Count
    $info = @($findings | Where-Object { $_.severity -eq 'info' }).Count

    $result = [pscustomobject]@{
        host     = [pscustomobject]@{
            name         = $computerName
            os           = $osName
            uptime_hours = $uptimeHours
            generated_at = ([datetime]::UtcNow.ToString('o'))
        }
        findings = $findings
        summary  = [pscustomobject]@{
            critical = $critical
            warning  = $warning
            info     = $info
        }
    }

    if ($Pretty) { $json = $result | ConvertTo-Json -Depth 6 }
    else { $json = $result | ConvertTo-Json -Depth 6 -Compress }
    [Console]::Out.WriteLine($json)
    exit 0
} catch {
    [Console]::Error.WriteLine("audit failed: $($_.Exception.Message)")
    exit 1
}
