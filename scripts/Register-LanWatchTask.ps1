<#
.SYNOPSIS
    Registers (or removes) a per-user scheduled task that runs a passive lan-watch inventory.

.DESCRIPTION
    Battery-safe settings: the task starts and keeps running on battery, catches up
    after sleep (StartWhenAvailable), never overlaps itself and is killed after 5 minutes.
    It runs as the signed-in user with limited rights (no elevation), which is also what
    lets it show Windows toasts.

    Every run re-checks the safety gate: off the confirmed network, or with a VPN up,
    it records nothing and sends nothing.

.EXAMPLE
    .\scripts\Register-LanWatchTask.ps1                      # passive run every 15 minutes
    .\scripts\Register-LanWatchTask.ps1 -IntervalMinutes 30 -ListenSeconds 20
    .\scripts\Register-LanWatchTask.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 1440)][int]$IntervalMinutes = 15,
    [ValidateRange(0, 120)][int]$ListenSeconds = 0,
    [switch]$Active,
    [switch]$Unregister,
    [string]$TaskName = 'lan-watch inventory'
)
$ErrorActionPreference = 'Stop'

if ($Unregister) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "No scheduled task named '$TaskName'."
    }
    return
}

$repo = Split-Path -Parent $PSScriptRoot
$pythonw = Join-Path $repo '.venv\Scripts\pythonw.exe'
if (-not (Test-Path $pythonw)) { throw "Missing $pythonw. Create the venv first (see README)." }

$argList = @('-m', 'lanwatch', 'run', '--quiet')
if ($ListenSeconds -gt 0) { $argList += @('--listen', "$ListenSeconds") }
if ($Active) { $argList += '--active' }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument ($argList -join ' ') -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -Priority 7
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description 'lan-watch: passive home-network inventory and new-device alerts.' -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName
Write-Host "Registered '$TaskName': every $IntervalMinutes min, $($argList -join ' ')"
Write-Host ("Battery: start={0} keep-running={1}" -f (-not $task.Settings.DisallowStartIfOnBatteries), (-not $task.Settings.StopIfGoingOnBatteries))
Write-Host "Remove with: .\scripts\Register-LanWatchTask.ps1 -Unregister"
