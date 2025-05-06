# Variables
$msaName = "PingCastle"
$domainName = "damberg"
$taskName = "PingCastleHealthCheck"
$scriptPath = "C:\PingCastle\PingCastle.ps1"
$executionPolicy = "Bypass"
$triggerTime = "14:00"  # 2:00 PM

# Create the Scheduled Task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy $executionPolicy -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At $triggerTime
$principal = New-ScheduledTaskPrincipal -UserId "$domainName\$msaName$" -LogonType Password -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Verify the task
Get-ScheduledTask -TaskName $taskName
