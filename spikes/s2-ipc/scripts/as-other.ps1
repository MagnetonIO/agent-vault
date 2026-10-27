# Launch another script as the spike's second local user, stdout+stderr redirected to -Out.
param(
  [Parameter(Mandatory)][string]$Script,
  [string]$ScriptArgs = '',
  [Parameter(Mandatory)][string]$Out,
  [switch]$Wait
)
$ErrorActionPreference = 'Stop'
$sec = ConvertTo-SecureString $env:SPIKE_OTHER_PASS -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential(($env:COMPUTERNAME + '\' + $env:SPIKE_OTHER_USER), $sec)
$argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$Script`" $ScriptArgs"
$sp = @{
  FilePath = 'powershell.exe'
  Credential = $cred
  WorkingDirectory = 'C:\Users\Public\av-spike'
  ArgumentList = $argLine
  RedirectStandardOutput = $Out
  RedirectStandardError = ($Out + '.err')
  WindowStyle = 'Hidden'
}
try {
  if ($Wait) { Start-Process @sp -Wait } else { Start-Process @sp }
  Write-Output 'as-other: launched'
} catch {
  Write-Output ('as-other: LAUNCH FAILED: ' + $_.Exception.Message)
  exit 1
}
