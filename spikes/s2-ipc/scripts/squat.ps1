# Create a named pipe server (multi-instance) and answer one client with "SQUAT".
param(
  [Parameter(Mandatory)][string]$Pipe,
  [int]$HoldSeconds = 20,
  [switch]$Everyone
)
$ErrorActionPreference = 'Stop'
$short = $Pipe -replace '^\\\\\.\\pipe\\', ''
try {
  $inout = [System.IO.Pipes.PipeDirection]::InOut
  if ($Everyone) {
    $ps = New-Object System.IO.Pipes.PipeSecurity
    $rule = New-Object System.IO.Pipes.PipeAccessRule('Everyone', [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
    $ps.AddAccessRule($rule)
    $s = New-Object System.IO.Pipes.NamedPipeServerStream($short, $inout, 10, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 4096, 4096, $ps)
  } else {
    $s = New-Object System.IO.Pipes.NamedPipeServerStream($short, $inout, 10, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
  }
  Write-Output ("SQUAT created as " + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name + " everyone=$Everyone")
} catch {
  Write-Output ("SQUAT create FAILED: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
  exit 0
}
try {
  $async = $s.BeginWaitForConnection($null, $null)
  if ($async.AsyncWaitHandle.WaitOne($HoldSeconds * 1000)) {
    $s.EndWaitForConnection($async)
    $r = New-Object System.IO.StreamReader($s); $w = New-Object System.IO.StreamWriter($s); $w.AutoFlush = $true
    $line = $r.ReadLine()
    Write-Output ("SQUAT got client line: $line")
    $w.WriteLine('SQUAT')
    Start-Sleep -Seconds 1
  } else { Write-Output 'SQUAT no client reached it within the hold time' }
} catch { Write-Output ("SQUAT serve error: " + $_.Exception.Message) }
$s.Dispose()
