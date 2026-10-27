# Run as a different user: what can they reach? One `PROBE <name>: <result>` line each.
param(
  [string]$Pipe = '',
  [string]$Server = '.',
  [string]$TokenFile = '',
  [string]$ControlFile = '',
  [int]$Port = 0
)
$ErrorActionPreference = 'Continue'
Write-Output ("PROBE whoami: " + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
if ($Pipe) {
  $short = $Pipe -replace '^\\\\\.\\pipe\\', ''
  foreach ($dir in 'InOut', 'In', 'Out') {
    try {
      $c = New-Object System.IO.Pipes.NamedPipeClientStream($Server, $short, [System.IO.Pipes.PipeDirection]$dir)
      $c.Connect(3000)
      Write-Output ("PROBE pipe-connect-${dir}: CONNECTED (server=$Server)")
      $c.Dispose()
    } catch { Write-Output ("PROBE pipe-connect-${dir}: REFUSED " + $_.Exception.GetType().Name + ": " + $_.Exception.Message) }
  }
}
foreach ($pair in @(@('token-file', $TokenFile), @('control-file', $ControlFile))) {
  if ($pair[1]) {
    try { $t = [System.IO.File]::ReadAllText($pair[1]); Write-Output ("PROBE read-" + $pair[0] + ": READ OK (" + $t.Length + " chars)") }
    catch { Write-Output ("PROBE read-" + $pair[0] + ": DENIED " + $_.Exception.GetType().Name + ": " + $_.Exception.Message) }
  }
}
if ($Port -gt 0) {
  try {
    $tc = New-Object System.Net.Sockets.TcpClient
    $tc.Connect('127.0.0.1', $Port)
    $ns = $tc.GetStream(); $ns.ReadTimeout = 3000
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("not-the-token`n")
    $ns.Write($bytes, 0, $bytes.Length)
    $buf = New-Object byte[] 64
    try { $n = $ns.Read($buf, 0, 64); Write-Output ("PROBE tcp-wrong-token: TCP connected, server closed/replied bytes=$n") }
    catch { Write-Output ("PROBE tcp-wrong-token: TCP connected, read error: " + $_.Exception.GetType().Name) }
    $tc.Close()
  } catch { Write-Output ("PROBE tcp-wrong-token: CONNECT FAILED " + $_.Exception.Message) }
}
