# Bind 127.0.0.1:<Port> and impersonate vaultd badly: read the client's first bytes, answer with a
# plausible-looking mac+nonce line, then count whatever the client sends afterwards.
param(
  [Parameter(Mandatory)][int]$Port,
  [int]$HoldSeconds = 20,
  [switch]$Reuse
)
$ErrorActionPreference = 'Stop'
try {
  $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse('127.0.0.1'), $Port)
  if ($Reuse) {
    $l.ExclusiveAddressUse = $false
    $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
  }
  $l.Start()
  Write-Output ("SQUATTCP bound as " + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name + " reuse=$Reuse")
} catch {
  Write-Output ("SQUATTCP bind FAILED: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
  exit 0
}
$end = (Get-Date).AddSeconds($HoldSeconds)
$clients = 0
while ((Get-Date) -lt $end) {
  if (-not $l.Pending()) { Start-Sleep -Milliseconds 50; continue }
  $c = $l.AcceptTcpClient(); $clients++
  $s = $c.GetStream(); $s.ReadTimeout = 1500
  $buf = New-Object byte[] 4096; $first = 0; $after = 0
  try { $first = $s.Read($buf, 0, 4096) } catch {}
  $fake = ('a' * 64) + ' ' + ('b' * 64) + "`n"
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($fake)
  try { $s.Write($bytes, 0, $bytes.Length) } catch {}
  try { while ($true) { $n = $s.Read($buf, 0, 4096); if ($n -le 0) { break }; $after += $n } } catch {}
  Write-Output ("SQUATTCP client=$clients first=$first after=$after")
  $c.Close()
}
Write-Output ("SQUATTCP done clients=$clients")
$l.Stop()
