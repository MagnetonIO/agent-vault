# Dump a named pipe's security descriptor three ways. Findings only; never fails the job.
param([Parameter(Mandatory)][string]$Pipe)
$ErrorActionPreference = 'Continue'
$short = $Pipe -replace '^\\\\\.\\pipe\\', ''

Write-Output "--- A: Get-Acl -LiteralPath $Pipe"
try {
  $a = Get-Acl -LiteralPath $Pipe -ErrorAction Stop
  Write-Output ("A.owner: " + $a.Owner)
  Write-Output ("A.sddl: " + $a.Sddl)
  $a.Access | ForEach-Object { "A.ace: {0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights }
} catch { Write-Output ("A.FAILED: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message) }

Write-Output "--- B: CreateFile(READ_CONTROL) + GetSecurityInfo(SE_KERNEL_OBJECT) -> SDDL"
try {
  Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class AvSecInfo {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("advapi32.dll")]
  public static extern uint GetSecurityInfo(SafeFileHandle h, int objType, uint secInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr sd, uint rev, uint secInfo, out IntPtr str, out uint len);
  [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr h);
}
"@
  # READ_CONTROL = 0x20000, share all = 7, OPEN_EXISTING = 3
  $h = [AvSecInfo]::CreateFileW($Pipe, 0x20000, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
  if ($h.IsInvalid) { Write-Output ("B.FAILED: CreateFile win32 error " + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  else {
    $o = [IntPtr]::Zero; $g = [IntPtr]::Zero; $d = [IntPtr]::Zero; $s = [IntPtr]::Zero; $sd = [IntPtr]::Zero
    $rc = [AvSecInfo]::GetSecurityInfo($h, 6, 7, [ref]$o, [ref]$g, [ref]$d, [ref]$s, [ref]$sd)
    if ($rc -ne 0) { Write-Output ("B.FAILED: GetSecurityInfo returned " + $rc) }
    else {
      $p = [IntPtr]::Zero; $len = [uint32]0
      [void][AvSecInfo]::ConvertSecurityDescriptorToStringSecurityDescriptor($sd, 1, 7, [ref]$p, [ref]$len)
      Write-Output ("B.sddl: " + [System.Runtime.InteropServices.Marshal]::PtrToStringUni($p))
      [void][AvSecInfo]::LocalFree($p); [void][AvSecInfo]::LocalFree($sd)
    }
    $h.Dispose()
  }
} catch { Write-Output ("B.FAILED: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message) }

Write-Output "--- C: NamedPipeClientStream(ReadPermissions).GetAccessControl()"
try {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $short, ([System.IO.Pipes.PipeAccessRights]'ReadData,ReadPermissions'), [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::None, [System.IO.HandleInheritability]::None)
  $c.Connect(3000)
  $sec = $c.GetAccessControl()
  Write-Output ("C.owner: " + $sec.GetOwner([System.Security.Principal.NTAccount]))
  Write-Output ("C.sddl: " + $sec.GetSecurityDescriptorSddlForm('All'))
  $sec.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]) | ForEach-Object { "C.ace: {0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.PipeAccessRights }
  $c.Dispose()
} catch { Write-Output ("C.FAILED: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message) }
