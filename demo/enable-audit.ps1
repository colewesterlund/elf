<#
.SYNOPSIS
  Turn on the Windows audit subcategories the ELF demo rules need.

.DESCRIPTION
  Most of the seeded kill-chain rules match Security 4688 (process creation
  with the command line) and 4625 (failed logon). Workstations do not audit
  these by default. This script enables, on the local host only:

    - Detailed Tracking \ Process Creation   (success)   -> 4688
    - ProcessCreationIncludeCmdLine_Enabled  (registry)  -> CommandLine field
    - Logon/Logoff \ Logon                    (failure)   -> 4625
    - Object Access \ Filtering Platform Connection (success) -> 5156
      (only with -IncludeNetwork; it is noisy)

  Run from an elevated PowerShell. Re-run with -Revert to put the policy back
  to "No Auditing" and remove the registry value. A domain GPO that sets
  these subcategories overrides local settings at the next refresh.

.EXAMPLE
  .\enable-audit.ps1
  .\enable-audit.ps1 -IncludeNetwork
  .\enable-audit.ps1 -Revert
#>
[CmdletBinding()]
param(
    [switch]$IncludeNetwork,
    [switch]$Revert
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this from an elevated PowerShell (Run as Administrator)." }

$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

function Set-Sub($name, $success, $failure) {
    $s = if ($success) { 'enable' } else { 'disable' }
    $f = if ($failure) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:"$name" /success:$s /failure:$f | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for '$name'" }
    Write-Host ("  {0,-36} success={1} failure={2}" -f $name, $s, $f)
}

if ($Revert) {
    Write-Host "Reverting audit policy to No Auditing:"
    Set-Sub 'Process Creation' $false $false
    Set-Sub 'Logon' $false $false
    Set-Sub 'Filtering Platform Connection' $false $false
    if (Test-Path $regPath) {
        Remove-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
        Write-Host "  ProcessCreationIncludeCmdLine_Enabled removed"
    }
    Write-Host "Done."
    return
}

Write-Host "Enabling audit subcategories for the ELF demo:"
Set-Sub 'Process Creation' $true $false
Set-Sub 'Logon' $false $true
if ($IncludeNetwork) { Set-Sub 'Filtering Platform Connection' $true $false }

New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1
Write-Host "  ProcessCreationIncludeCmdLine_Enabled = 1 (4688 carries the command line)"

Write-Host ""
Write-Host "Current settings:"
& auditpol.exe /get /subcategory:"Process Creation","Logon","Filtering Platform Connection" | Select-Object -Skip 2
Write-Host ""
Write-Host "Revert later with:  .\enable-audit.ps1 -Revert"
