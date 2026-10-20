<#
.SYNOPSIS
  Enroll this host with an ELF server and write config.ini for a console run.

.DESCRIPTION
  The production path is the server-generated install script (Agents tab ->
  "+ Add New Agent"), which creates the least-privilege service. This script
  is the ten-minute demo path instead: it registers this computer in a group
  and writes a config.ini next to the agent exe so you can run

      .\efficient_log_forwarder.exe --debug

  from an elevated console and watch alerts scroll by.

  Steps:
    1. Logs in to the server as an admin (cookie session) to resolve the
       group name to its id.
    2. POST /agents/register with that group -> the agent's auth token.
    3. Writes config.ini (server URL, agent id = this computer name, token,
       exe-relative rules/ and lists/ directories, three file destinations
       under %ProgramData%\ELFAgent\output).

.PARAMETER Server
  Base URL of the ELF server, e.g. http://localhost:8000

.PARAMETER Group
  Group the agent should join. "workstations" holds the seeded kill-chain
  rules (requires ELF_SEED_TEST_DATA=1 on the server, the default compose).

.PARAMETER AgentDir
  Directory containing efficient_log_forwarder.exe. Defaults to the
  directory this script is run from.

.EXAMPLE
  .\enroll-agent.ps1 -Server http://localhost:8000 -Group workstations -AgentDir C:\elf
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Server,
    [string]$Group = 'workstations',
    [string]$AgentDir = (Get-Location).Path,
    [string]$Username = 'admin',
    [string]$Password
)

$ErrorActionPreference = 'Stop'
$Server = $Server.TrimEnd('/')
$exe = Join-Path $AgentDir 'efficient_log_forwarder.exe'
if (-not (Test-Path $exe)) { throw "efficient_log_forwarder.exe not found in $AgentDir (use -AgentDir)" }

if (-not $Password) {
    $sec = Read-Host -Prompt "Password for '$Username' on $Server" -AsSecureString
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}

# 1. Admin login -> session cookie -> group id.
$null = Invoke-RestMethod -Uri "$Server/auth/login" -Method Post -ContentType 'application/json' `
    -Body (@{ username = $Username; password = $Password } | ConvertTo-Json) -SessionVariable sess
$groups = Invoke-RestMethod -Uri "$Server/groups" -WebSession $sess
$g = $groups | Where-Object { $_.name -eq $Group } | Select-Object -First 1
if (-not $g) {
    throw "Group '$Group' not found on $Server. Available: $(($groups | ForEach-Object name) -join ', ')"
}

# 2. Register this host in the group; the raw token is returned exactly once.
$agentId = $env:COMPUTERNAME
$reg = Invoke-RestMethod -Uri "$Server/agents/register" -Method Post -ContentType 'application/json' `
    -Body (@{ agent_id = $agentId; hostname = $agentId; os_name = (Get-CimInstance Win32_OperatingSystem).Caption;
              group_id = [int]$g.id } | ConvertTo-Json)
if (-not $reg.auth_token) { throw "Server did not return an auth_token for $agentId" }

# 3. config.ini next to the exe. Relative file:// paths resolve under
#    %ProgramData%\ELFAgent\output (the agent's writable data root).
$ini = @"
[buffer]
retention_seconds=30

[rules]
directory=rules

[lists]
directory=lists

[server]
url=$Server
poll_interval_seconds=30
agent_id=$agentId
auth_token=$($reg.auth_token)

[logging]
level=notice
max_file_size_mb=1
max_files=3

[spool]
max_spool_mb=100

[destinations]
siem = file://output/siem.jsonl
data_lake = file://output/data_lake.jsonl
alerts = file://output/alerts.jsonl
"@
$iniPath = Join-Path $AgentDir 'config.ini'
Set-Content -Path $iniPath -Value $ini -Encoding ascii
foreach ($d in 'rules', 'lists') { New-Item -ItemType Directory -Force (Join-Path $AgentDir $d) | Out-Null }

Write-Host "Enrolled '$agentId' in group '$Group' (id $($g.id)) on $Server"
Write-Host "Wrote $iniPath"
Write-Host ""
Write-Host "Next, from an elevated console in ${AgentDir}:"
Write-Host "    .\efficient_log_forwarder.exe --debug"
Write-Host "Outputs land in $env:ProgramData\ELFAgent\output\ ; alerts also appear on the server's Alerts tab."
