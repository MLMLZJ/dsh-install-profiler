<#
.SYNOPSIS
  Probe which installer-analysis tools are available on this machine.

.DESCRIPTION
  Read-only, fast (~1-2 s). Resolves each tool from PATH and from well-known
  install directories, then reports path, version and status. The result decides
  which extraction/diagnosis steps are possible and which need an install.

  Nothing is installed or executed beyond reading file version metadata.

.EXAMPLE
  ./probe-tools.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

function Resolve-Tool {
  param([string]$Name, [string[]]$Candidates)
  $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) { return $cmd.Source }
  foreach ($c in $Candidates) {
    if ([string]::IsNullOrEmpty($c)) { continue }
    if (Test-Path -LiteralPath $c) { return $c }
  }
  return $null
}

function Get-ToolVersion([string]$Path) {
  if (-not $Path) { return $null }
  try {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $v = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($v)) { $v = $vi.FileVersion }
    return $v
  }
  catch { return $null }
}

$pf   = $env:ProgramFiles
$pf86 = ${env:ProgramFiles(x86)}
$la   = $env:LOCALAPPDATA

$defs = @(
  @{ name = '7z';            group = 'extract';   candidates = @("$pf\7-Zip\7z.exe", "$pf86\7-Zip\7z.exe", "$la\Programs\7-Zip\7z.exe") }
  @{ name = 'msiexec';       group = 'extract';   candidates = @("$env:windir\System32\msiexec.exe"); builtin = $true }
  @{ name = 'lessmsi';       group = 'extract';   candidates = @("$pf\lessmsi\lessmsi.exe", "$pf86\lessmsi\lessmsi.exe", "$la\Apps\lessmsi\lessmsi.exe") }
  @{ name = 'dark';          group = 'extract';   candidates = @("$pf\WiX Toolset v3.14\bin\dark.exe", "$pf86\WiX Toolset v3.14\bin\dark.exe", "$pf\WiX Toolset v3.11\bin\dark.exe") }
  @{ name = 'innoextract';   group = 'extract';   candidates = @("$pf\innoextract\innoextract.exe", "$pf86\innoextract\innoextract.exe") }
  @{ name = 'makeappx';      group = 'extract';   candidates = @("$pf\Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe") }
  @{ name = 'sigcheck';      group = 'trust';     candidates = @("$pf\SysinternalsSuite\sigcheck.exe", "$pf86\SysinternalsSuite\sigcheck.exe", "$pf\Sysinternals\sigcheck.exe") }
  @{ name = 'signtool';      group = 'trust';     candidates = @() }
  @{ name = 'strings';       group = 'inspect';   candidates = @("$pf\SysinternalsSuite\strings.exe", "$pf86\SysinternalsSuite\strings.exe") }
  @{ name = 'objdump';       group = 'inspect';   candidates = @() }
  @{ name = 'dumpbin';       group = 'inspect';   candidates = @() }
  @{ name = 'ilspycmd';      group = 'decompile'; candidates = @("$env:USERPROFILE\.dotnet\tools\ilspycmd.exe") }
  @{ name = 'dotnet';        group = 'decompile'; candidates = @("$pf\dotnet\dotnet.exe") }
  @{ name = 'rizin';         group = 'decompile'; candidates = @() }
  @{ name = 'upx';           group = 'decompile'; candidates = @() }
  @{ name = 'monodis';       group = 'decompile'; candidates = @() }
  @{ name = 'python';        group = 'runtime';   candidates = @() }
  @{ name = 'node';          group = 'runtime';   candidates = @() }
  @{ name = 'npx';           group = 'runtime';   candidates = @() }
  @{ name = 'procmon';       group = 'runtime';   candidates = @("$pf\SysinternalsSuite\Procmon64.exe", "$pf\SysinternalsSuite\Procmon.exe") }
  @{ name = 'procmon64';     group = 'runtime';   candidates = @("$pf\SysinternalsSuite\Procmon64.exe") }
  @{ name = 'autoruns';      group = 'runtime';   candidates = @("$pf\SysinternalsSuite\Autoruns64.exe") }
  @{ name = 'accesschk';     group = 'runtime';   candidates = @("$pf\SysinternalsSuite\accesschk64.exe", "$pf\SysinternalsSuite\accesschk.exe") }
  @{ name = 'wevtutil';      group = 'logs';      candidates = @("$env:windir\System32\wevtutil.exe"); builtin = $true }
  @{ name = 'eventvwr';      group = 'logs';      candidates = @("$env:windir\System32\eventvwr.exe"); builtin = $true }
  @{ name = 'reg';           group = 'registry';  candidates = @("$env:windir\System32\reg.exe"); builtin = $true }
  @{ name = 'sc';            group = 'registry';  candidates = @("$env:windir\System32\sc.exe"); builtin = $true }
  @{ name = 'msinfo32';      group = 'system';    candidates = @("$env:windir\System32\msinfo32.exe"); builtin = $true }
  @{ name = 'pnputil';       group = 'system';    candidates = @("$env:windir\System32\pnputil.exe"); builtin = $true }
  @{ name = 'wevtutil.bak';  group = 'skip';      candidates = @() }
)

$results = @()
foreach ($d in $defs) {
  if ($d.group -eq 'skip') { continue }
  $path = Resolve-Tool -Name $d.name -Candidates $d.candidates
  $results += [pscustomobject][ordered]@{
    name    = $d.name
    group   = $d.group
    found   = [bool]$path
    path    = $path
    version = (Get-ToolVersion $path)
    builtin = [bool]$d.builtin
  }
}

# PowerShell version matters: several COM/JSON quirks differ between 5.1 and 7.x.
$psVersion = $PSVersionTable.PSVersion.ToString()

$byGroup = [ordered]@{}
foreach ($g in ($results | Group-Object group | Sort-Object Name)) {
  $byGroup[$g.Name] = [ordered]@{
    available = @($g.Group | Where-Object { $_.found } | ForEach-Object { $_.name })
    missing   = @($g.Group | Where-Object { -not $_.found } | ForEach-Object { $_.name })
  }
}

$missing = @($results | Where-Object { -not $_.found } | ForEach-Object { $_.name })

[ordered]@{
  tool        = 'probe-tools'
  toolVersion = '1.0.0'
  generated   = (Get-Date).ToString('o')
  machine     = $env:COMPUTERNAME
  os          = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
  powershell  = $psVersion
  groups      = $byGroup
  tools       = $results
  missing     = $missing
  notes       = @(
    'msiexec, reg, sc, wevtutil, eventvwr, msinfo32 are built into Windows.',
    'lessmsi/dark/innoextract/makeappx/sigcheck/strings/accesschk/Procmon are optional Sysinternals/WiX/third-party tools; install them only with user approval.',
    'export-msi-tables.ps1 needs no external tool: it uses the WindowsInstaller COM server.',
    'mine-strings.ps1 needs no external tool either: it scans the binary directly (ASCII + UTF-16LE).',
    'The decompile group is only needed when the installer/app itself must be read (.NET bootstrap, Electron, native loader). If the reverse-engineering skill is installed, use its probe for the deeper toolchain instead of duplicating it.',
    'In PowerShell 5.1, keep [void] before MSI COM Execute()/Close() calls; otherwise empty values leak into the pipeline.'
  )
} | ConvertTo-Json -Depth 8
