<#
.SYNOPSIS
  Collect read-only runtime state for an installed application or service, so a
  fault can be diagnosed from evidence instead of guesses.

.DESCRIPTION
  Given a product/app/service name (wildcards allowed), gathers:

    - uninstall entries (HKLM 64-bit, HKLM 32-bit, HKCU) with install location
    - Windows services and drivers whose name/display name/image path matches
    - scheduled tasks, Run/RunOnce startup entries
    - registered Event Log sources (HKLM\SYSTEM\...\Services\EventLog)
    - application data and log directories, newest log files
    - WER crash report folders and recent MSI install logs in %TEMP%
    - pending-reboot flags, service binary existence, install-dir ACL owner/rights

  Writes state.json into -OutDir and prints a compact summary. Never modifies
  the system: registry and filesystem access is read-only.

.PARAMETER Name
  Product name, service name, app folder or vendor fragment. Wildcards allowed.

.PARAMETER OutDir
  Output directory. Default: .\state-profile

.PARAMETER InstallDir
  Optional install directory to inspect directly (existence, size, ACL, newest files).

.PARAMETER SkipTasks
  Skip scheduled-task enumeration (it is the slowest part on some systems).

.EXAMPLE
  ./collect-state.ps1 -Name 'Acrobat*' -OutDir '.\re\case\state'

.EXAMPLE
  ./collect-state.ps1 -Name 'MyApp' -InstallDir 'C:\Program Files\MyApp'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Name,

  [string]$OutDir = '.\state-profile',
  [string]$InstallDir,
  [switch]$SkipTasks
)

$ErrorActionPreference = 'Continue'
$ToolVersion = '1.0.0'
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$issues = New-Object System.Collections.Generic.List[object]
function Add-Issue([string]$Severity, [string]$Area, [string]$Detail) {
  $issues.Add([pscustomobject][ordered]@{ severity = $Severity; area = $Area; detail = $Detail })
}

$pattern = $Name
function Test-Match([string]$Value) {
  if ([string]::IsNullOrEmpty($Value)) { return $false }
  return ($Value -like "*$pattern*")
}

# ---------------------------------------------------------------- environment
$os = $null
try {
  $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
  $os = [pscustomobject][ordered]@{
    caption        = $osInfo.Caption
    version        = $osInfo.Version
    build          = $osInfo.BuildNumber
    architecture   = $osInfo.OSArchitecture
    lastBoot       = $osInfo.LastBootUpTime
    uptimeHours    = [math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalHours, 1)
    freeMemoryMB   = [math]::Round($osInfo.FreePhysicalMemory / 1KB, 0)
  }
}
catch { Add-Issue 'info' 'os' "OS query failed: $($_.Exception.Message)" }

$disks = @()
try {
  $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [pscustomobject][ordered]@{
      drive      = $_.DeviceID
      sizeGB     = [math]::Round($_.Size / 1GB, 1)
      freeGB     = [math]::Round($_.FreeSpace / 1GB, 1)
      freePercent= if ($_.Size -gt 0) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { 0 }
    }
  })
  foreach ($d in $disks) { if ($d.freeGB -lt 2) { Add-Issue 'warn' 'disk' ("$($d.drive) has only $($d.freeGB) GB free") } }
}
catch { }

# ------------------------------------------------------------ uninstall entries
$uninstall = @()
$keys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($k in $keys) {
  try {
    foreach ($p in (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue)) {
      if ((Test-Match $p.DisplayName) -or (Test-Match $p.InstallLocation) -or (Test-Match $p.Publisher -and (Test-Match $p.DisplayName))) {
        $uninstall += [pscustomobject][ordered]@{
          displayName     = $p.DisplayName
          displayVersion  = $p.DisplayVersion
          publisher       = $p.Publisher
          installLocation = $p.InstallLocation
          uninstallString = $p.UninstallString
          installDate     = $p.InstallDate
          productCode     = $p.PSChildName
          hive            = ($k -replace '\\\*$', '')
        }
      }
    }
  }
  catch { Add-Issue 'info' 'registry' "Uninstall scan failed for $k : $($_.Exception.Message)" }
}

# --------------------------------------------------------------------- services
$services = @()
try {
  $allSvc = @(Get-CimInstance -ClassName Win32_Service)
  foreach ($s in $allSvc) {
    if ((Test-Match $s.Name) -or (Test-Match $s.DisplayName) -or (Test-Match $s.PathName)) {
      $binPath = $null
      if ($s.PathName -match '^"([^"]+)"') { $binPath = $Matches[1] }
      elseif ($s.PathName) { $binPath = ($s.PathName -split ' ')[0] }
      $binExists = $null
      if ($binPath) { $binExists = Test-Path -LiteralPath $binPath }
      $services += [pscustomobject][ordered]@{
        name          = $s.Name
        displayName   = $s.DisplayName
        state         = $s.State
        startMode     = $s.StartMode
        startName     = $s.StartName
        pathName      = $s.PathName
        binaryExists  = $binExists
        processId     = $s.ProcessId
        exitCode      = $s.ExitCode
      }
      if ($binExists -eq $false) { Add-Issue 'error' 'service' "$($s.Name): binary not found at $binPath" }
      if ($s.State -ne 'Running' -and $s.StartMode -eq 'Auto') { Add-Issue 'warn' 'service' "$($s.Name) is $($s.State) but set to Auto" }
    }
  }
}
catch { Add-Issue 'info' 'service' "Service query failed: $($_.Exception.Message)" }

$drivers = @()
try {
  foreach ($d in (Get-CimInstance -ClassName Win32_SystemDriver)) {
    if ((Test-Match $d.Name) -or (Test-Match $d.DisplayName) -or (Test-Match $d.PathName)) {
      $drivers += [pscustomobject][ordered]@{
        name = $d.Name; displayName = $d.DisplayName; state = $d.State; startMode = $d.StartMode; pathName = $d.PathName
      }
    }
  }
}
catch { }

# --------------------------------------------------------------- startup items
$runEntries = @()
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($rk in $runKeys) {
  try {
    $item = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
    if ($null -eq $item) { continue }
    foreach ($prop in $item.PSObject.Properties) {
      if ($prop.Name -like 'PS*') { continue }
      if ((Test-Match $prop.Name) -or (Test-Match ([string]$prop.Value))) {
        $runEntries += [pscustomobject][ordered]@{ key = $rk; name = $prop.Name; command = [string]$prop.Value }
      }
    }
  }
  catch { }
}

# ---------------------------------------------------------------- scheduled tasks
$tasks = @()
if (-not $SkipTasks) {
  try {
    foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
      $full = ($t.TaskPath + $t.TaskName)
      $actionText = ''
      foreach ($a in $t.Actions) { $actionText += "$($a.Execute) $($a.Arguments) " }
      if ((Test-Match $full) -or (Test-Match $actionText)) {
        $tasks += [pscustomobject][ordered]@{
          taskPath = $t.TaskPath; taskName = $t.TaskName; state = [string]$t.State
          actions = $actionText.Trim(); principal = [string]$t.Principal.UserId
        }
      }
    }
  }
  catch { Add-Issue 'info' 'tasks' "Scheduled task scan failed: $($_.Exception.Message)" }
}

# ------------------------------------------------------------- event log sources
$eventSources = @()
foreach ($log in @('Application', 'System')) {
  $base = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$log"
  try {
    foreach ($sub in (Get-ChildItem -Path $base -ErrorAction SilentlyContinue)) {
      $srcName = $sub.PSChildName
      if (Test-Match $srcName) {
        $props = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
        $eventSources += [pscustomobject][ordered]@{
          log = $log; source = $srcName; eventMessageFile = $props.EventMessageFile
          typesSupported = $props.TypesSupported
        }
      }
    }
  }
  catch { }
}

# --------------------------------------------------------------- data/log dirs
$candidateDirs = @()
foreach ($root in @($env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, "$env:ProgramFiles", "${env:ProgramFiles(x86)}")) {
  if (-not $root) { continue }
  try {
    foreach ($d in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
      if ($d.Name -like "*$pattern*") { $candidateDirs += $d.FullName }
    }
  }
  catch { }
}
if ($InstallDir -and (Test-Path -LiteralPath $InstallDir)) { $candidateDirs = @($InstallDir) + $candidateDirs }
$candidateDirs = @($candidateDirs | Select-Object -Unique)

$dirsReport = @()
$logFiles = @()
foreach ($d in $candidateDirs) {
  try {
    $files = @(Get-ChildItem -LiteralPath $d -File -Recurse -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 40)
    $totalBytes = 0
    foreach ($f in $files) { $totalBytes += $f.Length }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $d } catch { }
    $dirsReport += [pscustomobject][ordered]@{
      path          = $d
      exists        = $true
      fileCount     = $files.Count
      sampledBytes  = $totalBytes
      lastWrite     = if ($files.Count -gt 0) { $files[0].LastWriteTime } else { $null }
      owner         = if ($acl) { $acl.Owner } else { $null }
    }
    foreach ($f in $files) {
      if ($f.Extension -in '.log', '.txt', '.etl', '.dmp', '.wer', '.json', '.xml', '.ini', '.cfg', '.conf') {
        $logFiles += [pscustomobject][ordered]@{ path = $f.FullName; sizeKB = [math]::Round($f.Length / 1KB, 1); lastWrite = $f.LastWriteTime }
      }
    }
  }
  catch { Add-Issue 'info' 'files' "Cannot inspect $d : $($_.Exception.Message)" }
}
$logFiles = @($logFiles | Sort-Object lastWrite -Descending | Select-Object -First 40)

# ---------------------------------------------------------------- install dir
$installInfo = $null
if ($InstallDir) {
  if (Test-Path -LiteralPath $InstallDir) {
    try {
      $acl = Get-Acl -LiteralPath $InstallDir
      $top = @(Get-ChildItem -LiteralPath $InstallDir -ErrorAction SilentlyContinue)
      $installInfo = [pscustomobject][ordered]@{
        path = (Resolve-Path -LiteralPath $InstallDir).Path
        exists = $true
        topLevelEntries = $top.Count
        owner = $acl.Owner
        accessRules = @($acl.Access | ForEach-Object { "$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)" })
      }
    }
    catch { }
  }
  else {
    $installInfo = [pscustomobject][ordered]@{ path = $InstallDir; exists = $false }
    Add-Issue 'error' 'install-dir' "Install directory does not exist: $InstallDir"
  }
}

# ------------------------------------------------------------- WER + MSI logs
$wer = @()
try {
  $werRoot = Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'
  if (Test-Path -LiteralPath $werRoot) {
    foreach ($d in (Get-ChildItem -LiteralPath $werRoot -Directory -ErrorAction SilentlyContinue)) {
      if (Test-Match $d.Name) {
        $wer += [pscustomobject][ordered]@{ folder = $d.FullName; lastWrite = $d.LastWriteTime; ageDays = [math]::Round(((Get-Date) - $d.LastWriteTime).TotalDays, 1) }
      }
    }
  }
}
catch { }

$installLogs = @()
try {
  $installLogs = @(Get-ChildItem -LiteralPath $env:TEMP -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'MSI*.LOG' -or $_.Name -like "*$pattern*" } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 15 |
    ForEach-Object { [pscustomobject][ordered]@{ path = $_.FullName; sizeKB = [math]::Round($_.Length / 1KB, 1); lastWrite = $_.LastWriteTime } })
}
catch { }

# ------------------------------------------------------------- pending reboot
$pendingReboot = $false
foreach ($k in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
  if (Test-Path -LiteralPath $k) { $pendingReboot = $true }
}
try {
  $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
  if ($null -ne $pfro.PendingFileRenameOperations) { $pendingReboot = $true }
}
catch { }
if ($pendingReboot) { Add-Issue 'warn' 'system' 'A pending reboot can block installation, repair and uninstall.' }

# ------------------------------------------------------------------- assemble
$state = [pscustomobject][ordered]@{
  tool        = 'collect-state'
  toolVersion = $ToolVersion
  generated   = (Get-Date).ToString('o')
  query       = $Name
  environment = $os
  disks       = $disks
  uninstall   = $uninstall
  services    = $services
  drivers     = $drivers
  startup     = $runEntries
  tasks       = $tasks
  eventSources= $eventSources
  directories = $dirsReport
  logFiles    = $logFiles
  installDir  = $installInfo
  werReports  = $wer
  installLogs = $installLogs
  pendingReboot = $pendingReboot
  issues      = $issues
}

$statePath = Join-Path $OutDir 'state.json'
$state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statePath -Encoding UTF8

[ordered]@{
  status    = 'ok'
  outDir    = $OutDir
  state     = $statePath
  query     = $Name
  counts    = [ordered]@{
    uninstall = $uninstall.Count; services = $services.Count; drivers = $drivers.Count
    startup = $runEntries.Count; tasks = $tasks.Count; eventSources = $eventSources.Count
    directories = $dirsReport.Count; logFiles = $logFiles.Count; werReports = $wer.Count
    installLogs = $installLogs.Count
  }
  pendingReboot = $pendingReboot
  issues    = $issues.ToArray()
} | ConvertTo-Json -Depth 8
