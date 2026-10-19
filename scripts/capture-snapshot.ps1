<#
.SYNOPSIS
  Take a read-only runtime snapshot of the targets named by a probe plan.

.DESCRIPTION
  Executes the observation half of the plan produced by build-probe-plan.ps1:
  files under the watched paths, the named registry keys and values, service
  state, matching processes and their listening ports, Event Log entries, and
  WER crash folders. Writes <OutDir>\<Label>.json.

  Nothing is modified. Run it once before the reproduction (label "before") and
  once after (label "after"), then feed both to diff-snapshots.ps1.

.PARAMETER Plan
  probe-plan.json from build-probe-plan.ps1.

.PARAMETER Label
  Snapshot name; used as the file name. Default: snapshot

.PARAMETER OutDir
  Output directory. Default: .\probe-snapshots

.PARAMETER SinceMinutes
  How far back the Event Log query looks. Keep it close to the reproduction window.

.PARAMETER MaxFilesPerPath
  Safety cap per watched path. Default 2000.

.EXAMPLE
  ./capture-snapshot.ps1 -Plan .\probe-plan\probe-plan.json -Label before

.EXAMPLE
  ./capture-snapshot.ps1 -Plan .\probe-plan\probe-plan.json -Label after -SinceMinutes 10
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Plan,

  [string]$Label = 'snapshot',
  [string]$OutDir = '.\probe-snapshots',
  [int]$SinceMinutes = 30,
  [int]$MaxFilesPerPath = 2000
)

$ErrorActionPreference = 'Continue'
$ToolVersion = '1.0.0'

if (-not (Test-Path -LiteralPath $Plan)) {
  [ordered]@{ tool = 'capture-snapshot'; status = 'error'; message = "Plan not found: $Plan" } | ConvertTo-Json
  exit 2
}
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$p = Get-Content -LiteralPath $Plan -Raw -Encoding UTF8 | ConvertFrom-Json
$generated = (Get-Date).ToString('o')
$errors = New-Object System.Collections.Generic.List[string]

# Paths too broad to enumerate; we record their existence only.
$broadRoots = @(
  $env:windir,
  (Join-Path $env:windir 'System32'),
  $env:ProgramData,
  $env:ProgramFiles,
  ${env:ProgramFiles(x86)},
  $env:LOCALAPPDATA,
  $env:APPDATA
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() }

function Test-BroadPath([string]$Path) {
  if ([string]::IsNullOrEmpty($Path)) { return $true }
  $norm = $Path.TrimEnd('\').ToLowerInvariant()
  return ($broadRoots -contains $norm)
}

# ------------------------------------------------------------------- files
$pathSnapshots = New-Object System.Collections.Generic.List[object]
foreach ($target in $p.paths) {
  $real = [string]$target.real
  if ([string]::IsNullOrEmpty($real)) { continue }
  $exists = Test-Path -LiteralPath $real
  $entry = [ordered]@{
    path       = $real
    role       = [string]$target.role
    exists     = $exists
    broad      = (Test-BroadPath $real)
    fileCount  = 0
    totalBytes = 0
    newestWrite= $null
    owner      = $null
    truncated  = $false
    files      = @()
  }
  if ($exists) {
    try { $entry.owner = (Get-Acl -LiteralPath $real).Owner } catch { }
    if (-not $entry.broad) {
      try {
        $all = @(Get-ChildItem -LiteralPath $real -File -Recurse -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTimeUtc -Descending)
        $entry.fileCount = $all.Count
        $sum = 0L
        foreach ($f in $all) { $sum += $f.Length }
        $entry.totalBytes = $sum
        if ($all.Count -gt 0) { $entry.newestWrite = $all[0].LastWriteTimeUtc.ToString('o') }
        $take = @($all | Select-Object -First $MaxFilesPerPath)
        if ($all.Count -gt $MaxFilesPerPath) { $entry.truncated = $true }
        $entry.files = @($take | ForEach-Object {
            [ordered]@{
              path  = $_.FullName
              size  = $_.Length
              write = $_.LastWriteTimeUtc.ToString('o')
            }
          })
      }
      catch { $errors.Add("files: $real -> $($_.Exception.Message)") }
    }
  }
  $pathSnapshots.Add([pscustomobject]$entry)
}

# ---------------------------------------------------------------- registry
$regSnapshots = New-Object System.Collections.Generic.List[object]
foreach ($k in $p.registry) {
  $psPath = [string]$k.psPath
  $entry = [ordered]@{
    psPath  = $psPath
    reason  = [string]$k.reason
    exists  = $false
    values  = @{}
    subKeys = @()
  }
  try {
    if (Test-Path -LiteralPath $psPath) {
      $entry.exists = $true
      $item = Get-ItemProperty -LiteralPath $psPath -ErrorAction Stop
      $bag = @{}
      foreach ($prop in $item.PSObject.Properties) {
        if ($prop.Name -like 'PS*') { continue }
        $bag[$prop.Name] = [string]$prop.Value
      }
      $entry.values = $bag
      $entry.subKeys = @(Get-ChildItem -LiteralPath $psPath -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
    }
  }
  catch { $errors.Add("registry: $psPath -> $($_.Exception.Message)") }
  $regSnapshots.Add([pscustomobject]$entry)
}

# ---------------------------------------------------------------- services
$svcSnapshots = New-Object System.Collections.Generic.List[object]
foreach ($s in $p.services) {
  $name = [string]$s.name
  if ([string]::IsNullOrEmpty($name)) { continue }
  $live = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + ($name -replace "'", "''") + "'") -ErrorAction SilentlyContinue
  $svcSnapshots.Add([pscustomobject][ordered]@{
      name        = $name
      installed   = [bool]$live
      state       = if ($live) { [string]$live.State } else { $null }
      startMode   = if ($live) { [string]$live.StartMode } else { $null }
      startName   = if ($live) { [string]$live.StartName } else { $null }
      pathName    = if ($live) { [string]$live.PathName } else { $null }
      exitCode    = if ($live) { $live.ExitCode } else { $null }
      processId   = if ($live) { $live.ProcessId } else { $null }
    })
}

# --------------------------------------------------------------- processes
$procSnapshots = New-Object System.Collections.Generic.List[object]
$pids = @()
foreach ($name in $p.processes) {
  if ([string]::IsNullOrEmpty($name)) { continue }
  foreach ($proc in (Get-Process -Name $name -ErrorAction SilentlyContinue)) {
    $procPath = $null
    try { $procPath = $proc.MainModule.FileName } catch { }
    $startText = $null
    try { $startText = $proc.StartTime.ToString('o') } catch { }
    $procSnapshots.Add([pscustomobject][ordered]@{
        name       = $proc.ProcessName
        id         = $proc.Id
        startTime  = $startText
        path       = $procPath
        responding = $proc.Responding
        workingSetMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
      })
    $pids += $proc.Id
  }
}

# ------------------------------------------------------------------- ports
$portSnapshots = @()
if ($pids.Count -gt 0) {
  try {
    $portSnapshots = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
      Where-Object { $pids -contains $_.OwningProcess } |
      ForEach-Object {
        [pscustomobject][ordered]@{
          localAddress = [string]$_.LocalAddress
          localPort    = $_.LocalPort
          remoteAddress= [string]$_.RemoteAddress
          remotePort   = $_.RemotePort
          state        = [string]$_.State
          processId    = $_.OwningProcess
        }
      })
  }
  catch { $errors.Add("ports: $($_.Exception.Message)") }
}

# -------------------------------------------------------------- event logs
$since = (Get-Date).AddMinutes(-1 * [Math]::Abs($SinceMinutes))
$eventSnapshots = New-Object System.Collections.Generic.List[object]
foreach ($q in $p.eventLog) {
  $logName = [string]$q.log
  $source = [string]$q.source
  $ids = @()
  if ($q.ids) { $ids = @($q.ids | ForEach-Object { [int]$_ }) }
  try {
    $filter = @{ LogName = $logName; StartTime = $since }
    if ($source) { $filter.ProviderName = $source }
    if ($ids.Count -gt 0) { $filter.Id = $ids }
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 60 -ErrorAction Stop)
    foreach ($e in $events) {
      $msg = [string]$e.Message
      if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) }
      $eventSnapshots.Add([pscustomobject][ordered]@{
          log        = $logName
          source     = [string]$e.ProviderName
          timeCreated= $e.TimeCreated.ToString('o')
          id         = $e.Id
          level      = [string]$e.LevelDisplayName
          message    = $msg
        })
    }
  }
  catch {
    $msg = [string]$_.Exception.Message
    if ($msg -notmatch 'No events were found') { $errors.Add("events: $logName/$source -> $msg") }
  }
}

# ------------------------------------------------------------------- WER
$werSnapshots = @()
try {
  $werRoot = Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'
  if (Test-Path -LiteralPath $werRoot) {
    $werSnapshots = @(Get-ChildItem -LiteralPath $werRoot -Directory -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 100 |
      ForEach-Object { [pscustomobject][ordered]@{ folder = $_.Name; path = $_.FullName; lastWrite = $_.LastWriteTimeUtc.ToString('o') } })
  }
}
catch { }

# ------------------------------------------------------------------ output
$snapshot = [ordered]@{
  tool        = 'capture-snapshot'
  toolVersion = $ToolVersion
  generated   = $generated
  label       = $Label
  plan        = (Resolve-Path -LiteralPath $Plan).Path
  product     = $p.product
  sinceUtc    = $since.ToUniversalTime().ToString('o')
  machine     = $env:COMPUTERNAME
  paths       = $pathSnapshots.ToArray()
  registry    = $regSnapshots.ToArray()
  services    = $svcSnapshots.ToArray()
  processes   = $procSnapshots.ToArray()
  ports       = $portSnapshots
  events      = $eventSnapshots.ToArray()
  wer         = $werSnapshots
  errors      = $errors.ToArray()
}

$file = Join-Path $OutDir ("{0}.json" -f ($Label -replace '[^\w\-]', '_'))
$snapshot | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $file -Encoding UTF8

[ordered]@{
  status    = 'ok'
  snapshot  = $file
  label     = $Label
  counts    = [ordered]@{
    paths = $pathSnapshots.Count; existingPaths = @($pathSnapshots | Where-Object { $_.exists }).Count
    registryKeys = $regSnapshots.Count; existingKeys = @($regSnapshots | Where-Object { $_.exists }).Count
    services = $svcSnapshots.Count; processes = $procSnapshots.Count; ports = $portSnapshots.Count
    events = $eventSnapshots.Count; wer = $werSnapshots.Count
  }
  errors    = $errors.ToArray()
} | ConvertTo-Json -Depth 6
