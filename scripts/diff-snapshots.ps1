<#
.SYNOPSIS
  Diff two runtime snapshots and turn the changes into ranked findings.

.DESCRIPTION
  Compares a "before" and an "after" snapshot from capture-snapshot.ps1 and
  reports what moved: files added/removed/modified under the watched paths,
  registry values created/changed/deleted, service state and configuration
  changes, processes that appeared or exited, ports opened or closed, new Event
  Log entries, and new WER crash folders.

  Every difference becomes a finding with a severity (error / warn / info) and a
  plain-language mechanism hint, so the next step is a hypothesis to test rather
  than a wall of raw diff.

.PARAMETER Before
  Path to the "before" snapshot JSON.

.PARAMETER After
  Path to the "after" snapshot JSON.

.PARAMETER OutDir
  Output directory. Default: .\probe-diff

.EXAMPLE
  ./diff-snapshots.ps1 -Before .\probe-snapshots\before.json -After .\probe-snapshots\after.json
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Before,

  [Parameter(Mandatory = $true, Position = 1)]
  [string]$After,

  [string]$OutDir = '.\probe-diff'
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'

foreach ($f in @($Before, $After)) {
  if (-not (Test-Path -LiteralPath $f)) {
    [ordered]@{ tool = 'diff-snapshots'; status = 'error'; message = "Snapshot not found: $f" } | ConvertTo-Json
    exit 2
  }
}
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$b = Get-Content -LiteralPath $Before -Raw -Encoding UTF8 | ConvertFrom-Json
$a = Get-Content -LiteralPath $After -Raw -Encoding UTF8 | ConvertFrom-Json

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Severity, [string]$Area, [string]$Change, [string]$Detail) {
  $findings.Add([pscustomobject][ordered]@{ severity = $Severity; area = $Area; change = $Change; detail = $Detail })
}

function Index-By($items, [string]$key) {
  $h = @{}
  if ($null -eq $items) { return $h }
  foreach ($i in $items) {
    $k = [string]$i.$key
    if ([string]::IsNullOrEmpty($k)) { continue }
    $h[$k] = $i
  }
  return $h
}

# ------------------------------------------------------------------- paths
$bPaths = Index-By $b.paths 'path'
$aPaths = Index-By $a.paths 'path'
foreach ($key in $aPaths.Keys) {
  $av = $aPaths[$key]
  if (-not $bPaths.ContainsKey($key)) { continue }
  $bv = $bPaths[$key]
  if ($bv.exists -and -not $av.exists) {
    Add-Finding 'error' 'path' 'disappeared' "Watched path existed before and is gone after: $key"
    continue
  }
  if (-not $bv.exists -and $av.exists) {
    Add-Finding 'info' 'path' 'created' "Watched path did not exist before and now does: $key"
    continue
  }
  if (-not $av.exists) { continue }

  $bFiles = Index-By $bv.files 'path'
  $aFiles = Index-By $av.files 'path'
  $added = @(); $removed = @(); $modified = @()
  foreach ($k in $aFiles.Keys) {
    if (-not $bFiles.ContainsKey($k)) { $added += $k; continue }
    $x = $bFiles[$k]; $y = $aFiles[$k]
    if (([string]$x.size -ne [string]$y.size) -or ([string]$x.write -ne [string]$y.write)) { $modified += $k }
  }
  foreach ($k in $bFiles.Keys) { if (-not $aFiles.ContainsKey($k)) { $removed += $k } }

  if ($added.Count -gt 0) {
    Add-Finding 'info' 'files' 'added' ("{0}: {1} new file(s) under {2}. Sample: {3}" -f $key, $added.Count, $key, (($added | Select-Object -First 5) -join '; '))
  }
  if ($removed.Count -gt 0) {
    $sev = 'warn'
    if ($bv.role -eq 'install-root') { $sev = 'error' }
    Add-Finding $sev 'files' 'removed' ("{0}: {1} file(s) present before are gone. Sample: {2}" -f $key, $removed.Count, (($removed | Select-Object -First 5) -join '; '))
  }
  if ($modified.Count -gt 0) {
    Add-Finding 'info' 'files' 'modified' ("{0}: {1} file(s) changed size/mtime. Sample: {2}" -f $key, $modified.Count, (($modified | Select-Object -First 5) -join '; '))
  }
  if ($bv.fileCount -ne $av.fileCount) {
    Add-Finding 'info' 'files' 'count-changed' ("{0}: file count {1} -> {2}, total bytes {3} -> {4}" -f $key, $bv.fileCount, $av.fileCount, $bv.totalBytes, $av.totalBytes)
  }
}
foreach ($key in $bPaths.Keys) {
  if (-not $aPaths.ContainsKey($key)) { Add-Finding 'warn' 'path' 'not-in-after' "Path present in the before snapshot is absent from the after snapshot: $key" }
}

# ---------------------------------------------------------------- registry
$bReg = Index-By $b.registry 'psPath'
$aReg = Index-By $a.registry 'psPath'
foreach ($key in $aReg.Keys) {
  $av = $aReg[$key]
  if (-not $bReg.ContainsKey($key)) { continue }
  $bv = $bReg[$key]
  if ($bv.exists -and -not $av.exists) {
    $sev = 'warn'
    if ($av.reason -match 'service|uninstall') { $sev = 'error' }
    Add-Finding $sev 'registry' 'key-removed' ("Key existed before and is gone: {0} ({1})" -f $key, $av.reason)
    continue
  }
  if (-not $bv.exists -and $av.exists) {
    Add-Finding 'info' 'registry' 'key-created' ("Key did not exist before and was created: {0} ({1})" -f $key, $av.reason)
    continue
  }
  if (-not $av.exists) { continue }

  $bVals = @{}; if ($bv.values) { foreach ($p in $bv.values.PSObject.Properties) { $bVals[$p.Name] = [string]$p.Value } }
  $aVals = @{}; if ($av.values) { foreach ($p in $av.values.PSObject.Properties) { $aVals[$p.Name] = [string]$p.Value } }

  foreach ($n in $aVals.Keys) {
    if (-not $bVals.ContainsKey($n)) { Add-Finding 'info' 'registry' 'value-created' ("{0} :: {1} = {2}" -f $key, $n, $aVals[$n]) }
    elseif ($bVals[$n] -ne $aVals[$n]) { Add-Finding 'info' 'registry' 'value-changed' ("{0} :: {1}: '{2}' -> '{3}'" -f $key, $n, $bVals[$n], $aVals[$n]) }
  }
  foreach ($n in $bVals.Keys) {
    if (-not $aVals.ContainsKey($n)) {
      $sev = 'warn'
      if ($av.reason -match 'service|uninstall|eventlog') { $sev = 'error' }
      Add-Finding $sev 'registry' 'value-removed' ("{0} :: {1} (was '{2}')" -f $key, $n, $bVals[$n])
    }
  }
}

# ---------------------------------------------------------------- services
$bSvc = Index-By $b.services 'name'
$aSvc = Index-By $a.services 'name'
foreach ($key in $aSvc.Keys) {
  $av = $aSvc[$key]
  if (-not $bSvc.ContainsKey($key)) {
    if ($av.installed) { Add-Finding 'info' 'service' 'appeared' "Service now installed: $key" }
    continue
  }
  $bv = $bSvc[$key]
  if (-not $bv.installed -and $av.installed) { Add-Finding 'info' 'service' 'installed' "Service $key is now installed ($($av.state) / $($av.startMode))"; continue }
  if ($bv.installed -and -not $av.installed) { Add-Finding 'error' 'service' 'not-installed' "Service $key was installed before and is gone now"; continue }
  if (-not $av.installed) { continue }
  if ([string]$bv.state -ne [string]$av.state) {
    $sev = 'info'
    if ($av.state -eq 'Stopped' -and $bv.state -eq 'Running') { $sev = 'error' }
    Add-Finding $sev 'service' 'state-changed' "Service $key state: $($bv.state) -> $($av.state) (exit code $($av.exitCode))"
  }
  if ([string]$bv.startMode -ne [string]$av.startMode) {
    Add-Finding 'warn' 'service' 'start-mode-changed' "Service $key start mode: $($bv.startMode) -> $($av.startMode)"
  }
  if ([string]$bv.pathName -ne [string]$av.pathName) {
    Add-Finding 'warn' 'service' 'binary-changed' "Service $key image path: $($bv.pathName) -> $($av.pathName)"
  }
}
foreach ($key in $bSvc.Keys) {
  if (-not $aSvc.ContainsKey($key) -and $bSvc[$key].installed) { Add-Finding 'error' 'service' 'missing-from-after' "Installed service $key is absent from the after snapshot" }
}

# --------------------------------------------------------------- processes
$bProc = @{}; foreach ($x in $b.processes) { $bProc[[string]$x.name] = $true }
$aProc = @{}; foreach ($x in $a.processes) { $aProc[[string]$x.name] = $true }
foreach ($n in $aProc.Keys) { if (-not $bProc.ContainsKey($n)) { Add-Finding 'info' 'process' 'appeared' "Process appeared: $n" } }
foreach ($n in $bProc.Keys) {
  if (-not $aProc.ContainsKey($n)) {
    Add-Finding 'warn' 'process' 'exited' "Process $n was running before and is gone after. Confirm whether that was a normal exit or a crash (check WER and Event Log)."
  }
}

# ------------------------------------------------------------------- ports
$bPorts = @{}; foreach ($x in $b.ports) { $bPorts[("{0}:{1}/{2}" -f $x.localAddress, $x.localPort, $x.state)] = $true }
$aPorts = @{}; foreach ($x in $a.ports) { $aPorts[("{0}:{1}/{2}" -f $x.localAddress, $x.localPort, $x.state)] = $true }
foreach ($k in $aPorts.Keys) { if (-not $bPorts.ContainsKey($k)) { Add-Finding 'info' 'ports' 'opened' "Port binding appeared: $k" } }
foreach ($k in $bPorts.Keys) { if (-not $aPorts.ContainsKey($k)) { Add-Finding 'warn' 'ports' 'closed' "Port binding disappeared: $k" } }

# ------------------------------------------------------------------ events
# Localized LevelDisplayName values are matched without embedding non-ASCII
# literals, so this script stays ANSI-safe when PowerShell 5.1 reads it.
$rxLevelError = 'Error|Critical|' + [char]0x9519 + [char]0x8BEF
$rxLevelWarn = 'Warning|' + [char]0x8B66 + [char]0x544A

$bEventKeys = @{}
foreach ($e in $b.events) { $bEventKeys[("{0}|{1}|{2}" -f $e.log, $e.id, $e.timeCreated)] = $true }
foreach ($e in $a.events) {
  $k = "{0}|{1}|{2}" -f $e.log, $e.id, $e.timeCreated
  if ($bEventKeys.ContainsKey($k)) { continue }
  $sev = 'info'
  if ($e.level -match $rxLevelError) { $sev = 'error' }
  elseif ($e.level -match $rxLevelWarn) { $sev = 'warn' }
  $msg = [string]$e.message
  if ($msg.Length -gt 240) { $msg = $msg.Substring(0, 240) + '...' }
  Add-Finding $sev 'eventlog' 'new-event' ("{0} / {1} / ID {2} / {3}: {4}" -f $e.log, $e.source, $e.id, $e.level, $msg)
}

# --------------------------------------------------------------------- WER
$bWer = @{}; foreach ($w in $b.wer) { $bWer[[string]$w.folder] = $true }
foreach ($w in $a.wer) {
  if (-not $bWer.ContainsKey([string]$w.folder)) {
    Add-Finding 'error' 'wer' 'new-crash-report' ("New WER report folder: {0} ({1})" -f $w.folder, $w.path)
  }
}

# ------------------------------------------------------------------- output
$order = @{ 'error' = 0; 'warn' = 1; 'info' = 2 }
$sorted = @($findings | Sort-Object { $order[[string]$_.severity] })

$counts = [ordered]@{ error = 0; warn = 0; info = 0 }
foreach ($f in $sorted) { $counts[[string]$f.severity] = $counts[[string]$f.severity] + 1 }

$diff = [ordered]@{
  tool        = 'diff-snapshots'
  toolVersion = $ToolVersion
  generated   = (Get-Date).ToString('o')
  before      = [ordered]@{ path = (Resolve-Path -LiteralPath $Before).Path; generated = $b.generated; label = $b.label }
  after       = [ordered]@{ path = (Resolve-Path -LiteralPath $After).Path; generated = $a.generated; label = $a.label }
  product     = $a.product
  counts      = $counts
  findings    = $sorted
}

$jsonPath = Join-Path $OutDir 'findings.json'
$diff | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Runtime diff - $($a.product.name) $($a.product.version)")
[void]$md.AppendLine('')
[void]$md.AppendLine("Before: ``$($diff.before.path)`` ($($diff.before.generated))")
[void]$md.AppendLine("After:  ``$($diff.after.path)`` ($($diff.after.generated))")
[void]$md.AppendLine('')
[void]$md.AppendLine("Errors: $($counts.error)    Warnings: $($counts.warn)    Info: $($counts.info)")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Severity | Area | Change | Detail |')
[void]$md.AppendLine('|---|---|---|---|')
foreach ($f in $sorted) {
  $d = ([string]$f.detail).Replace('|', '\|')
  if ($d.Length -gt 300) { $d = $d.Substring(0, 300) + '...' }
  [void]$md.AppendLine("| $($f.severity) | $($f.area) | $($f.change) | $d |")
}
$mdPath = Join-Path $OutDir 'diff.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

[ordered]@{
  status   = 'ok'
  outDir   = $OutDir
  findings = $jsonPath
  summary  = $mdPath
  counts   = $counts
  top      = @($sorted | Select-Object -First 12)
} | ConvertTo-Json -Depth 8
