<#
.SYNOPSIS
  Sample a running process over time to prove or disprove a CPU / thread /
  handle leak, and point at the offending threads.

.DESCRIPTION
  Long-running resource bugs ("after a few hours CPU is at 30%", "thread count
  only goes up") are invisible in a single snapshot. This script samples the
  process at a fixed interval and reports:

    - CPU percent per interval (delta of TotalProcessorTime / elapsed / cores)
    - thread count, handle count, working set, private bytes over time
    - monotonic growth detection (thread leak / handle leak suspicion)
    - the top threads by CPU time in the last interval, with state and
      wait reason (a spinning thread shows Running/0% wait; a blocked pool
      shows Waiting with a specific reason)

  Read-only: uses only Get-Process / ProcessThread counters. No injection, no
  debugger attach, no dump.

.PARAMETER Name
  Process name (without .exe). All processes with that name are sampled.

.PARAMETER Id
  Process id. Takes precedence over -Name.

.PARAMETER Samples
  Number of samples. Default 12.

.PARAMETER IntervalSeconds
  Seconds between samples. Default 5.

.PARAMETER OutDir
  Output directory. Default: .\resource-watch

.PARAMETER TopThreads
  How many threads to list per sample in the report. Default 5.

.EXAMPLE
  ./watch-process.ps1 -Name 'YoudaoDict' -Samples 24 -IntervalSeconds 10

.EXAMPLE
  ./watch-process.ps1 -Id 12345 -Samples 6 -IntervalSeconds 30
#>
[CmdletBinding()]
param(
  [string]$Name,
  [int]$Id = 0,
  [int]$Samples = 12,
  [int]$IntervalSeconds = 5,
  [string]$OutDir = '.\resource-watch',
  [int]$TopThreads = 5
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'

function Get-Target {
  if ($Id -gt 0) { return @(Get-Process -Id $Id -ErrorAction SilentlyContinue) }
  if (-not $Name) { return @() }
  return @(Get-Process -Name $Name -ErrorAction SilentlyContinue)
}

$initial = Get-Target
if ($initial.Count -eq 0) {
  [ordered]@{ tool = 'watch-process'; status = 'error'; message = ('Process not running: ' + $(if ($Id) { "id $Id" } else { $Name })) } | ConvertTo-Json
  exit 2
}

$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$cores = [Environment]::ProcessorCount

$sampleRows = New-Object System.Collections.Generic.List[object]
$prevCpu = @{}
$prevThreads = @{}
$prevAt = $null

for ($i = 1; $i -le $Samples; $i++) {
  $procs = Get-Target
  $now = Get-Date
  if ($procs.Count -eq 0) {
    $sampleRows.Add([pscustomobject][ordered]@{ n = $i; time = $now.ToString('HH:mm:ss'); process = 'EXITED'; cpuTotalSec = $null; cpuPercent = $null; threads = $null; handles = $null; workingSetMB = $null; privateMB = $null; responding = $null })
    break
  }
  $p = $procs | Sort-Object -Property @{ Expression = { $_.TotalProcessorTime.TotalSeconds } } -Descending | Select-Object -First 1
  $cpuTotal = $p.TotalProcessorTime.TotalSeconds
  $cpuPct = $null
  if ($prevCpu.ContainsKey($p.Id) -and $prevAt) {
    $elapsed = ($now - $prevAt).TotalSeconds
    if ($elapsed -gt 0) { $cpuPct = [math]::Round((($cpuTotal - $prevCpu[$p.Id]) / $elapsed / $cores) * 100, 1) }
  }
  $threadList = @()
  try {
    $threadList = @($p.Threads | ForEach-Object {
        $cpu = $null
        try { $cpu = $_.TotalProcessorTime.TotalSeconds } catch { }
        [pscustomobject][ordered]@{
          id = $_.Id; state = [string]$_.ThreadState; waitReason = [string]$_.WaitReason; cpuSec = $cpu
        }
      })
  }
  catch { }
  $top = @($threadList | Where-Object { $null -ne $_.cpuSec } | Sort-Object { $_.cpuSec } -Descending | Select-Object -First $TopThreads)
  $threadDeltas = @()
  if ($prevThreads.ContainsKey($p.Id)) {
    $prevMap = $prevThreads[$p.Id]
    $threadDeltas = @($threadList | Where-Object { $null -ne $_.cpuSec -and $prevMap.ContainsKey($_.id) } | ForEach-Object {
        [pscustomobject][ordered]@{ id = $_.id; state = $_.state; waitReason = $_.waitReason; deltaSec = [math]::Round($_.cpuSec - $prevMap[$_.id], 3) }
      } | Sort-Object { $_.deltaSec } -Descending | Select-Object -First $TopThreads)
  }
  $sample = [pscustomobject][ordered]@{
    n = $i; time = $now.ToString('HH:mm:ss'); process = $p.ProcessName; pid = $p.Id
    cpuTotalSec = [math]::Round($cpuTotal, 1); cpuPercent = $cpuPct
    threads = $p.Threads.Count; handles = $p.HandleCount
    workingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1); privateMB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
    responding = $p.Responding
    topThreads = $top
    topThreadCpuDelta = $threadDeltas
  }
  $sampleRows.Add($sample)
  $prevCpu[$p.Id] = $cpuTotal
  $map = @{}
  foreach ($t in $threadList) { if ($null -ne $t.cpuSec) { $map[$t.id] = $t.cpuSec } }
  $prevThreads[$p.Id] = $map
  $prevAt = $now
  if ($i -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
}

$rows = @($sampleRows | Where-Object { $_.process -ne 'EXITED' })
$exited = @($sampleRows | Where-Object { $_.process -eq 'EXITED' })

# ------------------------------------------------------------- leak analysis
$analysis = [ordered]@{}
if ($rows.Count -ge 2) {
  $first = $rows[0]; $last = $rows[-1]
  $minutes = ((Get-Date $last.time) - (Get-Date $first.time)).TotalMinutes
  if ($minutes -le 0) { $minutes = 0.01 }
  $analysis.threadStart = $first.threads
  $analysis.threadEnd = $last.threads
  $analysis.threadDelta = $last.threads - $first.threads
  $analysis.threadPerMinute = [math]::Round(($last.threads - $first.threads) / $minutes, 2)
  $analysis.handleStart = $first.handles
  $analysis.handleEnd = $last.handles
  $analysis.handleDelta = $last.handles - $first.handles
  $analysis.privateStartMB = $first.privateMB
  $analysis.privateEndMB = $last.privateMB
  $analysis.memoryDeltaMB = [math]::Round($last.privateMB - $first.privateMB, 1)
  $cpuValues = @($rows | Where-Object { $null -ne $_.cpuPercent } | ForEach-Object { [double]$_.cpuPercent })
  $analysis.cpuAvg = if ($cpuValues.Count -gt 0) { [math]::Round(($cpuValues | Measure-Object -Average).Average, 1) } else { $null }
  $analysis.cpuMax = if ($cpuValues.Count -gt 0) { [math]::Round(($cpuValues | Measure-Object -Maximum).Maximum, 1) } else { $null }

  $monotonicThreads = $true
  for ($j = 1; $j -lt $rows.Count; $j++) { if ($rows[$j].threads -lt $rows[$j - 1].threads) { $monotonicThreads = $false; break } }
  $analysis.threadsMonotonic = $monotonicThreads

  $flags = @()
  if ($analysis.threadDelta -ge 5) { $flags += ('thread count grew by ' + $analysis.threadDelta + ' (' + $analysis.threadPerMinute + '/min)') }
  if ($monotonicThreads -and $analysis.threadDelta -ge 3) { $flags += 'thread growth is monotonic - classic thread leak shape' }
  if ($analysis.handleDelta -ge 100) { $flags += ('handle count grew by ' + $analysis.handleDelta) }
  if ($analysis.memoryDeltaMB -ge 100) { $flags += ('private bytes grew by ' + $analysis.memoryDeltaMB + ' MB') }
  if ($null -ne $analysis.cpuAvg -and $analysis.cpuAvg -ge ($cores * 15)) { $flags += ('average CPU ' + $analysis.cpuAvg + '% across ' + $cores + ' cores') }
  $analysis.flags = $flags
}
if ($exited.Count -gt 0) { $analysis.exited = $true }

# ------------------------------------------------------------------ output
$result = [ordered]@{
  tool = 'watch-process'; toolVersion = $ToolVersion; generated = (Get-Date).ToString('o')
  target = [ordered]@{ name = $Name; id = $Id; cores = $cores; samples = $rows.Count; intervalSeconds = $IntervalSeconds }
  analysis = $analysis
  samples = $rows
}
$jsonPath = Join-Path $OutDir 'resource-watch.json'
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Resource watch - ' + $(if ($Name) { $Name } else { "pid $Id" }))
[void]$md.AppendLine('')
[void]$md.AppendLine('Generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  |  cores: ' + $cores + '  |  interval: ' + $IntervalSeconds + 's  |  samples: ' + $rows.Count)
[void]$md.AppendLine('')
[void]$md.AppendLine('## Time series')
[void]$md.AppendLine('')
[void]$md.AppendLine('| # | time | CPU % | CPU total (s) | threads | handles | private (MB) | working set (MB) | responding |')
[void]$md.AppendLine('|---|---|---|---|---|---|---|---|---|')
foreach ($r in $rows) {
  [void]$md.AppendLine('| ' + $r.n + ' | ' + $r.time + ' | ' + $r.cpuPercent + ' | ' + $r.cpuTotalSec + ' | ' + $r.threads + ' | ' + $r.handles + ' | ' + $r.privateMB + ' | ' + $r.workingSetMB + ' | ' + $r.responding + ' |')
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## Verdict')
[void]$md.AppendLine('')
if ($analysis.Count -eq 0) { [void]$md.AppendLine('_Not enough samples to analyse._') }
else {
  [void]$md.AppendLine('- threads: ' + $analysis.threadStart + ' -> ' + $analysis.threadEnd + ' (delta ' + $analysis.threadDelta + ', ' + $analysis.threadPerMinute + '/min)')
  [void]$md.AppendLine('- handles: ' + $analysis.handleStart + ' -> ' + $analysis.handleEnd + ' (delta ' + $analysis.handleDelta + ')')
  [void]$md.AppendLine('- private bytes: ' + $analysis.privateStartMB + ' -> ' + $analysis.privateEndMB + ' MB (delta ' + $analysis.memoryDeltaMB + ' MB)')
  [void]$md.AppendLine('- CPU: avg ' + $analysis.cpuAvg + '%, max ' + $analysis.cpuMax + '%')
  [void]$md.AppendLine('- thread growth monotonic: ' + $analysis.threadsMonotonic)
  [void]$md.AppendLine('')
  if ($analysis.flags.Count -gt 0) {
    [void]$md.AppendLine('**Flags**')
    [void]$md.AppendLine('')
    foreach ($f in $analysis.flags) { [void]$md.AppendLine('- ' + $f) }
  }
  else { [void]$md.AppendLine('_No leak flag crossed the thresholds in this window. Longer sampling may be needed._') }
}
[void]$md.AppendLine('')
$lastRow = $rows | Select-Object -Last 1
if ($lastRow -and $lastRow.topThreadCpuDelta.Count -gt 0) {
  [void]$md.AppendLine('## Threads that consumed CPU in the last interval')
  [void]$md.AppendLine('')
  [void]$md.AppendLine('| Thread ID | CPU delta (s) | State | Wait reason |')
  [void]$md.AppendLine('|---|---|---|---|')
  foreach ($t in $lastRow.topThreadCpuDelta) { [void]$md.AppendLine('| ' + $t.id + ' | ' + $t.deltaSec + ' | ' + $t.state + ' | ' + $t.waitReason + ' |') }
  [void]$md.AppendLine('')
} 
$mdPath = Join-Path $OutDir 'resource-watch.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

[ordered]@{
  status = 'ok'; outDir = $OutDir; json = $jsonPath; report = $mdPath
  samples = $rows.Count
  analysis = $analysis
} | ConvertTo-Json -Depth 6
