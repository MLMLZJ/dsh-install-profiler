<#
.SYNOPSIS
  Build a complete, detailed operations sheet from everything collected.

.DESCRIPTION
  Consumes the outputs of the other scripts (detect-installer, export-msi-tables,
  collect-state, build-probe-plan, mine-strings) and writes one exhaustive
  document for the person who has to fix the machine:

    - identity: product, version, installer type, signature, payload size
    - every known path with file counts and newest files
    - every uninstall entry with ALL of its registry values
    - every service with live state AND the full service registry key
    - drivers, scheduled tasks, startup entries
    - every observed log file, plus newest log-like files per directory
    - configuration files (paths by default; content only with -IncludeConfigContent)
    - Event Log sources with their EventMessageFile
    - mined registry candidates from binary strings
    - MSI registry rows (first N, with total count)
    - a fixed triage order with paste-ready commands

  Nothing is truncated silently: every section states how many items exist and
  how many are listed.

.PARAMETER State
  state.json from collect-state.ps1 (most of the value comes from here).

.PARAMETER Profile
  Optional profile.json from export-msi-tables.ps1 (MSI packages).

.PARAMETER Plan
  Optional probe-plan.json from build-probe-plan.ps1.

.PARAMETER Strings
  Optional strings-evidence.json from mine-strings.ps1.

.PARAMETER Detect
  Optional detect-installer JSON output (installer type, signature, version).

.PARAMETER OutDir
  Output directory. Default: .\ops

.PARAMETER IncludeConfigContent
  Also print the first 40 lines of each config file. Off by default because
  configs can contain tokens or personal data.

.PARAMETER MaxRows
  Cap for the MSI registry table section. Default 500.

.EXAMPLE
  ./build-ops-sheet.ps1 -State .\profile\state.json -Profile .\profile\profile.json -Detect .\evidence\detect.json -OutDir .\ops
#>
[CmdletBinding()]
param(
  [string]$State,
  [string]$Profile,
  [string]$Plan,
  [string]$Strings,
  [string]$Detect,
  [string]$OutDir = '.\ops',
  [switch]$IncludeConfigContent,
  [int]$MaxRows = 500
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Read-Json([string]$File) {
  if (-not $File) { return $null }
  if (-not (Test-Path -LiteralPath $File)) { return $null }
  try { return (Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
$st = Read-Json $State
$pf = Read-Json $Profile
$pl = Read-Json $Plan
$sx = Read-Json $Strings
$dt = Read-Json $Detect

if (-not $st -and -not $pf -and -not $pl) {
  [ordered]@{ tool = 'build-ops-sheet'; status = 'error'; message = 'Need at least one of -State, -Profile, -Plan.' } | ConvertTo-Json
  exit 2
}

function Quote([string]$Value) { return "'" + ($Value -replace "'", "''") + "'" }

function Get-RegValues([string]$PsPath) {
  $bag = [ordered]@{}
  try {
    if (-not (Test-Path -LiteralPath $PsPath)) { return $null }
    $item = Get-ItemProperty -LiteralPath $PsPath -ErrorAction Stop
    foreach ($p in $item.PSObject.Properties) {
      if ($p.Name -like 'PS*') { continue }
      $bag[$p.Name] = [string]$p.Value
    }
  }
  catch { return $null }
  return $bag
}

$md = New-Object System.Text.StringBuilder
$data = [ordered]@{}
function L([string]$Text) { [void]$md.AppendLine($Text) }

# ------------------------------------------------------------------ identity
$productName = $null
$productVersion = $null
if ($pl -and $pl.product) { $productName = $pl.product.name; $productVersion = $pl.product.version }
elseif ($pf -and $pf.product) { $productName = $pf.product.name; $productVersion = $pf.product.version }
elseif ($dt -and $dt.versionInfo) { $productName = $dt.versionInfo.product; $productVersion = $dt.versionInfo.fileVersion }

$installRoots = @()
if ($pl -and $pl.paths) { $installRoots = @($pl.paths | Where-Object { $_.role -eq 'install-root' } | ForEach-Object { [string]$_.real }) }
if ($st -and $st.directories) { foreach ($d in $st.directories) { if ($installRoots -notcontains [string]$d.path) { $installRoots += [string]$d.path } } }

$mainExe = $null
foreach ($root in $installRoots) {
  if (-not (Test-Path -LiteralPath $root)) { continue }
  $e = Get-ChildItem -LiteralPath $root -Filter *.exe -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
  if ($e) { $mainExe = $e; break }
}

L('# Ops sheet - ' + (([string]$productName).Trim() + ' ' + [string]$productVersion).Trim())
L ''
L ('Generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  |  host: ' + $env:COMPUTERNAME + '  |  powershell: ' + $PSVersionTable.PSVersion)
L ''
L '## 0. Identity'
L ''
L '| Item | Value |'
L '|---|---|'
L ('| Product | ' + $productName + ' |')
L ('| Version | ' + $productVersion + ' |')
if ($dt) {
  $best = $dt.candidates | Select-Object -First 1
  L ('| Installer type | ' + $best.type + ' (confidence ' + $best.confidence + ') |')
  L ('| Installer size | ' + [math]::Round([double]$dt.sizeBytes / 1MB, 1) + ' MB |')
  if ($dt.sha256) { L ('| SHA-256 | `' + $dt.sha256 + '` |') }
  $signerText = ''
  if ($dt.signature.signer) { $signerText = ' - ' + $dt.signature.signer }
  L ('| Signature | ' + $dt.signature.status + $signerText + ' |')
  if ($dt.versionInfo) { L ('| File version | ' + $dt.versionInfo.fileVersion + ' |') }
}
if ($st -and $st.environment) {
  L ('| OS | ' + $st.environment.caption + ' build ' + $st.environment.build + ' |')
  L ('| Uptime (h) | ' + $st.environment.uptimeHours + ' |')
  L ('| Free memory (MB) | ' + $st.environment.freeMemoryMB + ' |')
}
if ($st -and $st.pendingReboot) { L '| Pending reboot | **YES** - can block install/repair/uninstall |' }
L ''
if ($installRoots.Count -gt 0) {
  L '### Install locations'
  L ''
  L '| Path | Exists |'
  L '|---|---|'
  foreach ($r in $installRoots) { L ('| `' + $r + '` | ' + (Test-Path -LiteralPath $r) + ' |') }
  L ''
}
if ($mainExe) {
  L ('Main executable: `' + $mainExe.FullName + '` (' + [math]::Round($mainExe.Length / 1MB, 2) + ' MB, modified ' + $mainExe.LastWriteTime + ')')
  L ''
}

# -------------------------------------------------------------- uninstall
$uninstallData = @()
if ($st -and $st.uninstall) {
  L '## 1. Uninstall entries (full registry values)'
  L ''
  foreach ($u in $st.uninstall) {
    $key = [string]$u.hive
    if ($u.productCode) { $key = $key.TrimEnd('\') + '\' + [string]$u.productCode }
    $vals = Get-RegValues ($key -replace '^HKLM:', 'HKLM:' -replace '^HKCU:', 'HKCU:')
    # normalize to provider path
    $psKey = $key
    if ($psKey -notmatch '^HK(LM|CU):') { $psKey = 'HKLM:\' + $psKey.TrimStart('\') }
    $vals = Get-RegValues $psKey
    L ('### ' + $u.displayName + ' ' + $u.displayVersion)
    L ''
    L ('Registry key: `' + $psKey + '`')
    L ''
    if ($vals -and $vals.Count -gt 0) {
      L '| Value | Data |'
      L '|---|---|'
      foreach ($k in $vals.Keys) {
        $v = ([string]$vals[$k]).Replace('|', '\|')
        if ($v.Length -gt 300) { $v = $v.Substring(0, 300) + '...' }
        L ('| ' + $k + ' | ' + $v + ' |')
      }
    }
    else { L '_Key not readable (deleted or different view)._ ' }
    L ''
    $uninstallData += [pscustomobject][ordered]@{ displayName = $u.displayName; version = $u.displayVersion; key = $psKey; values = $vals }
  }
}

# --------------------------------------------------------------- services
$servicesData = @()
L '## 2. Services (live state + full registry key)'
L ''
if (-not ($st -and $st.services -and $st.services.Count -gt 0)) { L '_No services registered by this product._'; L '' }
if ($st -and $st.services) {
  foreach ($s in $st.services) {
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s.name
    $vals = Get-RegValues $svcKey
    L ('### ' + $s.name + ' (' + $s.displayName + ')')
    L ''
    L '| Property | Value |'
    L '|---|---|'
    L ('| State | ' + $s.state + ' |')
    L ('| Start mode | ' + $s.startMode + ' |')
    L ('| Account | ' + $s.startName + ' |')
    L ('| Binary path | `' + $s.pathName + '` |')
    L ('| Binary exists | ' + $s.binaryExists + ' |')
    L ('| Exit code | ' + $s.exitCode + ' |')
    L ''
    L ('Registry key: `' + $svcKey + '`')
    L ''
    if ($vals -and $vals.Count -gt 0) {
      L '| Value | Data |'
      L '|---|---|'
      foreach ($k in $vals.Keys) {
        $v = ([string]$vals[$k]).Replace('|', '\|')
        if ($v.Length -gt 300) { $v = $v.Substring(0, 300) + '...' }
        L ('| ' + $k + ' | ' + $v + ' |')
      }
      L ''
    }
    $failKey = $svcKey + '\FailureActions'
    if (Test-Path -LiteralPath $failKey) {
      L 'Failure actions (raw): `' + ((Get-ItemProperty -LiteralPath $failKey -ErrorAction SilentlyContinue).FailureActions -join ',') + '`'
      L ''
    }
    $servicesData += [pscustomobject][ordered]@{ name = $s.name; state = $s.state; startMode = $s.startMode; account = $s.startName; pathName = $s.pathName; values = $vals }
  }
}

# ---------------------------------------------------------------- drivers
L '## 3. Drivers'
L ''
if (-not ($st -and $st.drivers -and $st.drivers.Count -gt 0)) { L '_No drivers registered by this product._'; L '' }
if ($st -and $st.drivers -and $st.drivers.Count -gt 0) {
  L '| Name | Display | State | Start | Binary |'
  L '|---|---|---|---|---|'
  foreach ($d in $st.drivers) { L ('| ' + $d.name + ' | ' + $d.displayName + ' | ' + $d.state + ' | ' + $d.startMode + ' | `' + $d.pathName + '` |') }
  L ''
}

# ------------------------------------------------------------------ tasks
L '## 4. Scheduled tasks'
L ''
if (-not ($st -and $st.tasks -and $st.tasks.Count -gt 0)) { L '_No scheduled tasks matched this product._'; L '' }
if ($st -and $st.tasks -and $st.tasks.Count -gt 0) {
  L '| Task | State | Runs as | Actions |'
  L '|---|---|---|---|'
  foreach ($t in $st.tasks) { L ('| ' + $t.taskPath + $t.taskName + ' | ' + $t.state + ' | ' + $t.principal + ' | ' + $t.actions + ' |') }
  L ''
}

# --------------------------------------------------------------- startup
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
L '## 5. Startup entries (all Run/RunOnce values)'
L ''
$appRx = if ($installRoots.Count -gt 0) { '(?i)(' + (($installRoots | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')' } else { $null }
$nameRx = if ($productName) { '(?i)' + [regex]::Escape([string]$productName) } else { $null }
$suspectRx = '(?i)^([A-Za-z]:\\ProgramData\\Microsoft\\Windows\\Caches\\|%?TEMP%?\\|.*\\AppData\\Local\\Temp\\)'
$runRows = @()
foreach ($rk in $runKeys) {
  $vals = Get-RegValues $rk
  if (-not $vals) { continue }
  foreach ($k in $vals.Keys) {
    $cmd = [string]$vals[$k]
    $isApp = $false
    if ($appRx -and $cmd -match $appRx) { $isApp = $true }
    if ($nameRx -and ($k -match $nameRx -or $cmd -match $nameRx)) { $isApp = $true }
    $isSuspect = ($cmd -match $suspectRx)
    $runRows += [pscustomobject][ordered]@{ key = $rk; name = $k; command = $cmd; app = $isApp; suspect = $isSuspect }
  }
}
$appRows = @($runRows | Where-Object { $_.app })
$otherRows = @($runRows | Where-Object { -not $_.app })
L ('App-related entries: ' + $appRows.Count + ' (out of ' + $runRows.Count + ' total)')
L ''
if ($appRows.Count -gt 0) {
  L '| Key | Name | Command |'
  L '|---|---|---|'
  foreach ($r in $appRows) { L ('| `' + $r.key + '` | ' + $r.name + ' | `' + $r.command + '` |') }
}
else { L '_No autostart entry points at this product._' }
L ''
L 'Other autostart entries on this host (context only, not this product):'
L ''
L '| Key | Name | Command | Flag |'
L '|---|---|---|---|'
foreach ($r in $otherRows) {
  $flag = if ($r.suspect) { '**unusual path - verify**' } else { '' }
  $cmd = ([string]$r.command).Replace('|', '\|')
  L ('| `' + $r.key + '` | ' + $r.name + ' | `' + $cmd + '` | ' + $flag + ' |')
}
$runCount = $runRows.Count
L ''

# ------------------------------------------------------------------ logs
L '## 6. Log files'
L ''
if ($st -and $st.logFiles -and $st.logFiles.Count -gt 0) {
  L ('Observed log-like files: ' + $st.logFiles.Count)
  L ''
  L '| Size (KB) | Last write | Path |'
  L '|---|---|---|'
  foreach ($l in $st.logFiles) { L ('| ' + $l.sizeKB + ' | ' + $l.lastWrite + ' | `' + $l.path + '` |') }
  L ''
}
if ($st -and $st.directories) {
  L 'Newest files per watched directory (top 8):'
  L ''
  foreach ($d in $st.directories) {
    $p = [string]$d.path
    if (-not (Test-Path -LiteralPath $p)) { continue }
    L ('### `' + $p + '`')
    L ''
    $files = @(Get-ChildItem -LiteralPath $p -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 8)
    if ($files.Count -eq 0) { L '_empty or unreadable_'; L ''; continue }
    L '| Size (KB) | Last write | Name |'
    L '|---|---|---|'
    foreach ($f in $files) { L ('| ' + [math]::Round($f.Length / 1KB, 1) + ' | ' + $f.LastWriteTime + ' | `' + $f.FullName + '` |') }
    L ''
  }
}

# ---------------------------------------------------------------- configs
L '## 7. Configuration files'
L ''
$configCandidates = @()
if ($pl -and $pl.configFiles) { $configCandidates += @($pl.configFiles) }
foreach ($d in @($installRoots)) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  $configCandidates += @(Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -match '(?i)^\.(ini|json|xml|config|cfg|conf|yaml|yml|properties|toml)$' } |
      Select-Object -First 30 | ForEach-Object { $_.FullName })
}
$configCandidates = @($configCandidates | Select-Object -Unique)
if ($configCandidates.Count -eq 0) { L '_No config files found._'; L '' }
else {
  L '| Size (KB) | Last write | Path |'
  L '|---|---|---|'
  foreach ($c in $configCandidates) {
    $f = Get-Item -LiteralPath $c -ErrorAction SilentlyContinue
    if (-not $f) { continue }
    L ('| ' + [math]::Round($f.Length / 1KB, 1) + ' | ' + $f.LastWriteTime + ' | `' + $f.FullName + '` |')
  }
  L ''
  if ($IncludeConfigContent) {
    foreach ($c in $configCandidates) {
      L ('### `' + $c + '`')
      L ''
      L '```'
      Get-Content -LiteralPath $c -TotalCount 40 -ErrorAction SilentlyContinue | ForEach-Object { L $_ }
      L '```'
      L ''
    }
  }
  else {
    L '_Content not printed. Re-run with -IncludeConfigContent to include the first 40 lines of each (configs may contain tokens or personal data)._ '
    L ''
  }
}

# ------------------------------------------------------------ event sources
if ($st -and $st.eventSources -and $st.eventSources.Count -gt 0) {
  L '## 8. Event Log sources'
  L ''
  L '| Log | Source | EventMessageFile | TypesSupported |'
  L '|---|---|---|---|'
  foreach ($e in $st.eventSources) { L ('| ' + $e.log + ' | ' + $e.source + ' | `' + $e.eventMessageFile + '` | ' + $e.typesSupported + ' |') }
  L ''
}

# --------------------------------------------------------- mined registry
if ($sx -and $sx.evidence -and $sx.evidence.registry -and $sx.evidence.registry.Count -gt 0) {
  L '## 9. Registry paths mined from the binary (candidates, not confirmed)'
  L ''
  foreach ($r in $sx.evidence.registry) { L ('- `' + $r + '`') }
  L ''
}

# ------------------------------------------------------------- MSI registry
if ($pf -and $pf.registry -and $pf.registry.Count -gt 0) {
  $total = @($pf.registry).Count
  $shown = @($pf.registry | Select-Object -First $MaxRows)
  L '## 10. MSI Registry table (' + $shown.Count + ' of ' + $total + ' rows shown)'
  L ''
  L '| Hive | Key | Name | Value |'
  L '|---|---|---|---|'
  foreach ($r in $shown) {
    $k = ([string]$r.key).Replace('|', '\|')
    $n = ([string]$r.name).Replace('|', '\|')
    $v = ([string]$r.value).Replace('|', '\|')
    if ($v.Length -gt 200) { $v = $v.Substring(0, 200) + '...' }
    L ('| ' + $r.root + ' | `' + $k + '` | ' + $n + ' | ' + $v + ' |')
  }
  L ''
  L ('Full table: see the exported CSV `tables\Registry.csv` from export-msi-tables.ps1.')
  L ''
}

# ------------------------------------------------------------------ triage
L '## 11. Triage order (do it in this order, paste-ready)'
L ''
L '```powershell'
L '# 1. install layout'
foreach ($r in @($installRoots | Select-Object -First 3)) {
  L ('Test-Path -LiteralPath ' + (Quote $r))
  L ('Get-ChildItem -LiteralPath ' + (Quote $r) + ' | Select-Object Name,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 15')
}
L ''
L '# 2. process'
foreach ($p in @($pl.processes | Select-Object -First 5)) { L ('Get-Process -Name ' + (Quote ([string]$p)) + ' -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,StartTime,Responding,WorkingSet64') }
L ''
L '# 3. newest log lines'
foreach ($l in @($st.logFiles | Select-Object -First 3)) { L ('Get-Content -LiteralPath ' + (Quote ([string]$l.path)) + ' -Tail 40 -ErrorAction SilentlyContinue') }
L ''
L '# 4. crash / service events, last 24 h'
L 'Get-WinEvent -FilterHashtable @{LogName=''Application''; StartTime=(Get-Date).AddHours(-24); Id=1000,1001,1002} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | Format-List'
L 'Get-WinEvent -FilterHashtable @{LogName=''System''; StartTime=(Get-Date).AddHours(-24); Id=7000,7001,7009,7031,7034} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | Format-List'
L ''
if ($st -and $st.services) {
  L '# 5. services'
  foreach ($s in $st.services) { L ('sc.exe qc ' + (Quote $s.name)); L ('sc.exe queryex ' + (Quote $s.name)) }
  L ''
}
L '# 6. startup entries'
L 'Get-ItemProperty ''HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'', ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'' -ErrorAction SilentlyContinue'
L ''
L '# 7. uninstall entry'
foreach ($u in @($st.uninstall | Select-Object -First 3)) {
  $k = 'HKLM:\' + ([string]$u.hive).TrimStart('\')
  L ('Get-ItemProperty ' + (Quote $k) + ' -ErrorAction SilentlyContinue')
}
L ''
L '# 8. before/after capture (if a plan exists)'
if ($pl) {
  L ('capture-snapshot.ps1 -Plan ' + (Quote (Join-Path $OutDir '..\plan\probe-plan.json')) + ' -Label before')
  L ('capture-snapshot.ps1 -Plan ' + (Quote (Join-Path $OutDir '..\plan\probe-plan.json')) + ' -Label after -SinceMinutes 10')
  L 'diff-snapshots.ps1 -Before .\probe-snapshots\before.json -After .\probe-snapshots\after.json'
}
L '```'
L ''
L '## 12. Evidence index'
L ''
foreach ($pair in @(@('state', $State), @('profile', $Profile), @('plan', $Plan), @('strings', $Strings), @('detect', $Detect))) {
  if ($pair[1]) { L ('- ' + $pair[0] + ': `' + (Resolve-Path -LiteralPath $pair[1]).Path + '`') }
}

$sheetPath = Join-Path $OutDir 'ops-sheet.md'
$md.ToString() | Set-Content -LiteralPath $sheetPath -Encoding UTF8

$jsonPath = Join-Path $OutDir 'ops-sheet.json'
[ordered]@{
  tool = 'build-ops-sheet'; toolVersion = $ToolVersion; generated = (Get-Date).ToString('o')
  product = [ordered]@{ name = $productName; version = $productVersion }
  installRoots = $installRoots
  mainExe = if ($mainExe) { $mainExe.FullName } else { $null }
  uninstall = $uninstallData
  services = $servicesData
  logFiles = if ($st) { $st.logFiles } else { @() }
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

[ordered]@{
  status = 'ok'; sheet = $sheetPath; json = $jsonPath; product = (([string]$productName).Trim() + ' ' + [string]$productVersion).Trim()
  counts = [ordered]@{
    installRoots = $installRoots.Count
    uninstall = if ($st) { @($st.uninstall).Count } else { 0 }
    services = if ($st) { @($st.services).Count } else { 0 }
    drivers = if ($st) { @($st.drivers).Count } else { 0 }
    tasks = if ($st) { @($st.tasks).Count } else { 0 }
    logFiles = if ($st) { @($st.logFiles).Count } else { 0 }
    configFiles = $configCandidates.Count
    runEntries = $runCount
    msiRegistryRows = if ($pf) { @($pf.registry).Count } else { 0 }
  }
} | ConvertTo-Json -Depth 6
