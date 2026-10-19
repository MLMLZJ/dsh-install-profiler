<#
.SYNOPSIS
  Turn a static installation profile into a concrete dynamic-observation plan.

.DESCRIPTION
  Static analysis answers "what should happen". Dynamic analysis answers "what
  actually happens". This script derives the second from the first: it reads a
  profile.json produced by export-msi-tables.ps1 (and optionally a state.json
  from collect-state.ps1) and emits a plan that names exactly what to watch:

    - real install paths resolved from logical MSI directories
    - registry keys to snapshot before/after (ARP, services, EventLog, Run, COM)
    - services to query with their expected start type and account
    - process names, candidate config files and log locations
    - Event Log providers/IDs worth querying
    - Procmon filter expressions
    - explicit checks with commands and pass/fail expectations
    - a before -> reproduce -> after capture sequence

  Nothing is executed here. The plan is consumed by capture-snapshot.ps1 and
  diff-snapshots.ps1.

.PARAMETER Profile
  profile.json written by export-msi-tables.ps1.

.PARAMETER State
  Optional state.json written by collect-state.ps1; enriches log and event data.

.PARAMETER OutDir
  Output directory. Default: .\probe-plan

.EXAMPLE
  ./build-probe-plan.ps1 -Profile .\re\case\profile\profile.json -State .\re\case\profile\state.json
#>
[CmdletBinding()]
param(
  [string]$Profile,
  [string]$State,
  [string]$Strings,
  [string]$AppDir,
  [string]$OutDir = '.\probe-plan'
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.1.0'

$OutDir = [IO.Path]::GetFullPath($OutDir)

function Read-JsonFile([string]$File) {
  if (-not $File) { return $null }
  if (-not (Test-Path -LiteralPath $File)) { return $null }
  try { return (Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

$pf = Read-JsonFile $Profile
$st = Read-JsonFile $State
$str = Read-JsonFile $Strings
$appRoot = $null
if ($AppDir -and (Test-Path -LiteralPath $AppDir)) { $appRoot = (Resolve-Path -LiteralPath $AppDir).Path }

$inputWarnings = New-Object System.Collections.Generic.List[string]
if ($Profile -and -not $pf) { $inputWarnings.Add("Profile not readable: $Profile") }
if ($State -and -not $st) { $inputWarnings.Add("State not readable: $State") }
if ($Strings -and -not $str) { $inputWarnings.Add("Strings evidence not readable: $Strings") }
if ($AppDir -and -not $appRoot) { $inputWarnings.Add("AppDir not found: $AppDir") }

if ($null -eq $pf -and $null -eq $st -and $null -eq $str -and -not $appRoot) {
  [ordered]@{
    tool = 'build-probe-plan'; status = 'error'
    message = 'Nothing to plan from: pass at least one of -Profile, -State, -Strings or -AppDir. -AppDir covers portable / PyInstaller / Electron apps that have no MSI.'
  } | ConvertTo-Json
  exit 2
}

# ------------------------------------------------------------ folder mapping
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$arch = if ($pf -and $pf.product) { [string]$pf.product.architecture } else { 'x64' }
$is64Os = [Environment]::Is64BitOperatingSystem
$x86Base = if ($is64Os -and ${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles }
$programFiles = if ($arch -eq 'x86' -and $is64Os) { $x86Base } else { $env:ProgramFiles }
$commonFiles = if ($arch -eq 'x86' -and $is64Os -and ${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles }

$rootMap = @{
  'ProgramFilesFolder'    = $programFiles
  'ProgramFiles64Folder'  = $env:ProgramFiles
  'CommonFilesFolder'     = $commonFiles
  'CommonFiles64Folder'   = $env:CommonProgramFiles
  'WindowsFolder'         = $env:windir
  'SystemFolder'          = (Join-Path $env:windir 'System32')
  'System64Folder'        = (Join-Path $env:windir 'System32')
  'FontsFolder'           = (Join-Path $env:windir 'Fonts')
  'AppDataFolder'         = $env:APPDATA
  'LocalAppDataFolder'    = $env:LOCALAPPDATA
  'CommonAppDataFolder'   = $env:ProgramData
  'DesktopFolder'         = [Environment]::GetFolderPath('Desktop')
  'ProgramMenuFolder'     = [Environment]::GetFolderPath('Programs')
  'StartupFolder'         = [Environment]::GetFolderPath('Startup')
  'SendToFolder'          = [Environment]::GetFolderPath('SendTo')
  'FavoritesFolder'       = [Environment]::GetFolderPath('Favorites')
  'PersonalFolder'        = [Environment]::GetFolderPath('MyDocuments')
  'TemplatesFolder'       = [Environment]::GetFolderPath('Templates')
  'TempFolder'            = $env:TEMP
  'WindowsVolume'         = ([IO.Path]::GetPathRoot($env:windir)).TrimEnd('\')
}

$dirsById = @{}
if ($pf.installPaths) { foreach ($d in $pf.installPaths) { $dirsById[[string]$d.id] = $d } }

function Get-RootId([string]$id) {
  $cur = $dirsById[$id]
  $guard = 0
  while ($null -ne $cur -and $guard -lt 60) {
    $parent = [string]$cur.parent
    if ([string]::IsNullOrEmpty($parent) -or $parent -eq 'TARGETDIR') { break }
    $next = $dirsById[$parent]
    if ($null -eq $next) { break }
    $cur = $next
    $guard++
  }
  if ($null -eq $cur) { return $null }
  $rid = [string]$cur.id
  $rid = $rid.Split('.')[0]
  if (-not $rootMap.ContainsKey($rid)) {
    foreach ($k in $rootMap.Keys) {
      if ($rid -like ($k + '*')) { $rid = $k; break }
    }
  }
  return $rid
}

function Resolve-RealPath([string]$dirId) {
  $d = $dirsById[$dirId]
  if ($null -eq $d) { return $null }
  $logical = [string]$d.path
  if ([string]::IsNullOrEmpty($logical)) { return $null }
  $rootId = Get-RootId $dirId
  if ($null -eq $rootId -or -not $rootMap.ContainsKey($rootId)) {
    return [pscustomobject][ordered]@{ real = $logical; mapped = $false; rootId = $rootId }
  }
  $realRoot = $rootMap[$rootId]
  $idx = $logical.IndexOf('\')
  $rest = if ($idx -ge 0) { $logical.Substring($idx + 1) } else { '' }
  $real = if ($rest) { Join-Path $realRoot $rest } else { $realRoot }
  return [pscustomobject][ordered]@{ real = $real; mapped = $true; rootId = $rootId }
}

# ------------------------------------------------------------ install targets
$pathTargets = New-Object System.Collections.Generic.List[object]
$seenReal = @{}
if ($pf.installPaths) {
  foreach ($d in $pf.installPaths) {
    $id = [string]$d.id
    $parent = [string]$d.parent
    if ($parent -ne 'TARGETDIR') { continue }
    $r = Resolve-RealPath $id
    if ($null -eq $r) { continue }
    if ($seenReal.ContainsKey($r.real)) { continue }
    $seenReal[$r.real] = $true
    $exists = Test-Path -LiteralPath $r.real
    $pathTargets.Add([pscustomobject][ordered]@{
        dirId    = $id
        logical  = [string]$d.path
        real     = $r.real
        mapped   = $r.mapped
        exists   = $exists
        role     = 'install-root'
        reason   = "Directory table root $id"
      })
  }
}

# specific directories that hold config/log data, even when nested deeper
if ($pf.installPaths) {
  foreach ($d in $pf.installPaths) {
    $id = [string]$d.id
    $logical = [string]$d.path
    if ([string]::IsNullOrEmpty($logical)) { continue }
    if ($logical -notmatch '(?i)(log|data|config|cache|temp|user)') { continue }
    $r = Resolve-RealPath $id
    if ($null -eq $r) { continue }
    if ($seenReal.ContainsKey($r.real)) { continue }
    $seenReal[$r.real] = $true
    $pathTargets.Add([pscustomobject][ordered]@{
        dirId   = $id
        logical = $logical
        real    = $r.real
        mapped  = $r.mapped
        exists  = (Test-Path -LiteralPath $r.real)
        role    = 'data-or-log'
        reason  = 'Directory name suggests config/log/data storage'
      })
  }
}

# ------------------------------------------- application directory (non-MSI)
if ($appRoot) {
  if (-not $seenReal.ContainsKey($appRoot)) {
    $seenReal[$appRoot] = $true
    $pathTargets.Add([pscustomobject][ordered]@{
        dirId = 'APPROOT'; logical = $appRoot; real = $appRoot; mapped = $true
        exists = $true; role = 'install-root'; reason = 'application directory supplied with -AppDir'
      })
  }
  foreach ($d in (Get-ChildItem -LiteralPath $appRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 40)) {
    if ($d.Name -notmatch '(?i)(log|data|config|cache|temp|user|rules|kb|tools|source|internal)') { continue }
    if ($seenReal.ContainsKey($d.FullName)) { continue }
    $seenReal[$d.FullName] = $true
    $pathTargets.Add([pscustomobject][ordered]@{
        dirId = $d.Name; logical = $d.FullName; real = $d.FullName; mapped = $true
        exists = $true; role = 'data-or-log'; reason = 'subdirectory name suggests config/log/data storage'
      })
  }
}
if ($st -and $st.directories) {
  foreach ($d in $st.directories) {
    $rp = [string]$d.path
    if (-not $rp -or $seenReal.ContainsKey($rp)) { continue }
    $seenReal[$rp] = $true
    $pathTargets.Add([pscustomobject][ordered]@{
        dirId = $null; logical = $rp; real = $rp; mapped = $true
        exists = [bool]$d.exists; role = 'data-or-log'; reason = 'directory observed by collect-state'
      })
  }
}

# --------------------------------------------------------------- services
$serviceTargets = New-Object System.Collections.Generic.List[object]
if ($pf.services) {
  foreach ($s in $pf.services) {
    $svcName = [string]$s.name
    $live = $null
    if ($svcName) {
      $live = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + ($svcName -replace "'", "''") + "'") -ErrorAction SilentlyContinue
    }
    $serviceTargets.Add([pscustomobject][ordered]@{
        name             = $svcName
        displayName      = [string]$s.displayName
        expectedStart    = [string]$s.startTypeName
        expectedStartRaw = [string]$s.startType
        expectedAccount  = [string]$s.startName
        binaryPath       = [string]$s.binaryPath
        installed        = [bool]$live
        currentState     = if ($live) { [string]$live.State } else { $null }
        currentStartMode = if ($live) { [string]$live.StartMode } else { $null }
        currentAccount   = if ($live) { [string]$live.StartName } else { $null }
        currentBinary    = if ($live) { [string]$live.PathName } else { $null }
      })
  }
}
if ($st -and $st.services) {
  foreach ($s in $st.services) {
    $svcName = [string]$s.name
    if (-not $svcName) { continue }
    $already = $false
    foreach ($existing in $serviceTargets) { if ($existing.name -eq $svcName) { $already = $true; break } }
    if ($already) { continue }
    $serviceTargets.Add([pscustomobject][ordered]@{
        name             = $svcName
        displayName      = [string]$s.displayName
        expectedStart    = [string]$s.startMode
        expectedStartRaw = $null
        expectedAccount  = [string]$s.startName
        binaryPath       = [string]$s.pathName
        installed        = $true
        currentState     = [string]$s.state
        currentStartMode = [string]$s.startMode
        currentAccount   = [string]$s.startName
        currentBinary    = [string]$s.pathName
      })
  }
}

# --------------------------------------------------------------- registry
$rootNameMap = @{ 'HKEY_LOCAL_MACHINE' = 'HKLM'; 'HKEY_CURRENT_USER' = 'HKCU'; 'HKEY_CLASSES_ROOT' = 'HKCR'; 'HKEY_USERS' = 'HKU'; 'HKEY_CURRENT_CONFIG' = 'HKCC' }
$regTargets = New-Object System.Collections.Generic.List[object]
$seenReg = @{}
function Add-RegTarget([string]$fullPath, [string]$reason) {
  if ([string]::IsNullOrEmpty($fullPath)) { return }
  $keyPath = $fullPath
  $sep = $keyPath.IndexOf('\')
  if ($sep -lt 1) { return }
  $hiveName = $keyPath.Substring(0, $sep)
  $rest = $keyPath.Substring($sep + 1)
  if (-not $rootNameMap.ContainsKey($hiveName)) { return }
  $short = $rootNameMap[$hiveName]
  $psPath = $short + ':\' + $rest
  if ($seenReg.ContainsKey($psPath)) { return }
  $seenReg[$psPath] = $true
  $regTargets.Add([pscustomobject][ordered]@{
      hive   = $hiveName
      short  = $short
      path   = $rest
      psPath = $psPath
      reason = $reason
    })
}

if ($pf.registry) {
  foreach ($r in $pf.registry) {
    $fp = [string]$r.fullPath
    $reason = 'component'
    if ($fp -match '(?i)\\CurrentVersion\\Uninstall\\') { $reason = 'uninstall-entry (ARP)' }
    elseif ($fp -match '(?i)\\CurrentControlSet\\Services\\EventLog\\') { $reason = 'eventlog-source' }
    elseif ($fp -match '(?i)\\CurrentControlSet\\Services\\') { $reason = 'service' }
    elseif ($fp -match '(?i)\\CurrentVersion\\Run(Once)?$') { $reason = 'startup' }
    elseif ($fp -match '(?i)^HKEY_CLASSES_ROOT') { $reason = 'com-or-file-association' }
    Add-RegTarget $fp $reason
  }
}
foreach ($s in $serviceTargets) {
  if ($s.name) { Add-RegTarget ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + $s.name) 'service (derived)' }
}
if ($str -and $str.evidence -and $str.evidence.registry) {
  # Chromium/V8 binaries carry OS-generic keys (DirectX, Intel MediaSDK, DNS
  # policy). Keep those out unless they mention the app itself, otherwise the
  # plan fills with noise the app never touches.
  $appTokens = @()
  if ($appRoot) { $appTokens += [IO.Path]::GetFileName($appRoot) }
  if ($pf -and $pf.product -and $pf.product.name) { $appTokens += [string]$pf.product.name }
  $appTokenRx = if ($appTokens.Count -gt 0) { '(?i)(' + (($appTokens | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')' } else { $null }
  $noiseRx = '(?i)^(Software|SOFTWARE)\\(Microsoft|Intel|Khronos|Policies|Google|NVIDIA)\\'
  # Autostart and uninstall keys are app-relevant even though they live under
  # Microsoft\Windows; do not let the noise filter swallow them.
  $relevantRx = '(?i)^(Software|SOFTWARE)\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|Uninstall)'
  foreach ($rp in @($str.evidence.registry | Select-Object -First 40)) {
    $text = [string]$rp
    if ($text -match $noiseRx -and $text -notmatch $relevantRx -and -not ($appTokenRx -and $text -match $appTokenRx)) { continue }
    if ($text -match '^(?i)(HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)\\') {
      Add-RegTarget $text 'registry path mined from the binary'
      continue
    }
    # A relative "Software\Vendor\App" string has no hive in it. Emit both
    # candidates instead of dropping the most useful evidence.
    if ($text -match '^(?i)(Software|System)\\') {
      Add-RegTarget ("HKEY_CURRENT_USER\" + $text) 'mined from binary; hive unknown, HKCU candidate'
      Add-RegTarget ("HKEY_LOCAL_MACHINE\" + $text) 'mined from binary; hive unknown, HKLM candidate'
    }
  }
}

# --------------------------------------------------------------- event log
$eventQueries = New-Object System.Collections.Generic.List[object]
$eventSources = @()
if ($pf.eventLogRegistryWrites) {
  foreach ($e in $pf.eventLogRegistryWrites) {
    $m = [regex]::Match([string]$e.fullPath, '(?i)EventLog\\([^\\]+)\\([^\\]+)$')
    if ($m.Success) {
      $logName = $m.Groups[1].Value
      $src = $m.Groups[2].Value
      if ($eventSources -notcontains $src) {
        $eventSources += $src
        $eventQueries.Add([pscustomobject][ordered]@{
            log = $logName; source = $src; ids = @(); reason = 'registered Event Log source in the MSI Registry table'
          })
      }
    }
  }
}
if ($st -and $st.eventSources) {
  foreach ($e in $st.eventSources) {
    $src = [string]$e.source
    if ($eventSources -notcontains $src) {
      $eventSources += $src
      $eventQueries.Add([pscustomobject][ordered]@{ log = [string]$e.log; source = $src; ids = @(); reason = 'Event Log source registered on this machine' })
    }
  }
}
if ($eventSources.Count -gt 0) {
  $eventQueries.Add([pscustomobject][ordered]@{
      log = 'Application'; source = 'Application Error'; ids = @(1000, 1001); reason = 'application crash / WER'
    })
  $eventQueries.Add([pscustomobject][ordered]@{
      log = 'Application'; source = 'Windows Error Reporting'; ids = @(1001); reason = 'WER report'
    })
}
if ($serviceTargets.Count -gt 0) {
  $eventQueries.Add([pscustomobject][ordered]@{
      log = 'System'; source = 'Service Control Manager'; ids = @(7000, 7001, 7009, 7011, 7023, 7031, 7034, 7045); reason = 'service start/stop/crash events'
    })
}
if ($pf) {
  $eventQueries.Add([pscustomobject][ordered]@{
      log = 'Application'; source = 'MsiInstaller'; ids = @(1033, 1034, 1040, 11707, 11708, 11724); reason = 'install/repair/uninstall record (present only if logged)'
    })
}
else {
  $eventQueries.Add([pscustomobject][ordered]@{
      log = 'Application'; source = 'Application Error'; ids = @(1000, 1002); reason = 'application crash (no MSI involved)'
    })
  $eventQueries.Add([pscustomobject][ordered]@{
      log = 'Application'; source = 'Windows Error Reporting'; ids = @(1001); reason = 'WER report (no MSI involved)'
    })
}

# --------------------------------------------------------- files / processes
$processNames = @()
$configFiles = @()
$binaryCandidates = @()
$fileRows = @()
if ($pf.files) { $fileRows = @($pf.files) }

foreach ($f in $fileRows) {
  $nm = [string]$f.name
  $pth = [string]$f.path
  if ($nm -match '(?i)\.exe$') {
    $base = [IO.Path]::GetFileNameWithoutExtension($nm)
    if ($processNames -notcontains $base) { $processNames += $base }
  }
  if ($pth -match '(?i)\.(ini|json|xml|config|cfg|conf|properties|yaml|yml)$') {
    $configFiles += $pth
  }
}
if ($appRoot) {
  foreach ($exe in (Get-ChildItem -LiteralPath $appRoot -Filter *.exe -File -ErrorAction SilentlyContinue | Select-Object -First 20)) {
    $base = [IO.Path]::GetFileNameWithoutExtension($exe.Name)
    if ($base -match '(?i)^(uninstall|cuninst)') { continue }
    if ($processNames -notcontains $base) { $processNames += $base }
    if ($binaryCandidates -notcontains $exe.FullName) { $binaryCandidates += $exe.FullName }
  }
  foreach ($cfg in (Get-ChildItem -LiteralPath $appRoot -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -match '(?i)^\.(ini|json|xml|config|cfg|conf|yaml|yml|properties)$' } |
      Select-Object -First 40)) {
    if ($configFiles -notcontains $cfg.FullName) { $configFiles += $cfg.FullName }
  }
}
$processNames = @($processNames | Select-Object -First 40)
$configFiles = @($configFiles | Select-Object -First 40)

foreach ($s in $serviceTargets) {
  if ($s.binaryPath) { $binaryCandidates += $s.binaryPath }
}

$largest = @()
if ($pf.largestFiles) {
  foreach ($f in $pf.largestFiles) { if ($f.path) { $binaryCandidates += [string]$f.path } }
}

# ---------------------------------------------------------------- log paths
$logCandidates = New-Object System.Collections.Generic.List[object]
foreach ($p in $pathTargets) {
  if ($p.role -eq 'data-or-log' -or $p.role -eq 'install-root') {
    $logCandidates.Add([pscustomobject][ordered]@{
        base = $p.real; patterns = @('*.log', '*.txt', '*.etl', '*.dmp', '*.json', '*.xml'); reason = "under $($p.role)"
      })
  }
}
if ($st -and $st.logFiles) {
  foreach ($l in $st.logFiles) {
    $logCandidates.Add([pscustomobject][ordered]@{ base = (Split-Path -Parent ([string]$l.path)); patterns = @((Split-Path -Leaf ([string]$l.path))); reason = 'log file observed by collect-state' })
  }
}

# ------------------------------------------------------------------ checks
$checks = New-Object System.Collections.Generic.List[object]
if ($pf) {
  $checks.Add([pscustomobject][ordered]@{
      id = 'profile-source'; description = 'The profile was built from the expected package'; command = 'compare source.sha256 with the installer'; expect = 'match'
    })
}
if ($appRoot) {
  $checks.Add([pscustomobject][ordered]@{
      id = 'app-root'; description = "Application directory exists: $appRoot"; command = "Test-Path -LiteralPath `"$appRoot`""; expect = 'True'
    })
  $mainExe = Get-ChildItem -LiteralPath $appRoot -Filter *.exe -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
  if ($mainExe) {
    $checks.Add([pscustomobject][ordered]@{
        id = 'app-main-exe'; description = "Main executable present: $($mainExe.Name)"; command = "Test-Path -LiteralPath `"$($mainExe.FullName)`""; expect = 'True'
      })
  }
}
foreach ($p in $pathTargets) {
  if ($p.role -ne 'install-root') { continue }
  if ($p.dirId -eq 'APPROOT') { continue }   # already covered by the app-root check
  $checks.Add([pscustomobject][ordered]@{
      id = 'path-' + ($p.dirId -replace '[^A-Za-z0-9]', '_')
      description = "Install root exists: $($p.real)"
      command = "Test-Path -LiteralPath `"$($p.real)`""
      expect = 'True after installation'
    })
}
foreach ($s in $serviceTargets) {
  $checks.Add([pscustomobject][ordered]@{
      id = 'svc-' + ($s.name -replace '[^A-Za-z0-9]', '_')
      description = "Service $($s.name) exists with start type $($s.expectedStart) and account $($s.expectedAccount)"
      command = "sc.exe qc $($s.name)"
      expect = "STATE/START_TYPE/START_NAME consistent with the profile; binary path exists"
    })
}
if ($eventSources.Count -gt 0) {
  $checks.Add([pscustomobject][ordered]@{
      id = 'eventlog-sources'
      description = "Event Log sources registered: $($eventSources -join ', ')"
      command = 'reg query "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /s /f "<source>"'
      expect = 'each source has an EventMessageFile that exists'
    })
}
foreach ($c in ($configFiles | Select-Object -First 10)) {
  $checks.Add([pscustomobject][ordered]@{
      id = 'cfg-' + ([IO.Path]::GetFileNameWithoutExtension($c) -replace '[^A-Za-z0-9]', '_')
      description = "Config file present: $c"
      command = 'Test-Path / read default values'
      expect = 'file exists and is readable by the account that runs the app'
    })
}

# -------------------------------------------------------------- procmon plan
$procmon = New-Object System.Collections.Generic.List[string]
foreach ($p in $pathTargets) { $procmon.Add("Path contains `"$($p.real)`"") }
foreach ($r in ($regTargets | Where-Object { $_.reason -ne 'component' } | Select-Object -First 20)) { $procmon.Add("Path contains `"$($r.path)`"") }
$procmon.Add('Result is "ACCESS DENIED"')
$procmon.Add('Result is "NAME NOT FOUND"')
$procmon.Add('Operation is "Process Create"')
$procmon.Add('Operation is "RegSetValue"')

$reproduction = [ordered]@{
  steps = @(
    '1. Install normally (or confirm the app is installed) and reboot if the installer asked.',
    '2. Take the baseline snapshot: capture-snapshot.ps1 -Plan <plan> -Label before',
    '3. Launch the failing feature only. Do not "try everything".',
    '4. If the failure is reproducible only after reboot / only for a non-admin user / only over VPN, record which variable was in play.',
    '5. Take the after snapshot: capture-snapshot.ps1 -Plan <plan> -Label after -SinceMinutes <window>',
    '6. Diff: diff-snapshots.ps1 -Before before.json -After after.json'
  )
  notes = @(
    'Run capture on the affected machine with an account that can read the same registry and directories.',
    'If the app needs elevation to start, take the "before" snapshot in the same elevation context.',
    'Keep the reproduction window short so the diff stays readable.'
  )
}

# ------------------------------------------------------------------- output
$pathArr    = $pathTargets.ToArray()
$regArr     = $regTargets.ToArray() | Select-Object -First 300
$svcArr     = $serviceTargets.ToArray()
$logArr     = $logCandidates.ToArray() | Select-Object -First 40
$eventArr   = $eventQueries.ToArray()
$checkArr   = $checks.ToArray()
$procmonArr = $procmon.ToArray()

# Without an MSI there is no ProductName property; the main executable's version
# resource is the next best identity source (Electron apps carry it).
$appProduct = $null
if (-not $pf -and $appRoot) {
  $appProduct = [ordered]@{ name = (Split-Path -Leaf $appRoot); version = $null; architecture = $arch }
  $mainExeForIdentity = Get-ChildItem -LiteralPath $appRoot -Filter *.exe -File -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending | Select-Object -First 1
  if ($mainExeForIdentity) {
    $vi = $mainExeForIdentity.VersionInfo
    if ($vi.ProductName) { $appProduct.name = [string]$vi.ProductName }
    if ($vi.FileVersion) { $appProduct.version = [string]$vi.FileVersion }
    elseif ($vi.ProductVersion) { $appProduct.version = [string]$vi.ProductVersion }
  }
}

$plan = [ordered]@{
  tool        = 'build-probe-plan'
  toolVersion = $ToolVersion
  generated   = (Get-Date).ToString('o')
  source      = [ordered]@{
    profile = if ($Profile -and (Test-Path -LiteralPath $Profile)) { (Resolve-Path -LiteralPath $Profile).Path } else { $null }
    state   = if ($State -and (Test-Path -LiteralPath $State)) { (Resolve-Path -LiteralPath $State).Path } else { $null }
    strings = if ($Strings -and (Test-Path -LiteralPath $Strings)) { (Resolve-Path -LiteralPath $Strings).Path } else { $null }
    appDir  = $appRoot
  }
  product     = if ($pf) { $pf.product } else { $appProduct }
  targetMachine = [ordered]@{
    name = $env:COMPUTERNAME; os = [string]$env:OS; psVersion = $PSVersionTable.PSVersion.ToString()
    is64BitOs = $is64Os; programFiles = $programFiles
  }
  paths       = $pathArr
  registry    = $regArr
  services    = $svcArr
  processes   = $processNames
  configFiles = $configFiles
  binaryCandidates = $binaryCandidates
  logCandidates = $logArr
  eventLog    = $eventArr
  checks      = $checkArr
  procmonFilters = $procmonArr
  reproduction = $reproduction
  notes = @(
    'Registry paths come from the MSI Registry table (or from mined binary strings when there is no MSI); values may contain [PROPERTY] placeholders that resolve only during install.',
    'binaryPath in services is logical until resolved on the machine; confirm with sc.exe qc.',
    'A "before" snapshot taken without the app installed is still useful: diff it against "after install" to capture first-run writes.',
    $(if ($appRoot -and -not $pf) { 'No MSI profile was supplied: this plan is built from the application directory and optional strings/state evidence. Paths are direct machine paths, not MSI logical paths.' } else { 'Plan built from an MSI profile.' })
  ) + $inputWarnings.ToArray()
}

$planPath = Join-Path $OutDir 'probe-plan.json'
$plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $planPath -Encoding UTF8

# human-readable plan
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Dynamic probe plan - " + ([string]$plan.product.name).Trim() + $(if ($plan.product.version) { ' ' + $plan.product.version } else { '' }))
[void]$md.AppendLine('')
$srcParts = @()
if ($plan.source.profile) { $srcParts += "profile=$($plan.source.profile)" }
if ($plan.source.state) { $srcParts += "state=$($plan.source.state)" }
if ($plan.source.strings) { $srcParts += "strings=$($plan.source.strings)" }
if ($plan.source.appDir) { $srcParts += "appDir=$($plan.source.appDir)" }
[void]$md.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  sources: " + ($srcParts -join ' ; '))
[void]$md.AppendLine('')
[void]$md.AppendLine('## 1. Watch these paths')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Logical path | Real path | Exists now | Role |')
[void]$md.AppendLine('|---|---|---|---|')
foreach ($p in $pathTargets) { [void]$md.AppendLine("| $($p.logical) | ``$($p.real)`` | $($p.exists) | $($p.role) |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 2. Snapshot these registry keys')
[void]$md.AppendLine('')
[void]$md.AppendLine('| PS path | Purpose |')
[void]$md.AppendLine('|---|---|')
foreach ($r in ($regTargets | Select-Object -First 40)) { [void]$md.AppendLine("| ``$($r.psPath)`` | $($r.reason) |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 3. Services and expected state')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Service | Expected start | Expected account | Installed | Current state |')
[void]$md.AppendLine('|---|---|---|---|---|')
foreach ($s in $serviceTargets) { [void]$md.AppendLine("| $($s.name) | $($s.expectedStart) | $($s.expectedAccount) | $($s.installed) | $($s.currentState) |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 4. Event Log queries')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Log | Source | Event IDs | Purpose |')
[void]$md.AppendLine('|---|---|---|---|')
foreach ($e in $eventQueries) { [void]$md.AppendLine("| $($e.log) | $($e.source) | $($e.ids -join ', ') | $($e.reason) |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 5. Procmon filters')
[void]$md.AppendLine('')
foreach ($f in $procmon) { [void]$md.AppendLine("- $f") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 6. Checks with expectations')
[void]$md.AppendLine('')
foreach ($c in $checks) { [void]$md.AppendLine("- **$($c.id)**: $($c.description)  (`` $($c.command) ``) -> expect: $($c.expect)") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 7. Capture sequence')
[void]$md.AppendLine('')
foreach ($s in $reproduction.steps) { [void]$md.AppendLine($s) }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 8. One-liners')
[void]$md.AppendLine('')
[void]$md.AppendLine('```powershell')
foreach ($e in $eventQueries) {
  $prov = $e.source -replace "'", "''"
  [void]$md.AppendLine("Get-WinEvent -FilterHashtable @{LogName='$($e.log)'; ProviderName='$prov'} -MaxEvents 40 -ErrorAction SilentlyContinue |")
  [void]$md.AppendLine("  Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap")
}
[void]$md.AppendLine('```')
$mdPath = Join-Path $OutDir 'probe-plan.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

[ordered]@{
  status      = 'ok'
  outDir      = $OutDir
  plan        = $planPath
  readme      = $mdPath
  product     = ("$($plan.product.name) $($plan.product.version)").Trim()
  counts      = [ordered]@{
    paths = $pathTargets.Count; registry = $regTargets.Count; services = $serviceTargets.Count
    processes = $processNames.Count; eventQueries = $eventQueries.Count; checks = $checks.Count
  }
  installedServices = @($serviceTargets | Where-Object { $_.installed } | ForEach-Object { "$($_.name): $($_.currentState) / $($_.currentStartMode)" })
  unmappedPaths = @($pathTargets | Where-Object { -not $_.mapped } | ForEach-Object { $_.logical })
} | ConvertTo-Json -Depth 6
