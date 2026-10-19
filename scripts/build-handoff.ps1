<#
.SYNOPSIS
  Generate a paste-ready handoff brief from install-profiler evidence to the
  reverse-engineering skill (or to a human analyst).

.DESCRIPTION
  When the package is a .NET bootstrap, an Electron/Squirrel app, a PyInstaller
  bundle or a native loader, strings evidence is not enough: someone has to read
  the code. This script produces the handoff package so the second pass does not
  rediscover everything.

  It classifies the target, collects the facts already established (profile,
  probe plan, strings evidence), turns the gaps into concrete questions per
  branch, and writes the exact commands plus an evidence contract.

  Output: handoff.md (paste into the other session) and handoff.json
  (machine-readable). Read-only; the target is never executed.

.PARAMETER Target
  Installer file, application directory, or main executable to be analysed.

.PARAMETER Profile
  Optional profile.json from export-msi-tables.ps1.

.PARAMETER ProbePlan
  Optional probe-plan.json from build-probe-plan.ps1.

.PARAMETER Strings
  Optional strings-evidence.json from mine-strings.ps1.

.PARAMETER OutDir
  Output directory. Default: .\handoff

.EXAMPLE
  ./build-handoff.ps1 -Target 'C:\Program Files\Vendor\App' -Profile .\profile\profile.json
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Target,

  [string]$Profile,
  [string]$ProbePlan,
  [string]$Strings,
  [string]$State,
  [string]$OutDir = '.\handoff'
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'

if (-not (Test-Path -LiteralPath $Target)) {
  [ordered]@{ tool = 'build-handoff'; status = 'error'; message = "Target not found: $Target" } | ConvertTo-Json
  exit 2
}
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Read-Json([string]$Path) {
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
  try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
$pf = Read-Json $Profile
$plan = Read-Json $ProbePlan
$str = Read-Json $Strings
$st = Read-Json $State

# ---------------------------------------------------------------- classify
$targetItem = Get-Item -LiteralPath $Target
$isDir = $targetItem.PSIsContainer
$mainExe = $null
if ($isDir) {
  $mainExe = Get-ChildItem -LiteralPath $targetItem.FullName -File -Filter *.exe -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending | Select-Object -First 1
}
else { $mainExe = $targetItem }

function Get-PeFlags([System.IO.FileInfo]$File) {
  $result = [ordered]@{ isPe = $false; is64 = $false; dotnet = $false; arch = 'unknown' }
  if ($null -eq $File) { return $result }
  try {
    $fs = [IO.File]::OpenRead($File.FullName)
    try {
      $head = New-Object byte[] ([int][Math]::Min(16384, $fs.Length))
      [void]$fs.Read($head, 0, $head.Length)
    }
    finally { $fs.Dispose() }
    if ($head.Length -lt 0x40 -or $head[0] -ne 0x4D -or $head[1] -ne 0x5A) { return $result }
    $result.isPe = $true
    $lfanew = [BitConverter]::ToInt32($head, 0x3C)
    if ($lfanew -lt 0 -or ($lfanew + 0x18) -ge $head.Length) { return $result }
    $machine = [BitConverter]::ToUInt16($head, $lfanew + 4)
    $result.arch = switch ($machine) { 0x014C { 'x86' } 0x8664 { 'x64' } 0xAA64 { 'arm64' } default { ('0x{0:X}' -f $machine) } }
    $optOff = $lfanew + 0x18
    $magic = [BitConverter]::ToUInt16($head, $optOff)
    $result.is64 = ($magic -eq 0x20B)
    $ddOff = $optOff + $(if ($result.is64) { 112 } else { 96 })
    $clrOff = $ddOff + (14 * 8)
    if (($clrOff + 8) -le $head.Length) {
      $rva = [BitConverter]::ToUInt32($head, $clrOff)
      $size = [BitConverter]::ToUInt32($head, $clrOff + 4)
      $result.dotnet = ($rva -ne 0 -and $size -ne 0)
    }
  }
  catch { }
  return $result
}

$pe = Get-PeFlags $mainExe
$sha = $null
if ($mainExe) { try { $sha = (Get-FileHash -LiteralPath $mainExe.FullName -Algorithm SHA256).Hash } catch { } }

$hasAsar = $false
$asarPaths = @()
if ($isDir) {
  $asarPaths = @(Get-ChildItem -LiteralPath $targetItem.FullName -Filter 'app.asar' -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 3 | ForEach-Object { $_.FullName })
  $hasAsar = $asarPaths.Count -gt 0
}

$packed = $false
if ($mainExe) {
  try {
    $fs = [IO.File]::OpenRead($mainExe.FullName)
    try {
      $b = New-Object byte[] 4096
      [void]$fs.Read($b, 0, $b.Length)
      $txt = [Text.Encoding]::GetEncoding(28591).GetString($b)
      $packed = ($txt -match 'UPX!|VMProtect|Themida|\.vmp[0-9]|Enigma Protector')
    }
    finally { $fs.Dispose() }
  }
  catch { }
}

$branch = 'native'
$branchWhy = 'No managed or Electron marker found; treat as a native loader.'
if ($hasAsar) { $branch = 'electron'; $branchWhy = 'resources/app.asar found next to the executable.' }
elseif ($pe.dotnet) { $branch = 'dotnet'; $branchWhy = 'PE optional header declares a CLR runtime data directory (managed assembly).' }
elseif ($str -and $str.markers -and $str.markers.pyinstaller) { $branch = 'pyinstaller'; $branchWhy = 'PyInstaller markers found in strings evidence.' }
elseif ($str -and $str.markers -and $str.markers.electron) { $branch = 'electron'; $branchWhy = 'Electron markers found in strings evidence.' }
if ($packed) { $branchWhy += ' The binary also looks packed; unpacking may be required first.' }

# ---------------------------------------------------------------- tools
function Get-ToolPath([string]$Name) {
  $c = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) { return $c.Source }
  if ($Name -eq 'ilspycmd') {
    $p = Join-Path $env:USERPROFILE '.dotnet\tools\ilspycmd.exe'
    if (Test-Path -LiteralPath $p) { return $p }
  }
  return $null
}
$toolIlspy = Get-ToolPath 'ilspycmd'
$toolDotnet = Get-ToolPath 'dotnet'
$toolNpx = Get-ToolPath 'npx'
$toolObjdump = Get-ToolPath 'objdump'
$toolRizin = Get-ToolPath 'rizin'

# ---------------------------------------------------------------- known facts
$known = New-Object 'System.Collections.Generic.List[object]'
if ($pf) {
  $known.Add([pscustomobject][ordered]@{ area = 'product'; fact = "$($pf.product.name) $($pf.product.version) / $($pf.product.manufacturer) / $($pf.product.architecture)" })
  if ($pf.installPaths) {
    foreach ($r in @($pf.installPaths | Where-Object { $_.parent -eq 'TARGETDIR' } | Select-Object -First 6)) {
      $known.Add([pscustomobject][ordered]@{ area = 'install-path'; fact = [string]$r.path })
    }
  }
  if ($pf.services) {
    foreach ($s in @($pf.services | Select-Object -First 8)) {
      $known.Add([pscustomobject][ordered]@{ area = 'service'; fact = "$($s.name) [$($s.startTypeName)] account=$($s.startName) bin=$($s.binaryPath)" })
    }
  }
  if ($pf.eventLogRegistryWrites) {
    foreach ($e in @($pf.eventLogRegistryWrites | Select-Object -First 6)) {
      $known.Add([pscustomobject][ordered]@{ area = 'eventlog'; fact = [string]$e.fullPath })
    }
  }
  if ($pf.registry) {
    $known.Add([pscustomobject][ordered]@{ area = 'registry'; fact = ("{0} registry writes; sample: {1}" -f @($pf.registry).Count, ((@($pf.registry) | Select-Object -First 3 | ForEach-Object { $_.fullPath }) -join ' | ')) })
  }
  if ($pf.files) {
    $known.Add([pscustomobject][ordered]@{ area = 'files'; fact = ("{0} files, {1} bytes" -f @($pf.files).Count, $pf.summary.filesTotalBytes) })
  }
}
if ($plan) {
  if ($plan.paths) {
    foreach ($p in @($plan.paths | Select-Object -First 6)) {
      $known.Add([pscustomobject][ordered]@{ area = 'watch-path'; fact = [string]$p.real })
    }
  }
  if ($plan.eventLog) {
    foreach ($e in @($plan.eventLog | Select-Object -First 6)) {
      $known.Add([pscustomobject][ordered]@{ area = 'event-query'; fact = "$($e.log) / $($e.source) / ids=$(($e.ids -join ','))" })
    }
  }
}
if ($str -and $str.counts) {
  $known.Add([pscustomobject][ordered]@{ area = 'strings'; fact = ("registry={0} paths={1} logs={2} services={3} urls={4}" -f $str.counts.registry, $str.counts.paths, $str.counts.logFiles, $str.counts.services, $str.counts.urls) })
}
if ($st) {
  if ($st.uninstall) {
    foreach ($u in @($st.uninstall | Select-Object -First 3)) {
      $known.Add([pscustomobject][ordered]@{ area = 'uninstall-entry'; fact = "$($u.displayName) $($u.displayVersion) at $($u.installLocation)" })
    }
  }
  if ($st.directories) {
    foreach ($d in @($st.directories | Select-Object -First 5)) {
      $known.Add([pscustomobject][ordered]@{ area = 'runtime-dir'; fact = "$($d.path) (files=$($d.fileCount))" })
    }
  }
  if ($st.services) {
    foreach ($s in @($st.services | Select-Object -First 5)) {
      $known.Add([pscustomobject][ordered]@{ area = 'runtime-service'; fact = "$($s.name) state=$($s.state) start=$($s.startMode)" })
    }
  }
  if ($st.logFiles) {
    $known.Add([pscustomobject][ordered]@{ area = 'log-files'; fact = ("{0} log-like files observed" -f @($st.logFiles).Count) })
  }
}

# ------------------------------------------------------------------ questions
$questions = New-Object 'System.Collections.Generic.List[string]'
$questions.Add('How is the effective config-file path resolved (hard-coded constant / registry / environment variable / user profile)? Give the resolution order.')
$questions.Add('Where are the log directory and log file name decided, and what is the rotation policy?')
$questions.Add('What error-message templates exist, and which of them also reach the Event Log or a crash dump (so they can be matched at runtime)?')
$questions.Add('Is there self-update, telemetry or licence checking? Endpoint and trigger condition?')
switch ($branch) {
  'dotnet' {
    $questions.Add('What is the entry assembly and namespace, and which method holds the main flow?')
    $questions.Add('Which logging framework is used (Serilog / NLog / log4net / custom) and where is its config read?')
    $questions.Add('Where are service registration, scheduled tasks and the single-instance mutex implemented?')
    $questions.Add('Are string constants obfuscated? If so, what is the deobfuscation path?')
  }
  'electron' {
    $questions.Add('What is the app.asar main entry file and the package.json main field?')
    $questions.Add('Where does electron-store / custom config persist, and how is the user-data directory used?')
    $questions.Add('What IPC channel names exist between main and renderer, and what do they do?')
    $questions.Add('What is the auto-update feed URL (Squirrel / electron-updater) and its failure handling?')
  }
  'pyinstaller' {
    $questions.Add('Can the PYZ be extracted, what is the main module name, and which config/log functions does the entry script call?')
    $questions.Add('Are any plaintext config or rule files bundled, and at which path?')
  }
  default {
    $questions.Add('Which imported APIs (Reg* / CreateService / RegisterEventSource / EventRegister) are present, and which feature does each serve?')
    $questions.Add('Where are the key strings (config path, log path, error messages) referenced, and in what context?')
    $questions.Add('Is the binary packed, and if so, which packer and what is the best static entry point?')
  }
}
$questions.Add('Mark any conclusion that is only inferred; do not invent detail to make the report look complete.')

# ---------------------------------------------------------- suggested commands
$cmds = New-Object 'System.Collections.Generic.List[object]'
$exePath = if ($mainExe) { $mainExe.FullName } else { $Target }
switch ($branch) {
  'dotnet' {
    $cmd = if ($toolIlspy) { "& '$toolIlspy' -p -o '<out-dir>' '$exePath'" } else { 'dotnet tool install --global ilspycmd ; ilspycmd -p -o <out-dir> <exe>' }
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'decompile project'; command = $cmd; available = [bool]$toolIlspy })
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'confirm CLR header'; command = "& '$toolObjdump' -x '$exePath' | Select-String -Pattern 'CLR|mscoree'"; available = [bool]$toolObjdump })
  }
  'electron' {
    $cmd = if ($toolNpx) { "npx --yes @electron/asar extract '<app.asar>' '<out-dir>'" } else { '7z x <app.asar> -o<out-dir>' }
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'extract asar'; command = $cmd; available = [bool]$toolNpx })
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'inspect entry'; command = "Get-Content '<out-dir>\\package.json' ; Get-Content '<out-dir>\\main.js' -TotalCount 80"; available = $true })
  }
  'pyinstaller' {
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'list archive'; command = "pyi-archive_viewer -l '$exePath'"; available = [bool](Get-ToolPath 'pyi-archive_viewer') })
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'extract (needs pyinstxtractor)'; command = 'python pyinstxtractor-ng.py <exe>'; available = [bool](Get-ToolPath 'python') })
  }
  default {
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'imports and headers'; command = "& '$toolObjdump' -x '$exePath'"; available = [bool]$toolObjdump })
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'strings with xrefs'; command = "& '$toolRizin' -N -q -c 'izz' -c 'q' '$exePath'"; available = [bool]$toolRizin })
    $cmds.Add([pscustomobject][ordered]@{ purpose = 'call sites of a symbol'; command = "& '$toolRizin' -N -q -c 'aaa' -c 'axt @ sym.imp.CreateServiceW' -c 'q' '$exePath'"; available = [bool]$toolRizin })
  }
}

# ------------------------------------------------------------------ contract
$contract = @(
  'You are executing the `reverse-engineering` skill. Answer only the questions in section 4; do not redo the installation profiling.',
  'Tag every conclusion [verified] (seen directly in tool output) / [inferred] (reasoned) / [unknown] (cannot determine), with file + method or address.',
  'Do not execute the target. Dynamic verification belongs to the install-profiler probe plan.',
  'Do not bypass licensing, activation or DRM. This is diagnostic reading, not cracking.',
  'Return new findings in the section 6 format so install-profiler can update its profile and probe plan.'
)

# -------------------------------------------------------------------- output
$result = [ordered]@{
  tool        = 'build-handoff'
  toolVersion = $ToolVersion
  generated   = (Get-Date).ToString('o')
  target      = [ordered]@{
    path = $targetItem.FullName; kind = if ($isDir) { 'directory' } else { 'file' }
    mainExe = if ($mainExe) { $mainExe.FullName } else { $null }
    sha256 = $sha; sizeBytes = if ($mainExe) { $mainExe.Length } else { $null }
    pe = $pe; hasAsar = $hasAsar; asarFiles = $asarPaths; packed = $packed
  }
  assessment  = [ordered]@{ branch = $branch; why = $branchWhy }
  inputs      = [ordered]@{
    profile = if ($Profile) { (Resolve-Path -LiteralPath $Profile).Path } else { $null }
    probePlan = if ($ProbePlan) { (Resolve-Path -LiteralPath $ProbePlan).Path } else { $null }
    strings = if ($Strings) { (Resolve-Path -LiteralPath $Strings).Path } else { $null }
    state = if ($State) { (Resolve-Path -LiteralPath $State).Path } else { $null }
  }
  knownFacts  = $known.ToArray()
  questions   = $questions.ToArray()
  suggestedCommands = $cmds.ToArray()
  contract    = $contract
}

$jsonPath = Join-Path $OutDir 'handoff.json'
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Handoff brief: install profile -> reverse engineering')
[void]$md.AppendLine('')
[void]$md.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$md.AppendLine('')
[void]$md.AppendLine('## 0. Instructions for the receiving agent')
[void]$md.AppendLine('')
foreach ($c in $contract) { [void]$md.AppendLine("- $c") }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 1. Target')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Item | Value |')
[void]$md.AppendLine('|---|---|')
[void]$md.AppendLine("| Path | ``$($targetItem.FullName)`` |")
[void]$md.AppendLine("| Main executable | ``$($result.target.mainExe)`` |")
[void]$md.AppendLine("| SHA256 | ``$sha`` |")
[void]$md.AppendLine("| Branch | **$branch** |")
[void]$md.AppendLine("| Why | $branchWhy |")
if ($hasAsar) { [void]$md.AppendLine("| app.asar | ``$($asarPaths -join '; ')`` |") }
if ($packed) { [void]$md.AppendLine('| Packed | Possible UPX/VMProtect/Themida - confirm before deep analysis |') }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 2. Established facts (do not re-derive)')
[void]$md.AppendLine('')
if ($known.Count -eq 0) {
  [void]$md.AppendLine('(No profile/plan/strings input was supplied.)')
}
else {
  [void]$md.AppendLine('| Area | Fact |')
  [void]$md.AppendLine('|---|---|')
  foreach ($k in $known) { [void]$md.AppendLine("| $($k.area) | $($k.fact) |") }
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## 3. Input files')
[void]$md.AppendLine('')
foreach ($k in @('profile', 'probePlan', 'strings', 'state')) {
  $v = $result.inputs[$k]
  if ($v) { [void]$md.AppendLine("- $k : ``$v``") }
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## 4. Questions to answer')
[void]$md.AppendLine('')
$i = 1
foreach ($q in $questions) { [void]$md.AppendLine("$i. $q"); $i++ }
[void]$md.AppendLine('')
[void]$md.AppendLine('## 5. Suggested commands')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Purpose | Command | Tool ready |')
[void]$md.AppendLine('|---|---|---|')
foreach ($c in $cmds) {
  $cmdText = ([string]$c.command).Replace('|', '\|')
  [void]$md.AppendLine("| $($c.purpose) | ``$cmdText`` | $(if ($c.available) { 'yes' } else { 'no (install first)' }) |")
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## 6. Return format')
[void]$md.AppendLine('')
[void]$md.AppendLine('```json')
[void]$md.AppendLine('{ "findings": [ { "question": 1, "answer": "...", "confidence": "verified|inferred|unknown", "evidence": "file:line / method / address" } ] }')
[void]$md.AppendLine('```')
$mdPath = Join-Path $OutDir 'handoff.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

[ordered]@{
  status     = 'ok'
  outDir     = $OutDir
  handoff    = $jsonPath
  brief      = $mdPath
  branch     = $branch
  why        = $branchWhy
  questions  = $questions.Count
  knownFacts = $known.Count
  tools      = [ordered]@{ ilspycmd = [bool]$toolIlspy; dotnet = [bool]$toolDotnet; npx = [bool]$toolNpx; objdump = [bool]$toolObjdump; rizin = [bool]$toolRizin }
} | ConvertTo-Json -Depth 6
