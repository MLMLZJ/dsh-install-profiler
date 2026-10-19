<#
.SYNOPSIS
  Mine a Windows binary (or a directory of them) for behavioural evidence:
  registry paths, file paths, service names, log paths, event-source hints,
  URLs, GUIDs and error templates - without executing it.

.DESCRIPTION
  For MSI packages the install definition is a readable database. For EXE-based
  installers (NSIS/Inno/InstallShield) and for installed applications there is no
  such database, so evidence has to come out of the binary.

  Extracts printable ASCII and UTF-16LE runs, deduplicates globally, classifies
  them, and writes JSON + Markdown. Static bridge between "I have a binary" and
  "I know which registry key, log directory and event source to watch".

  Read-only: the file is opened for reading and never launched.

.PARAMETER Path
  A single .exe/.dll/.sys, or a directory.

.PARAMETER OutDir
  Output directory. Default: .\strings-evidence

.PARAMETER MaxScanMB
  Files larger than this are scanned at head and tail only. Default 256.

.PARAMETER MaxPerCategory
  Cap of unique strings kept per category. Default 120.

.PARAMETER MaxFiles
  Directory mode: stop after this many files. Default 40.

.PARAMETER Recurse
  Recurse into subdirectories in directory mode.

.EXAMPLE
  ./mine-strings.ps1 -Path 'C:\Program Files\Vendor\App\app.exe'

.EXAMPLE
  ./mine-strings.ps1 -Path '.\extracted' -Recurse -MaxFiles 20
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Path,

  [string]$OutDir = '.\strings-evidence',
  [int]$MaxScanMB = 256,
  [int]$MaxPerCategory = 120,
  [int]$MaxFiles = 40,
  [switch]$Recurse
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.1.0'

if (-not (Test-Path -LiteralPath $Path)) {
  [ordered]@{ tool = 'mine-strings'; status = 'error'; message = "Path not found: $Path" } | ConvertTo-Json
  exit 2
}
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function New-Rx([string]$Pattern) {
  return [regex]::new($Pattern, [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

$rxRuns     = New-Rx '[\x20-\x7E]{4,}'
$rxRegistry = New-Rx '^(?i)(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\'
$rxSoftware = New-Rx '^(?i)SOFTWARE\\'
$rxUrl      = New-Rx '^(?i)https?://'
$rxGuid     = New-Rx '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$'
$rxPath     = New-Rx '^(?i)([A-Za-z]:\\[A-Za-z0-9_~.$-]|%[A-Za-z_()0-9]+%\\|\\\\[A-Za-z0-9_.-]+\\)'
$rxLogExt   = New-Rx '(?i)\.(log|etl|dmp|wer|trace|evtx)$'
$rxLogDir   = New-Rx '(?i)\\logs?\\'
$rxEvent    = New-Rx '(?i)(event ?log|eventsource|eventmessagefile|\betw\b|provider ?name)'
$rxService  = New-Rx '(?i)(^SERVICE_[A-Z_]+$|service\.exe$|^[a-z0-9_.-]*svc[a-z0-9_.-]*$)'
$rxMutex    = New-Rx '(?i)^(Global|Local)\\|\bmutex\b'
$rxError    = New-Rx '(?i)\b(error|failed|failure|denied|invalid|cannot|unable|timeout|unauthorized)\b'
# One combined pre-filter so marker detection costs one regex call per run
# instead of seven function calls (that difference was 10 s vs 130 s on 430k runs).
$rxMarker   = New-Rx '(?i)(PyInstaller|_MEIPASS|pyiboot|pyi-contents|app\.asar|chrome_100_percent|mscoree|System\.Runtime|BSJB|\.NET Framework|UPX!|UPX0|UPX1|Nullsoft|Inno Setup|VMProtect|Themida|Enigma Protector|\.vmp)'

# --------------------------------------------------------------- file list
$targets = @()
$item = Get-Item -LiteralPath $Path
if ($item.PSIsContainer) {
  $gciArgs = @{ LiteralPath = $item.FullName; File = $true; ErrorAction = 'SilentlyContinue' }
  if ($Recurse) { $gciArgs.Recurse = $true }
  $targets = @(Get-ChildItem @gciArgs |
    Where-Object { $_.Extension -in '.exe', '.dll', '.sys', '.ocx', '.cpl' } |
    Sort-Object Length -Descending | Select-Object -First $MaxFiles)
}
else { $targets = @($item) }

if ($targets.Count -eq 0) {
  [ordered]@{ tool = 'mine-strings'; status = 'ok'; message = 'No binary files matched.'; outDir = $OutDir } | ConvertTo-Json
  exit 0
}

# ------------------------------------------------------------- extraction
$latin1 = [Text.Encoding]::GetEncoding(28591)
$unique = New-Object 'System.Collections.Generic.HashSet[string]'

function Read-Runs {
  param([string]$File, [long]$LimitBytes)
  $fs = [IO.File]::Open($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $len = $fs.Length
    $ranges = @()
    if ($LimitBytes -le 0 -or $len -le $LimitBytes) { $ranges += , @(0L, $len) }
    else {
      $edge = [Math]::Min($len, 64L * 1024 * 1024)
      $ranges += , @(0L, $edge)
      $ranges += , @(($len - $edge), $edge)
    }
    $chunkSize = 8 * 1024 * 1024
    foreach ($range in $ranges) {
      $fs.Position = [long]$range[0]
      $remaining = [long]$range[1]
      $carryA = ''
      $carryU = ''
      while ($remaining -gt 0) {
        $want = [int][Math]::Min([long]$chunkSize, $remaining)
        if ($want % 2 -ne 0) { $want-- }
        if ($want -le 0) { break }
        $buf = New-Object byte[] $want
        $read = $fs.Read($buf, 0, $want)
        if ($read -le 0) { break }

        $textA = $carryA + $latin1.GetString($buf, 0, $read)
        foreach ($m in $rxRuns.Matches($textA)) {
          $v = $m.Value
          if ($v.Length -le 400) { [void]$unique.Add($v) }
        }
        $carryA = if ($textA.Length -gt 64) { $textA.Substring($textA.Length - 64) } else { $textA }

        $evenRead = $read - ($read % 2)
        if ($evenRead -gt 0) {
          $textU = $carryU + [Text.Encoding]::Unicode.GetString($buf, 0, $evenRead)
          foreach ($m in $rxRuns.Matches($textU)) {
            $v = $m.Value
            if ($v.Length -le 400) { [void]$unique.Add($v) }
          }
          $carryU = if ($textU.Length -gt 64) { $textU.Substring($textU.Length - 64) } else { $textU }
        }
        $remaining -= $read
      }
    }
  }
  finally { $fs.Dispose() }
}

# ----------------------------------------------------------- categorising
$cats = [ordered]@{
  registry = New-Object 'System.Collections.Generic.List[string]'
  paths    = New-Object 'System.Collections.Generic.List[string]'
  logFiles = New-Object 'System.Collections.Generic.List[string]'
  services = New-Object 'System.Collections.Generic.List[string]'
  eventLog = New-Object 'System.Collections.Generic.List[string]'
  urls     = New-Object 'System.Collections.Generic.List[string]'
  guids    = New-Object 'System.Collections.Generic.List[string]'
  mutexes  = New-Object 'System.Collections.Generic.List[string]'
  errors   = New-Object 'System.Collections.Generic.List[string]'
  other    = New-Object 'System.Collections.Generic.List[string]'
}
$caps = @{ registry = $MaxPerCategory; paths = $MaxPerCategory; logFiles = $MaxPerCategory; services = $MaxPerCategory; eventLog = $MaxPerCategory; urls = $MaxPerCategory; guids = 40; mutexes = 40; errors = 60; other = 60 }

function Add-To([string]$Cat, [string]$Value) {
  if ($cats[$Cat].Count -ge $caps[$Cat]) { return }
  $cats[$Cat].Add($Value)
}

function Get-Category([string]$s) {
  if ($rxRegistry.IsMatch($s) -or $rxSoftware.IsMatch($s)) { return 'registry' }
  if ($rxUrl.IsMatch($s)) { return 'urls' }
  if ($rxGuid.IsMatch($s)) { return 'guids' }
  if ($rxPath.IsMatch($s) -and $s.Length -ge 8) { return 'paths' }
  if ($rxLogExt.IsMatch($s) -or $rxLogDir.IsMatch($s)) { return 'logFiles' }
  if ($rxEvent.IsMatch($s)) { return 'eventLog' }
  if ($rxService.IsMatch($s)) { return 'services' }
  if ($rxMutex.IsMatch($s)) { return 'mutexes' }
  if ($rxError.IsMatch($s) -and $s.Length -ge 15 -and $s -match ' ') { return 'errors' }
  return 'other'
}

$perFile = New-Object 'System.Collections.Generic.List[object]'
$limitBytes = if ($MaxScanMB -gt 0) { [long]$MaxScanMB * 1MB } else { 0L }
foreach ($f in $targets) {
  $before = $unique.Count
  try { Read-Runs -File $f.FullName -LimitBytes $limitBytes }
  catch {
    $perFile.Add([pscustomobject][ordered]@{ file = $f.FullName; error = $_.Exception.Message })
    continue
  }
  $sha = $null
  try { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch { }
  $perFile.Add([pscustomobject][ordered]@{
      file = $f.FullName; sizeBytes = $f.Length; sha256 = $sha; newUniqueRuns = ($unique.Count - $before)
    })
}

# Marker detection runs over every unique run, not over the capped category
# lists, so a marker is never lost just because that bucket filled up first.
$mk = @{ dotnet = $false; electron = $false; pyi = $false; upx = $false; nsis = $false; inno = $false; prot = $false }
$pendingMarkers = 7
function Test-Any([string]$Value, [string[]]$Needles) {
  foreach ($n in $Needles) {
    if ($Value.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
  }
  return $false
}

foreach ($s in $unique) {
  if ($pendingMarkers -gt 0 -and $s.Length -le 128 -and $rxMarker.IsMatch($s)) {
    if (-not $mk.pyi -and (Test-Any $s @('PyInstaller', '_MEIPASS', 'pyiboot', 'pyi-contents'))) { $mk.pyi = $true; $pendingMarkers-- }
    if (-not $mk.electron -and (Test-Any $s @('app.asar', 'chrome_100_percent'))) { $mk.electron = $true; $pendingMarkers-- }
    if (-not $mk.dotnet -and (Test-Any $s @('mscoree', 'System.Runtime', 'BSJB', '.NET Framework'))) { $mk.dotnet = $true; $pendingMarkers-- }
    if (-not $mk.upx -and (Test-Any $s @('UPX!', 'UPX0', 'UPX1'))) { $mk.upx = $true; $pendingMarkers-- }
    if (-not $mk.nsis -and (Test-Any $s @('Nullsoft'))) { $mk.nsis = $true; $pendingMarkers-- }
    if (-not $mk.inno -and (Test-Any $s @('Inno Setup'))) { $mk.inno = $true; $pendingMarkers-- }
    if (-not $mk.prot -and (Test-Any $s @('VMProtect', 'Themida', 'Enigma Protector', '.vmp'))) { $mk.prot = $true; $pendingMarkers-- }
  }
  if ($s.Length -lt 6 -or $s.Length -gt 300) { continue }
  $alnum = 0
  foreach ($ch in $s.ToCharArray()) { if ([char]::IsLetterOrDigit($ch)) { $alnum++ } }
  if ($alnum -lt 4) { continue }
  if ($alnum * 2 -lt $s.Length) { continue }
  $cat = Get-Category $s
  Add-To $cat $s
}

$counts = [ordered]@{}
foreach ($k in $cats.Keys) { $counts[$k] = $cats[$k].Count }

# ------------------------------------------------------------ marker check
$markers = [ordered]@{
  dotnetClr = $mk.dotnet; electron = $mk.electron; pyinstaller = $mk.pyi
  upx = $mk.upx; nsis = $mk.nsis; inno = $mk.inno; protected = $mk.prot
}

# -------------------------------------------------------------- evidence
$result = [ordered]@{
  tool         = 'mine-strings'
  toolVersion  = $ToolVersion
  generated    = (Get-Date).ToString('o')
  scanned      = $perFile.ToArray()
  filesScanned = $targets.Count
  uniqueRuns   = $unique.Count
  maxScanMB    = $MaxScanMB
  markers      = $markers
  counts       = $counts
  evidence     = [ordered]@{
    registry = $cats.registry.ToArray()
    paths    = $cats.paths.ToArray()
    logFiles = $cats.logFiles.ToArray()
    services = $cats.services.ToArray()
    eventLog = $cats.eventLog.ToArray()
    urls     = $cats.urls.ToArray()
    guids    = $cats.guids.ToArray()
    mutexes  = $cats.mutexes.ToArray()
    errors   = $cats.errors.ToArray()
    other    = $cats.other.ToArray()
  }
  notes = @(
    'Strings are evidence of capability, not proof of behaviour. Confirm each lead at runtime (probe plan / Procmon / registry diff).',
    'UTF-16LE runs are included because Windows binaries store most path and user-facing strings wide.',
    'Files above MaxScanMB are scanned at head and tail only.',
    'A registry path in the binary may be read-only, conditional or legacy - never assume it is written.',
    'On a compressed self-extracting installer the payload is compressed: extract it first (7z/innoextract) and mine the extracted files instead.'
  )
}

$jsonPath = Join-Path $OutDir 'strings-evidence.json'
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Strings evidence')
[void]$md.AppendLine('')
[void]$md.AppendLine("Scanned $($targets.Count) file(s), $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').")
[void]$md.AppendLine('')
$activeMarkers = @($markers.Keys | Where-Object { $markers[$_] })
if ($activeMarkers.Count -gt 0) { [void]$md.AppendLine('Markers: ' + ($activeMarkers -join ', ')) }
[void]$md.AppendLine('')
foreach ($k in @('registry', 'paths', 'logFiles', 'services', 'eventLog', 'urls', 'guids', 'mutexes', 'errors')) {
  $list = $cats[$k]
  if ($list.Count -eq 0) { continue }
  [void]$md.AppendLine("## $k ($($list.Count))")
  [void]$md.AppendLine('')
  [void]$md.AppendLine('```')
  foreach ($s in ($list | Select-Object -First 60)) { [void]$md.AppendLine($s) }
  [void]$md.AppendLine('```')
  [void]$md.AppendLine('')
}
$mdPath = Join-Path $OutDir 'strings-evidence.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

[ordered]@{
  status       = 'ok'
  outDir       = $OutDir
  evidence     = $jsonPath
  readme       = $mdPath
  filesScanned = $targets.Count
  uniqueRuns   = $unique.Count
  markers      = $markers
  counts       = $counts
  topRegistry  = $cats.registry.ToArray() | Select-Object -First 8
  topPaths     = $cats.paths.ToArray() | Select-Object -First 8
  topLogs      = $cats.logFiles.ToArray() | Select-Object -First 8
} | ConvertTo-Json -Depth 6
