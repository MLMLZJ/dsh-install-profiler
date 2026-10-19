<#
.SYNOPSIS
  Classify a Windows installer/package file WITHOUT executing it.

.DESCRIPTION
  Reads magic bytes, PE headers and a bounded set of embedded ASCII markers to
  decide whether a file is an MSI, an EXE installer built by NSIS / Inno Setup /
  InstallShield / WiX Burn / InstallAware / Wise / Advanced Installer, an
  Electron-Squirrel bundle, a self-extracting archive, an MSIX/APPX package or a
  .NET bundle. Emits a JSON report on stdout, including the safest extraction
  command for the detected type.

  Read-only. The target file is opened for reading and never launched.

.PARAMETER Path
  Installer or package file to classify.

.PARAMETER MaxScanMB
  Files larger than this are marker-scanned only at the head and tail (64 MB
  each). Default 256.

.PARAMETER SkipHash
  Skip SHA-256 (useful for very large files during triage).

.PARAMETER SkipSignature
  Skip Authenticode verification (verification can touch the network for
  timestamp chains on some systems).

.EXAMPLE
  ./detect-installer.ps1 -Path 'C:\Downloads\setup.exe'

.EXAMPLE
  ./detect-installer.ps1 -Path '.\app.msix' | ConvertFrom-Json
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Path,

  [int]$MaxScanMB = 256,
  [switch]$SkipHash,
  [switch]$SkipSignature
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'

function New-Report {
  param([string]$Status, [string]$Message)
  [ordered]@{
    tool        = 'detect-installer'
    toolVersion = $ToolVersion
    generated   = (Get-Date).ToString('o')
    status      = $Status
    message     = $Message
    path        = $null
    sizeBytes   = $null
    sha256      = $null
    magic       = $null
    container   = $null
    pe          = $null
    signature   = $null
    versionInfo = $null
    candidates  = @()
    extraction  = @()
    notes       = @()
  }
}

function Fail-Json {
  param([string]$Message)
  $r = New-Report -Status 'error' -Message $Message
  $r | ConvertTo-Json -Depth 8
  exit 2
}

# ---------------------------------------------------------------- PE parsing
function Get-PeInfo {
  param([byte[]]$Head)
  if ($Head.Length -lt 0x40) { return $null }
  if ($Head[0] -ne 0x4D -or $Head[1] -ne 0x5A) { return $null }   # 'MZ'
  $lfanew = [BitConverter]::ToInt32($Head, 0x3C)
  if ($lfanew -lt 0 -or ($lfanew + 0x18) -ge $Head.Length) { return $null }
  if ($Head[$lfanew] -ne 0x50 -or $Head[$lfanew + 1] -ne 0x45) { return $null }  # 'PE'
  $machine     = [BitConverter]::ToUInt16($Head, $lfanew + 4)
  $sections    = [BitConverter]::ToUInt16($Head, $lfanew + 6)
  $timestamp   = [BitConverter]::ToUInt32($Head, $lfanew + 8)
  $optOff      = $lfanew + 0x18
  if (($optOff + 2) -ge $Head.Length) { return $null }
  $magic       = [BitConverter]::ToUInt16($Head, $optOff)
  $is64        = ($magic -eq 0x20B)
  $subsystem   = 0
  $subOff      = $optOff + 68
  if (($subOff + 2) -le $Head.Length) { $subsystem = [BitConverter]::ToUInt16($Head, $subOff) }
  $ddOff       = $optOff + $(if ($is64) { 112 } else { 96 })
  $hasClr      = $false
  $clrOff      = $ddOff + (14 * 8)
  if (($clrOff + 8) -le $Head.Length) {
    $clrRva  = [BitConverter]::ToUInt32($Head, $clrOff)
    $clrSize = [BitConverter]::ToUInt32($Head, $clrOff + 4)
    $hasClr  = ($clrRva -ne 0 -and $clrSize -ne 0)
  }
  $arch = switch ($machine) {
    0x014C  { 'x86' }
    0x8664  { 'x64' }
    0xAA64  { 'arm64' }
    0x01C4  { 'armv7' }
    default { ('unknown-0x{0:X}' -f $machine) }
  }
  $sub = switch ($subsystem) {
    1 { 'native' }
    2 { 'windows-gui' }
    3 { 'console' }
    default { "other-$subsystem" }
  }
  $built = $null
  try { $built = ([datetimeoffset]::FromUnixTimeSeconds($timestamp)).ToString('u') } catch { }
  [ordered]@{
    arch        = $arch
    is64        = $is64
    subsystem   = $sub
    sections    = $sections
    dotnetClr   = $hasClr
    linkTimeUtc = $built
  }
}

# ------------------------------------------------------- bounded string scan
function Get-MarkerHits {
  param([string]$File, [string[]]$Needles, [long]$LimitBytes)

  $enc = [Text.Encoding]::GetEncoding(28591)   # latin1: 1 byte -> 1 char
  $len = (Get-Item -LiteralPath $File).Length
  $whole = ($LimitBytes -le 0 -or $len -le $LimitBytes)

  $ranges = @()
  if ($whole) {
    $ranges += , @(0L, $len)
  }
  else {
    $edge = [Math]::Min($len, 64L * 1024 * 1024)
    $ranges += , @(0L, $edge)
    $ranges += , @(($len - $edge), $edge)
  }

  $maxNeedle = ($Needles | Measure-Object -Property Length -Maximum).Maximum
  $overlap   = [Math]::Max(0, $maxNeedle - 1)
  $hits      = @{}
  $chunkSize = 8 * 1024 * 1024

  $fs = [IO.File]::Open($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($range in $ranges) {
      $start = [long]$range[0]; $count = [long]$range[1]
      $fs.Position = $start
      $remaining = $count
      $carry = ''
      while ($remaining -gt 0) {
        $want = [int][Math]::Min([long]$chunkSize, $remaining)
        $buf  = New-Object byte[] $want
        $read = $fs.Read($buf, 0, $want)
        if ($read -le 0) { break }
        $text = $carry + $enc.GetString($buf, 0, $read)
        foreach ($n in $Needles) {
          if (-not $hits.ContainsKey($n) -and $text.IndexOf($n, [StringComparison]::Ordinal) -ge 0) {
            $hits[$n] = $true
          }
        }
        $remaining -= $read
        if ($overlap -gt 0 -and $text.Length -gt $overlap) {
          $carry = $text.Substring($text.Length - $overlap)
        }
        else { $carry = '' }
      }
    }
  }
  finally { $fs.Dispose() }

  return $hits
}

# ------------------------------------------------------------------- main
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
  Fail-Json "File not found: $Path"
}
$item = Get-Item -LiteralPath $Path
$full = $item.FullName
$report = New-Report -Status 'ok' -Message 'classified'
$report.path = $full
$report.sizeBytes = $item.Length

$head = New-Object byte[] ([int][Math]::Min(16384, $item.Length))
$fs0 = [IO.File]::OpenRead($full)
try { [void]$fs0.Read($head, 0, $head.Length) } finally { $fs0.Dispose() }

$hex16 = ($head[0..([Math]::Min(15, $head.Length - 1))] | ForEach-Object { $_.ToString('X2') }) -join ' '
$report.magic = $hex16

$isOle  = ($head.Length -ge 8 -and $head[0] -eq 0xD0 -and $head[1] -eq 0xCF -and $head[2] -eq 0x11 -and $head[3] -eq 0xE0)
$isZip  = ($head.Length -ge 4 -and $head[0] -eq 0x50 -and $head[1] -eq 0x4B -and ($head[2] -eq 0x03 -or $head[2] -eq 0x05 -or $head[2] -eq 0x07))
$isMz   = ($head.Length -ge 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A)
$ext    = [IO.Path]::GetExtension($full).ToLowerInvariant()

if (-not $SkipHash) {
  try { $report.sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash } catch { $report.notes += "SHA-256 failed: $($_.Exception.Message)" }
}

if (-not $SkipSignature) {
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $full
    $report.signature = [ordered]@{
      status      = [string]$sig.Status
      signer      = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
      issuer      = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { $null }
      thumbprint  = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
      timeStamped = [bool]($sig.TimeStamperCertificate)
    }
  }
  catch { $report.notes += "Authenticode check failed: $($_.Exception.Message)" }
}

if ($isMz) {
  try {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
    $report.versionInfo = [ordered]@{
      company     = $vi.CompanyName
      product     = $vi.ProductName
      description = $vi.FileDescription
      fileVersion = $vi.FileVersion
      productVer  = $vi.ProductVersion
      original    = $vi.OriginalFilename
      internal    = $vi.InternalName
    }
  }
  catch { }
  $report.pe = Get-PeInfo -Head $head
}

$candidates = @()

function Add-Candidate {
  param([string]$Type, [int]$Score, [string[]]$Evidence, [string]$Family = $null)
  $script:candidates += [ordered]@{
    type       = $Type
    family     = $Family
    confidence = if ($Score -ge 6) { 'high' } elseif ($Score -ge 3) { 'medium' } else { 'low' }
    score      = $Score
    evidence   = $Evidence
  }
}

# ---- container-level classification -------------------------------------
$zipEntries = @()
if ($isZip) {
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $za = [IO.Compression.ZipFile]::OpenRead($full)
    try { $zipEntries = @($za.Entries | ForEach-Object { $_.FullName }) } finally { $za.Dispose() }
  }
  catch { $report.notes += "ZIP entry listing failed: $($_.Exception.Message)" }

  if ($zipEntries -contains 'AppxManifest.xml' -or ($zipEntries | Where-Object { $_ -match '^AppxManifest\.xml$' })) {
    $report.container = 'zip'
    Add-Candidate -Type 'msix-appx' -Score 9 -Evidence @('AppxManifest.xml present in archive') -Family 'MSIX/APPX'
  }
  elseif ($zipEntries | Where-Object { $_ -match '(^|/)app\.asar$' }) {
    $report.container = 'zip'
    Add-Candidate -Type 'electron-asar-zip' -Score 8 -Evidence @('resources/app.asar present') -Family 'Electron'
  }
  elseif ($zipEntries | Where-Object { $_ -match '\.nuspec$' }) {
    $report.container = 'zip'
    Add-Candidate -Type 'nuget-package' -Score 7 -Evidence @('.nuspec present') -Family 'NuGet/Squirrel'
  }
  else {
    $report.container = 'zip'
    Add-Candidate -Type 'zip-archive' -Score 2 -Evidence @('PK zip signature, no appx/asar marker') -Family 'archive'
  }
}

if ($isOle) {
  $report.container = 'ole-compound'
  if ($ext -in @('.msi', '.mst', '.msp')) {
    Add-Candidate -Type 'msi' -Score 9 -Evidence @("OLE compound file with $ext extension (Windows Installer database)") -Family 'MSI'
  }
  else {
    Add-Candidate -Type 'ole-channel' -Score 4 -Evidence @('OLE compound file, extension not .msi/.mst/.msp - could be MSI renamed or an Office/legacy container') -Family 'OLE'
  }
}

if ($isMz -and -not $isZip) {
  $report.container = 'pe'
}

# ---- marker scan (PE or self-extracting payload) -------------------------
$maxBytes = if ($MaxScanMB -gt 0) { [long]$MaxScanMB * 1MB } else { 0L }
if ($isMz -or $isZip -or $isOle) {
  $markers = [ordered]@{
    'NSIS'              = @('Nullsoft.NSIS', 'Nullsoft Install System', 'NullsoftInst')
    'InnoSetup'         = @('Inno Setup', 'InnoSetupLdr', 'Inno Setup Setup Data')
    'InstallShield'     = @('InstallShield', 'ISSetupStream', 'InstallShield Software Corporation')
    'WiXBurn'           = @('.wixburn', 'WixBundle', 'BurnEngine', 'wixburn')
    'Squirrel'          = @('SquirrelAwareVersion', 'Squirrel', 'Update.exe')
    'Electron'          = @('app.asar', 'electron.asar', 'chrome_100_percent.pak', 'electron.exe')
    'InstallAware'      = @('InstallAware')
    'Wise'              = @('Wise Installation', 'WiseInst')
    'SetupFactory'      = @('Setup Factory')
    'AdvancedInstaller' = @('Advanced Installer', 'Caphyon')
    'IExpress'          = @('IExpress', 'wextract.exe')
    '7zSFX'             = @('7zS.sfx', '7-Zip SFX', '7zSFX')
    'RarSFX'            = @('WinRAR SFX', 'RarSFX')
    'PyInstaller'       = @('PyInstaller', '_MEIPASS')
    'Chocolatey'        = @('chocolatey', '.nupkg')
    'WindowsInstaller'  = @('Windows Installer', 'MsiExec.exe')
  }
  try {
    $hits = Get-MarkerHits -File $full -Needles @($markers.Values | ForEach-Object { $_ }) -LimitBytes $maxBytes
  }
  catch {
    $hits = @{}
    $report.notes += "Marker scan failed: $($_.Exception.Message)"
  }

  $found = @{}
  foreach ($family in $markers.Keys) {
    $ev = @()
    foreach ($m in $markers[$family]) {
      if ($hits.ContainsKey($m)) { $ev += $m }
    }
    if ($ev.Count -gt 0) { $found[$family] = $ev }
  }

  # weights: family-specific markers outrank generic ones
  $weights = @{
    'NSIS' = 5; 'InnoSetup' = 5; 'InstallShield' = 4; 'WiXBurn' = 6; 'Squirrel' = 4;
    'Electron' = 3; 'InstallAware' = 5; 'Wise' = 4; 'SetupFactory' = 5; 'AdvancedInstaller' = 5;
    'IExpress' = 4; '7zSFX' = 5; 'RarSFX' = 5; 'PyInstaller' = 5; 'Chocolatey' = 3; 'WindowsInstaller' = 2
  }
  $typeMap = @{
    'NSIS' = 'nsis'; 'InnoSetup' = 'inno-setup'; 'InstallShield' = 'installshield'; 'WiXBurn' = 'wix-burn';
    'Squirrel' = 'squirrel'; 'Electron' = 'electron'; 'InstallAware' = 'installaware'; 'Wise' = 'wise';
    'SetupFactory' = 'setup-factory'; 'AdvancedInstaller' = 'advanced-installer'; 'IExpress' = 'iexpress';
    '7zSFX' = '7z-sfx'; 'RarSFX' = 'rar-sfx'; 'PyInstaller' = 'pyinstaller'; 'Chocolatey' = 'chocolatey-nupkg';
    'WindowsInstaller' = 'msi-launcher'
  }
  foreach ($family in $found.Keys) {
    Add-Candidate -Type $typeMap[$family] -Score $weights[$family] -Evidence $found[$family] -Family $family
  }

  if ($report.pe -and $report.pe.dotnetClr) {
    Add-Candidate -Type 'dotnet-application' -Score 6 -Evidence @('PE optional header declares a CLR runtime data directory') -Family '.NET'
  }
}

# extension hints (weak evidence, only when nothing strong was found)
$extHint = @{
  '.msi' = 'msi'; '.mst' = 'msi'; '.msp' = 'msi-patch'; '.msix' = 'msix-appx'; '.appx' = 'msix-appx';
  '.msixbundle' = 'msix-bundle'; '.appxbundle' = 'msix-bundle'; '.msu' = 'windows-update-package';
  '.msixupload' = 'msix-upload'; '.appxupload' = 'msix-upload'
}
if ($extHint.ContainsKey($ext) -and -not ($candidates | Where-Object { $_.type -eq $extHint[$ext] })) {
  Add-Candidate -Type $extHint[$ext] -Score 2 -Evidence @("extension $ext") -Family 'extension-hint'
}

$report.candidates = @($candidates | Sort-Object { $_.score } -Descending)

# ---- extraction plan -----------------------------------------------------
$best = $report.candidates | Select-Object -First 1
$deliverable = 'deliverable/'
$plan = @()
switch ($best.type) {
  'msi' {
    $plan += [ordered]@{ step = 1; method = 'msi-admin-extract'; command = 'msiexec /a "<msi>" /qn TARGETDIR="<dest>"'; notes = 'Administrative install: lays out the full file tree without registering the product.' }
    $plan += [ordered]@{ step = 2; method = 'msi-tables'; command = 'export-msi-tables.ps1 -MsiPath "<msi>" -OutDir "<dest>\msi-tables"'; notes = 'Authoritative registry/service/file/shortcut tables.' }
  }
  'msi-patch' { $plan += [ordered]@{ step = 1; method = 'msi-patch-inspect'; command = 'export-msi-tables.ps1 -MsiPath "<msp>" -OutDir "<dest>"'; notes = 'Patch summary + target product validation.' } }
  'nsis' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = 'Extracts the NSIS payload files; the installer script itself is not recovered by 7z.' } }
  'inno-setup' { $plan += [ordered]@{ step = 1; method = 'innoextract'; command = 'innoextract "<exe>" -d "<dest>"'; notes = 'Preferred. Falls back to 7z x when innoextract is missing.' } }
  'wix-burn' {
    $plan += [ordered]@{ step = 1; method = 'burn-dark'; command = 'dark.exe -x "<dest>" "<exe>"'; notes = 'Needs WiX toolset (dark.exe).' }
    $plan += [ordered]@{ step = 2; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = 'Fallback: extracts the attached container payloads.' }
  }
  'installshield' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = 'Works for many InstallShield builds; some use a CAB stream that 7z only lists. Try "<exe> /s /extract_all:<dest>" as a second option.' } }
  'squirrel' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = 'Then unpack the app-<version>.nupkg with 7z; the app.asar inside is the application code.' } }
  'electron' { $plan += [ordered]@{ step = 1; method = 'asan'; command = 'npx --yes @electron/asar extract "<app.asar>" "<dest>"'; notes = 'Needs Node.js/npx. Falls back to 7z x on the asar.' } }
  'msix-appx' { $plan += [ordered]@{ step = 1; method = 'makeappx'; command = 'makeappx unpack /p "<msix>" /d "<dest>" /o'; notes = 'Needs Windows SDK makeappx. A plain zip extract also works.' } }
  'msix-bundle' { $plan += [ordered]@{ step = 1; method = 'makeappx'; command = 'makeappx unpack /p "<bundle>" /d "<dest>" /o'; notes = 'Unpacks to per-architecture .msix files; repeat for the matching architecture.' } }
  '7z-sfx' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = '7-Zip SFX payload.' } }
  'rar-sfx' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = 'WinRAR SFX payload.' } }
  'iexpress' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<exe>" -o"<dest>" -y'; notes = 'IExpress packages often hold an MSI plus config; recurse with detect-installer on the results.' } }
  'pyinstaller' { $plan += [ordered]@{ step = 1; method = 'pyi-archive_viewer'; command = 'pyi-archive_viewer -l "<exe>"'; notes = 'Lists the Python archive; extraction needs pyinstxtractor.' } }
  'zip-archive' { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z x "<zip>" -o"<dest>" -y'; notes = 'Generic archive.' } }
  default { $plan += [ordered]@{ step = 1; method = 'archive-extract'; command = '7z l "<file>"'; notes = 'List first; recurse on the extracted payload with detect-installer.' } }
}
$report.extraction = $plan

if ($report.candidates.Count -eq 0) {
  $report.notes += 'No known installer family matched. Try: 7z l "<file>" and inspect the payload manually.'
}

if ($report.pe -and $report.pe.subsystem -eq 'windows-gui' -and $report.candidates.Count -eq 1 -and $report.candidates[0].score -le 3) {
  $report.notes += 'A GUI PE with no installer markers may be a portable application or a custom launcher rather than an installer.'
}

$report | ConvertTo-Json -Depth 10
