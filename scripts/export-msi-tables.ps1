<#
.SYNOPSIS
  Export an MSI database's install tables to JSON/CSV and derive a structured
  installation profile - no installation, no execution of the package.

.DESCRIPTION
  Opens the .msi read-only through the WindowsInstaller COM automation server and
  reads the tables that answer "what does this installer actually do":

    Property, Directory, Component, File, Feature, FeatureComponents, Registry,
    RemoveRegistry, ServiceInstall, ServiceControl, MsiServiceConfig,
    MsiServiceConfigFailureActions, Shortcut, Environment, CustomAction,
    InstallExecuteSequence, InstallUISequence, LaunchCondition, Upgrade, Media

  Writes one CSV per table, a manifest, and profile.json with resolved install
  paths, registry writes, services, shortcuts, custom actions and upgrade rules.

  Read-only. Works on an installed product's cached MSI too
  (C:\Windows\Installer\*.msi) when the original setup source is gone.

.PARAMETER MsiPath
  Path to the .msi (or .msp patch) file.

.PARAMETER OutDir
  Output directory. Default: .\msi-profile

.PARAMETER Tables
  Restrict the export to these table names.

.PARAMETER AllTables
  Export every table in the database (Binary/Icon data is skipped, only listed).

.PARAMETER SkipHash
  Skip SHA-256 of the source file.

.EXAMPLE
  ./export-msi-tables.ps1 -MsiPath 'C:\Downloads\app.msi' -OutDir '.\re\case\extracted\msi'

.EXAMPLE
  ./export-msi-tables.ps1 -MsiPath 'C:\Windows\Installer\18d57057.msi' -AllTables
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$MsiPath,

  [string]$OutDir = '.\msi-profile',
  [string[]]$Tables,
  [switch]$AllTables,
  [switch]$SkipHash
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'

# `powershell -File script.ps1 -Tables A,B` passes one comma-joined string;
# normalize so both array and CLI usage work.
if ($Tables) {
  $Tables = @($Tables | ForEach-Object { ([string]$_).Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
  @{ tool = 'export-msi-tables'; status = 'error'; message = "File not found: $MsiPath" } | ConvertTo-Json
  exit 2
}
$src = (Resolve-Path -LiteralPath $MsiPath).Path
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir 'tables') | Out-Null

$Curated = @(
  'Property', 'Directory', 'Component', 'File', 'Feature', 'FeatureComponents',
  'Registry', 'RemoveRegistry', 'ServiceInstall', 'ServiceControl',
  'MsiServiceConfig', 'MsiServiceConfigFailureActions', 'Shortcut', 'Environment',
  'CustomAction', 'InstallExecuteSequence', 'InstallUISequence', 'LaunchCondition',
  'Upgrade', 'Media'
)
$SkipData = @('Binary', 'Icon')

$installer = $null
try { $installer = New-Object -ComObject WindowsInstaller.Installer }
catch {
  @{ tool = 'export-msi-tables'; status = 'error'; message = "WindowsInstaller COM not available: $($_.Exception.Message)" } | ConvertTo-Json
  exit 3
}

$db = $null
try { $db = $installer.OpenDatabase($src, 0) }   # 0 = msiOpenDatabaseModeReadOnly
catch {
  @{ tool = 'export-msi-tables'; status = 'error'; message = "Cannot open MSI database: $($_.Exception.Message)" } | ConvertTo-Json
  exit 4
}

function Get-TableNames {
  param($Database)
  $names = @()
  $view = $Database.OpenView('SELECT `Name` FROM `_Tables`')
  [void]$view.Execute()
  while ($null -ne ($rec = $view.Fetch())) {
    $v = $rec.StringData(1)
    if (-not [string]::IsNullOrEmpty($v)) { $names += $v }
  }
  [void]$view.Close()
  return $names
}

function Get-TableColumns {
  param($Database, [string]$Table)
  $cols = @()
  $sql = 'SELECT `Name` FROM `_Columns` WHERE `Table` = ''{0}'' ORDER BY `Number`' -f $Table
  $view = $Database.OpenView($sql)
  [void]$view.Execute()
  while ($null -ne ($rec = $view.Fetch())) { $cols += $rec.StringData(1) }
  [void]$view.Close()
  return $cols
}

function Read-Table {
  param($Database, [string]$Table, [string[]]$Columns)
  $rows = New-Object System.Collections.Generic.List[object]
  $sql = 'SELECT * FROM `{0}`' -f $Table
  $view = $Database.OpenView($sql)
  try {
    [void]$view.Execute()
    while ($null -ne ($rec = $view.Fetch())) {
      $o = [ordered]@{}
      # MSI Record.FieldCount is not reliably exposed through IDispatch late
      # binding; the _Columns row count is the authoritative field count.
      $n = $Columns.Count
      for ($i = 1; $i -le $n; $i++) {
        $name = if ($i -le $Columns.Count) { $Columns[$i - 1] } else { "Col$i" }
        $o[$name] = $rec.StringData($i)
      }
      $rows.Add([pscustomobject]$o)
    }
  }
  finally { [void]$view.Close() }
  return , $rows
}

# ------------------------------------------------------------------ read all
# NOTE: do not name this variable $allTables - it would collide with the
# [switch]$AllTables script parameter (PowerShell variable names are
# case-insensitive) and assigning an array to a switch throws.
$tableNames = @(Get-TableNames $db)
$wanted = if ($Tables) { $Tables } elseif ($AllTables) { $tableNames } else { $Curated }
$wanted = @($wanted | Where-Object { $tableNames -contains $_ })

$data = @{}
$tableStats = @()
foreach ($t in $wanted) {
  try {
    if ($SkipData -contains $t) {
      $cols = @(Get-TableColumns -Database $db -Table $t)
      $cnt = (Read-Table -Database $db -Table $t -Columns $cols).Count
      $tableStats += [pscustomobject][ordered]@{ table = $t; rows = $cnt; exported = $false; reason = 'binary data skipped' }
      continue
    }
    $cols = @(Get-TableColumns -Database $db -Table $t)
    if ($cols.Count -eq 0) {
      $tableStats += [pscustomobject][ordered]@{ table = $t; rows = 0; exported = $false; reason = 'no column metadata' }
      continue
    }
    $rows = Read-Table -Database $db -Table $t -Columns $cols
    $data[$t] = $rows
    $csv = Join-Path (Join-Path $OutDir 'tables') ("{0}.csv" -f $t)
    if ($rows.Count -gt 0) { $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8 }
    else { "no rows" | Set-Content -LiteralPath $csv -Encoding UTF8 }
    $tableStats += [pscustomobject][ordered]@{ table = $t; rows = $rows.Count; exported = $true; columns = $cols }
  }
  catch {
    $tableStats += [pscustomobject][ordered]@{ table = $t; rows = 0; exported = $false; reason = ($_.Exception.Message + ' @line ' + $_.InvocationInfo.ScriptLineNumber) }
  }
}

function Get-Rows([string]$Name) {
  if ($data.ContainsKey($Name)) { return $data[$Name] }
  return @()
}

# ------------------------------------------------------------ property bag
$props = @{}
foreach ($r in (Get-Rows 'Property')) { $props[[string]$r.Property] = [string]$r.Value }

# ---------------------------------------------------------- directory tree
$dirRows = Get-Rows 'Directory'
$dirMap = @{}
foreach ($r in $dirRows) { $dirMap[[string]$r.Directory] = $r }

function Get-DirLongName([string]$DefaultDir) {
  if ([string]::IsNullOrEmpty($DefaultDir)) { return '' }
  # DefaultDir syntax is "target:source" and each side may be "short|long".
  $target = $DefaultDir
  $colon = $target.IndexOf(':')
  if ($colon -ge 0) { $target = $target.Substring(0, $colon) }
  if ($target -eq '.') { return '' }
  if ($target.Contains('|')) { return $target.Split('|')[-1] }
  return $target
}

$dirPathCache = @{}
function Resolve-DirPath([string]$Id, [int]$Depth = 0) {
  if ([string]::IsNullOrEmpty($Id)) { return '' }
  if ($Id -eq 'TARGETDIR') { return '' }
  if ($dirPathCache.ContainsKey($Id)) { return $dirPathCache[$Id] }
  if ($Depth -gt 40) { return $Id }
  $row = $dirMap[$Id]
  if ($null -eq $row) { $dirPathCache[$Id] = $Id; return $Id }
  $self = Get-DirLongName ([string]$row.DefaultDir)
  $parentId = [string]$row.Directory_Parent
  if ([string]::IsNullOrEmpty($parentId)) { $p = '' } else { $p = Resolve-DirPath $parentId ($Depth + 1) }
  if ([string]::IsNullOrEmpty($self)) { $path = $p }
  elseif ([string]::IsNullOrEmpty($p)) { $path = $self }
  else { $path = $p + '\' + $self }
  $dirPathCache[$Id] = $path
  return $path
}

$dirPaths = @()
foreach ($r in $dirRows) {
  $id = [string]$r.Directory
  $dirPaths += [pscustomobject][ordered]@{
    id     = $id
    parent = [string]$r.Directory_Parent
    path   = (Resolve-DirPath $id)
    source = 'Directory table'
  }
}

# folder property roots that resolve to machine-specific locations
$folderProps = @{
  'ProgramFilesFolder'   = "$env:ProgramFiles"
  'ProgramFiles64Folder' = "${env:ProgramFiles}"
  'ProgramFilesFolderX86' = "${env:ProgramFiles(x86)}"
  'CommonFilesFolder'    = "${env:CommonProgramFiles}"
  'CommonFiles64Folder'  = "${env:CommonProgramFiles}"
  'DesktopFolder'        = [Environment]::GetFolderPath('Desktop')
  'ProgramMenuFolder'    = [Environment]::GetFolderPath('Programs')
  'StartMenuFolder'      = [Environment]::GetFolderPath('StartMenu')
  'StartupFolder'        = [Environment]::GetFolderPath('Startup')
  'AppDataFolder'        = [Environment]::GetFolderPath('ApplicationData')
  'LocalAppDataFolder'   = [Environment]::GetFolderPath('LocalApplicationData')
  'PersonalFolder'       = [Environment]::GetFolderPath('MyDocuments')
  'FontsFolder'          = "$env:windir\Fonts"
  'WindowsFolder'        = "$env:windir"
  'SystemFolder'         = "$env:windir\System32"
  'System64Folder'       = "$env:windir\System32"
}

# -------------------------------------------------------------- file/component
$fileRows = Get-Rows 'File'
$compRows = Get-Rows 'Component'
$compFile = @{}
foreach ($f in $fileRows) { $compFile[[string]$f.Component_] = $f }
$compDir = @{}
foreach ($c in $compRows) { $compDir[[string]$c.Component] = [string]$c.Directory_ }

function Get-FilePath($FileRow) {
  $fileName = [string]$FileRow.FileName
  if ($fileName.Contains('|')) { $fileName = $fileName.Split('|')[-1] }
  $comp = [string]$FileRow.Component_
  $dirId = $compDir[$comp]
  $dirPath = if ($dirId) { Resolve-DirPath $dirId } else { '' }
  if ($dirPath) { return ($dirPath + '\' + $fileName) } else { return $fileName }
}

$files = @()
foreach ($f in $fileRows) {
  $size = 0L
  [void][long]::TryParse([string]$f.FileSize, [ref]$size)
  $files += [pscustomobject][ordered]@{
    file     = [string]$f.File
    name     = (Get-DirLongName ([string]$f.FileName))
    size     = $size
    version  = [string]$f.Version
    component= [string]$f.Component_
    path     = (Get-FilePath $f)
    attributes = [string]$f.Attributes
  }
}
$filesTotal = 0L
foreach ($f in $files) { $filesTotal += [long]$f.size }

# ------------------------------------------------------------------- registry
$rootMap = @{ '-1' = 'HKEY_LOCAL_MACHINE'; '0' = 'HKEY_CLASSES_ROOT'; '1' = 'HKEY_CURRENT_USER'; '2' = 'HKEY_LOCAL_MACHINE'; '3' = 'HKEY_USERS' }
$registry = @()
foreach ($r in (Get-Rows 'Registry')) {
  $root = [string]$r.Root
  $rootName = if ($rootMap.ContainsKey($root)) { $rootMap[$root] } else { "ROOT-$root" }
  $registry += [pscustomobject][ordered]@{
    root      = $rootName
    key       = [string]$r.Key
    name      = [string]$r.Name
    value     = [string]$r.Value
    component = [string]$r.Component_
    fullPath  = ($rootName + '\' + ([string]$r.Key).TrimStart('\'))
  }
}
$eventLogRegs = @($registry | Where-Object { $_.key -match 'EventLog' })

# ------------------------------------------------------------------- services
$startMap = @{ '0' = 'boot'; '1' = 'system'; '2' = 'auto'; '3' = 'demand (manual)'; '4' = 'disabled' }
$services = @()
foreach ($s in (Get-Rows 'ServiceInstall')) {
  $comp = [string]$s.Component_
  $file = $compFile[$comp]
  $binPath = if ($file) { Get-FilePath $file } else { $null }
  $services += [pscustomobject][ordered]@{
    name          = [string]$s.Name
    displayName   = [string]$s.DisplayName
    description   = [string]$s.Description
    startType     = [string]$s.StartType
    startTypeName = $(if ($startMap.ContainsKey([string]$s.StartType)) { $startMap[[string]$s.StartType] } else { "unknown-$($s.StartType)" })
    serviceType   = [string]$s.ServiceType
    startName     = [string]$s.StartName
    errorControl  = [string]$s.ErrorControl
    component     = $comp
    binaryPath    = $binPath
    arguments     = [string]$s.Arguments
  }
}
$serviceControl = @()
foreach ($s in (Get-Rows 'ServiceControl')) {
  $serviceControl += [pscustomobject][ordered]@{
    name    = [string]$s.Name
    event   = [string]$s.Event
    wait    = [string]$s.Wait
    component = [string]$s.Component_
  }
}
$serviceConfig = @()
foreach ($s in (Get-Rows 'MsiServiceConfig')) {
  $serviceConfig += [pscustomobject][ordered]@{ name = [string]$s.Name; configType = [string]$s.ConfigType; argument = [string]$s.Argument; component = [string]$s.Component_ }
}
$serviceRecovery = @()
foreach ($s in (Get-Rows 'MsiServiceConfigFailureActions')) {
  $serviceRecovery += [pscustomobject][ordered]@{ name = [string]$s.Name; resetPeriod = [string]$s.ResetPeriod; reboot = [string]$s.RebootMessage; command = [string]$s.Command; actions = [string]$s.Actions; component = [string]$s.Component_ }
}

# ------------------------------------------------------------------ shortcuts
$shortcuts = @()
foreach ($s in (Get-Rows 'Shortcut')) {
  $dirId = [string]$s.Directory_
  $shortcuts += [pscustomobject][ordered]@{
    name      = (Get-DirLongName ([string]$s.Name))
    directory = $dirId
    dirPath   = (Resolve-DirPath $dirId)
    target    = [string]$s.Target
    arguments = [string]$s.Arguments
    component = [string]$s.Component_
  }
}

# ------------------------------------------------------------- custom actions
$caTypeMap = {
  param([string]$t)
  $n = 0; [void][int]::TryParse($t, [ref]$n)
  $base = $n -band 0x3F
  switch ($base) {
    { $_ -in 1, 17, 18, 19, 33, 34, 35, 49, 50, 51 } { return 'exe/dll' }
    { $_ -in 2, 20, 21, 22, 36, 37, 38 } { return 'exe+dll (custom action dll)' }
    { $_ -in 5, 6, 7, 37, 38, 39 } { return 'jscript/vbscript' }
    { $_ -in 0, 4, 16, 32, 48 } { return 'dll (stream)' }
    { $_ -in 3, 5 } { return 'script' }
    default { return "type-$n" }
  }
}
$customActions = @()
foreach ($c in (Get-Rows 'CustomAction')) {
  $t = [string]$c.Type
  $kind = 'unknown'
  try { $kind = & $caTypeMap $t } catch { }
  $customActions += [pscustomobject][ordered]@{
    action  = [string]$c.Action
    type    = $t
    kind    = $kind
    source  = [string]$c.Source
    target  = [string]$c.Target
  }
}

# --------------------------------------------------------------- sequences
$installSeq = @()
foreach ($r in (Get-Rows 'InstallExecuteSequence')) {
  $installSeq += [pscustomobject][ordered]@{ action = [string]$r.Action; condition = [string]$r.Condition; sequence = [string]$r.Sequence }
}
$installSeq = @($installSeq | Sort-Object { if ([string]$_.sequence -match '^\d+$') { [int]$_.sequence } else { 0 } })

# --------------------------------------------------------------- misc tables
$launchConditions = @(Get-Rows 'LaunchCondition' | ForEach-Object { [pscustomobject][ordered]@{ condition = [string]$_.Condition; description = [string]$_.Description } })
$upgrades = @(Get-Rows 'Upgrade' | ForEach-Object { [pscustomobject][ordered]@{ upgradeCode = [string]$_.UpgradeCode; versionMin = [string]$_.VersionMin; versionMax = [string]$_.VersionMax; attributes = [string]$_.Attributes; actionProperty = [string]$_.ActionProperty } })
$environment = @(Get-Rows 'Environment' | ForEach-Object { [pscustomobject][ordered]@{ name = [string]$_.Name; value = [string]$_.Value; component = [string]$_.Component_ } })
$removeRegistry = @(Get-Rows 'RemoveRegistry' | ForEach-Object { [pscustomobject][ordered]@{ root = [string]$_.Root; key = [string]$_.Key; name = [string]$_.Name; component = [string]$_.Component_ } })
$features = @(Get-Rows 'Feature' | ForEach-Object { [pscustomobject][ordered]@{ feature = [string]$_.Feature; title = [string]$_.Title; level = [string]$_.Level; parent = [string]$_.Feature_Parent } })

# ------------------------------------------------------------- arch/version
$template = [string]$props['Template']
$arch = 'x86'
if ($template -match 'x64') { $arch = 'x64' }
elseif ($template -match 'Arm64') { $arch = 'arm64' }
elseif ($props.ContainsKey('ProductLanguage') -and $props['ProductLanguage'] -eq '0') { }

$largest = @($files | Sort-Object { $_.size } -Descending | Select-Object -First 15)

$hash = $null
if (-not $SkipHash) { try { $hash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash } catch { } }

# ------------------------------------------------------------------- output
$profile = [ordered]@{
  tool        = 'export-msi-tables'
  toolVersion = $ToolVersion
  generated   = (Get-Date).ToString('o')
  source      = [ordered]@{ path = $src; sha256 = $hash; sizeBytes = (Get-Item -LiteralPath $src).Length; lastWrite = (Get-Item -LiteralPath $src).LastWriteTimeUtc.ToString('o') }
  product     = [ordered]@{
    name          = $props['ProductName']
    version       = $props['ProductVersion']
    manufacturer  = $props['Manufacturer']
    productCode   = $props['ProductCode']
    upgradeCode   = $props['UpgradeCode']
    language      = $props['ProductLanguage']
    template      = $template
    architecture  = $arch
    allUsers      = $props['ALLUSERS']
    perUser       = $props['MSIINSTALLPERUSER']
    installDirProp= $props['INSTALLDIR']
  }
  summary     = [ordered]@{
    tables           = $tableStats
    directories      = $dirPaths.Count
    components       = $compRows.Count
    files            = $files.Count
    filesTotalBytes  = $filesTotal
    registryWrites   = $registry.Count
    services         = $services.Count
    shortcuts        = $shortcuts.Count
    customActions    = $customActions.Count
    launchConditions = $launchConditions.Count
    upgrades         = $upgrades.Count
    features         = $features.Count
  }
  installPaths = $dirPaths
  folderProperties = $folderProps
  files        = $files
  largestFiles = $largest
  registry     = $registry
  eventLogRegistryWrites = $eventLogRegs
  services     = $services
  serviceControl = $serviceControl
  serviceConfig  = $serviceConfig
  serviceRecovery = $serviceRecovery
  shortcuts    = $shortcuts
  environment  = $environment
  removeRegistry = $removeRegistry
  customActions = $customActions
  installSequence = $installSeq
  launchConditions = $launchConditions
  upgrades     = $upgrades
  features     = $features
  properties   = $props
  notes = @(
    'Paths are logical: folder properties such as ProgramFilesFolder resolve to a machine-specific location, shown in folderProperties.',
    'File sizes and versions come from the File table (install-time truth), not from the files on disk.',
    'Event Log sources are not an MSI table; look for HKLM\SYSTEM\CurrentControlSet\Services\EventLog writes in the Registry table or in the application at first run.',
    'CustomAction "kind" is decoded from the low 6 bits of Type and is approximate for exotic types.'
  )
}

$profilePath = Join-Path $OutDir 'profile.json'
$profile | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $profilePath -Encoding UTF8

$manifest = [ordered]@{
  tool = 'export-msi-tables'
  toolVersion = $ToolVersion
  generated = (Get-Date).ToString('o')
  source = $src
  sha256 = $hash
  outDir = $OutDir
  profile = $profilePath
  tables = $tableStats
  allTableNames = $tableNames
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutDir 'manifest.json') -Encoding UTF8

# stdout summary (compact; full data is on disk)
[ordered]@{
  status   = 'ok'
  outDir   = $OutDir
  profile  = $profilePath
  product  = $profile.product
  summary  = $profile.summary
  installPaths = @($dirPaths | Where-Object { $_.path -notmatch '\\' -or $_.parent -in @('TARGETDIR', '') } | Select-Object -First 12)
} | ConvertTo-Json -Depth 8
