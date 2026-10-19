# Install Profiler — a switchable DSH skill plugin

A DeepSeek Harness **bundle** that registers one model-invocable skill,
`install-profiler`, in the profile-global skill layer. It teaches the agent to
turn a Windows installer (or an installed application) into an evidence-backed
map — install paths, registry writes, services, config files, logs, Event Log
sources — and then diagnose install/startup/runtime faults with a
symptom→cause→mechanism→fix chain.

Disable the row (or the whole bundle) in Plugin Manager and the skill disappears
from the session catalog; enable it again and it comes back, re-reading
`SKILL.md` so edits apply without restarting Harness.

## What it does

- **Static profiling, no execution.** Classifies MSI / NSIS / Inno Setup /
  InstallShield / WiX Burn / Squirrel / Electron / MSIX / SFX packages, then
  extracts the payload and reads the install definition.
- **MSI is read as a database.** `export-msi-tables.ps1` drives the built-in
  `WindowsInstaller.Installer` COM server — no lessmsi needed — and emits
  `profile.json` plus one CSV per table (`Directory`, `File`, `Registry`,
  `ServiceInstall`, `ServiceControl`, `Shortcut`, `Environment`, `CustomAction`,
  `InstallExecuteSequence`, `LaunchCondition`, `Upgrade`, …).
- **Runtime state, read-only.** `collect-state.ps1` gathers uninstall entries,
  live services (with binary existence), drivers, startup items, scheduled
  tasks, Event Log source registrations, app data/log dirs, WER crash folders,
  MSI logs and pending-reboot flags, and flags concrete anomalies.
- **Fault playbook.** `references/fault-playbook.md` carries the MSI error-code
  table, the service-startup triage order, crash evidence sources, the
  upgrade/repair/uninstall failure matrix, and how to read a before/after diff —
  with the mechanism behind each one.

## Where this stops and reverse-engineering starts

The two skills are complementary, not overlapping:

- **`install-profiler`** answers *what should be observed* — install layout, registry, services, logs, event sources, and which of them to watch at runtime.
- **`reverse-engineering`** answers *how to read the code* — .NET (`ilspycmd`), Electron (`asar`), native (`objdump`/`rizin`/Ghidra).

When an installer is itself a .NET bootstrap or an Electron/Squirrel app and strings are not enough, `build-handoff.ps1` packages the handoff: it classifies the branch (dotnet / electron / pyinstaller / native / packed), lists the facts already established, turns the gaps into branch-specific questions, emits the exact decompile commands with tool availability, and writes `handoff.md` + `handoff.json`. The receiving skill is told not to redo discovery and to tag every answer `[verified]/[inferred]/[unknown]`.

`mine-strings.ps1` covers the common case without needing any decompiler; its output is evidence of capability, not proof of behaviour.

## The loop: static map → dynamic probe

Static facts say what *should* happen; the fault is in what *actually* happens.
The profile is the aiming device, not the deliverable:

```
export-msi-tables   → profile.json          (what the installer promises)
build-probe-plan    → probe-plan.json/.md   (exactly what to watch, and where)
capture-snapshot    → before.json           (baseline)
   … reproduce ONE failing action …
capture-snapshot    → after.json
diff-snapshots      → findings.json/.md     (errors/warnings anchored to promises)
```

`build-probe-plan` resolves MSI directory roots to real machine paths, lists the
registry keys worth snapshotting (ARP, services, EventLog, Run, COM), states each
service's expected start type/account against its live state, names the process
names and config/log candidates, emits Event Log providers/IDs and Procmon filter
expressions, and produces a check list with the command and expectation for each.

`diff-snapshots` ranks what moved: files added/removed/modified under watched
paths, registry values created/changed/deleted, service state changes, processes
appearing/exiting, ports opening/closing, new Event Log entries, new WER crash
folders.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/probe-tools.ps1` | Which extractor/inspector tools exist (read-only, ~2 s) |
| `scripts/detect-installer.ps1` | Classify the package + emit the extraction plan |
| `scripts/mine-strings.ps1` | No MSI database? Mine registry paths, log paths, services, URLs, GUIDs and error templates out of the binary (ASCII + UTF-16LE) |
| `scripts/build-handoff.ps1` | Package the evidence into a paste-ready brief for the reverse-engineering skill: branch, established facts, questions, commands, evidence contract |
| `scripts/export-msi-tables.ps1` | MSI tables → JSON/CSV + derived profile |
| `scripts/collect-state.ps1` | Read-only runtime snapshot for an installed app |
| `scripts/build-probe-plan.ps1` | Static profile → targeted dynamic-observation plan |
| `scripts/capture-snapshot.ps1` | Execute the plan: files, registry, services, processes, ports, events |
| `scripts/diff-snapshots.ps1` | Before/after diff → ranked findings with mechanism hints |

Invoke with `powershell -NoProfile -ExecutionPolicy Bypass -File <path> …`
(Windows blocks local scripts by default).

## Install (once)

From a DSH session with Full access or approval:

```
plugin_manager action=install_bundle target=<absolute path to this directory>
```

Confirm with approval-free `cordis_inspect_query` on `Config`, filtered by
`@local/dsh-install-profiler` (row id `install-profiler`).

## On / off

- `plugin_manager action=set_plugin target=install-profiler enabled=false`
- `plugin_manager action=set_plugin target=install-profiler enabled=true`
- `plugin_manager action=remove_bundle target=@local/dsh-install-profiler`

## Layout

```
package.json                 bundle manifest (dsh.bundle.patch)
cordis.patch.yml             inserts row id `install-profiler`
index.js                     registers the skill via ctx.skills.register()
locale/en.json, zh.json      Plugin Manager title/description
icon.svg                     original icon
skills/install-profiler/
  SKILL.md                   the instructions the model loads
  references/fault-playbook.md
  assets/report-template.md
  assets/profile.schema.json
scripts/*.ps1                the four tools
```

## Verified during development

- `detect-installer` on a 30 MB Chinese setup EXE → `7z-sfx`, medium confidence,
  correct extraction command.
- `export-msi-tables` on `Microsoft Visual C++ 2005 Redistributable` (96 files,
  492 registry writes, 749 directory rows), `Adobe Acrobat DC (64-bit)`
  (6406 files, 3306 registry rows, 1 service, 6 shortcuts, 46 s) and the Office
  Click-to-Run licensing MSI (service account `NT AUTHORITY\NetworkService`).
- `collect-state` on an installed app → uninstall entry, data dir, log files,
  pending-reboot flag.
- `mine-strings` on `7zFM.exe` → 4239 unique runs in 1 s, recovered `Software\7-Zip\FM\Columns` and the shell-extension key without any decompiler; on a 30 MB self-extracting installer it runs in ~8 s and correctly yields little, because the payload is compressed (the doc says to extract first).
- `build-handoff` on a PyInstaller bundle → branch `pyinstaller`, 7 targeted
  questions, tool readiness (`pyi-archive_viewer`, `python`), SHA256 of the main
  executable; on `7zFM.exe` → `native` branch with objdump/rizin availability.
- `build-probe-plan` on the Acrobat profile → 85 watched paths (logical MSI
  directories resolved to real ones, incl. `ProgramFilesFolder` → `C:\Program
  Files`), 300 registry keys, 1 service with expected state, 32 process names,
  14 checks with commands.
- `capture-snapshot` + `diff-snapshots` on a controlled lab: a deleted file in an
  install root reported as `error/files/removed`, a new log file as
  `info/files/added`, an edited config as `info/files/modified`, a new HKCU value
  as `info/registry/value-created`.
- Start-type mapping cross-checked against a live service (`Start=2` → auto).

## Safety

The skill never runs the installer on the host and never modifies the target
machine. Repair commands are proposed, not executed, until the user explicitly
confirms the machine and the action. It refuses license/DRM circumvention and
credential extraction; profiling is limited to authorized targets.

## Known traps baked into the code

PowerShell 5.1 quirks are documented in `SKILL.md` so the agent doesn't rediscover
them: `[void]` before MSI COM `Execute()`/`Close()`, no `$var` name that collides
with a `[switch]` parameter, `Record.FieldCount` unavailable via late binding,
`Directory.DefaultDir` being `target:source`, and `-File` not splitting comma lists.
