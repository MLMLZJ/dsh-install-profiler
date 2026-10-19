---
name: install-profiler
description: Profile a Windows installer or an installed application from evidence — install layout, registry writes, services/drivers, config files, log locations, Event Log sources — then diagnose install, startup and runtime faults with a symptom→cause decision tree and explain the mechanism behind the fix. 安装包画像与故障排查。
when_to_use: The user supplies an application installer (EXE/MSI/MSIX) or a machine where an app is installed and asks what it installs where, which registry keys, services, config files, logs or event sources it uses, why it fails to install/start/run, or how to fix and prevent it.
---

# Install Profiler

Two jobs, often in sequence:

1. **Profile** — turn an opaque installer into a factual map: what lands where, what it writes to the registry, which services it registers, which config files and logs it uses, which Event Log source it owns.
2. **Diagnose** — start from a symptom, walk an evidence chain, name the mechanism, then propose the minimum fix and a way to verify it.

Never present a guess as a fact. Tag every finding `verified` (observed in a tool's output), `inferred` (reasoned from structure/strings), or `unknown` (needs a VM run or vendor docs).

## Gate 0 — authorization and safety

Proceed when the user owns the software or has permission to analyze it (their own machine, their company's licensed product, an evaluation copy). This skill profiles installation behavior; it does not crack licensing, bypass activation/DRM, defeat anti-tamper, or extract other users' credentials. If the request is really "make this paid app work without a license", refuse and say why.

Hard rules:

- **Never execute the installer or the app on the host.** Static extraction only. Dynamic verification (Procmon, service start, log capture) happens in a disposable VM the user controls — write the commands, let them run it, or ask first.
- **Read-only on the target machine.** Registry reads and file reads only. Any repair command (`sc config`, `reg add`, `icacls`, reinstall) is *proposed*, not executed, unless the user explicitly says to apply it on a machine they own.
- Work inside a case directory; never modify files in `%ProgramFiles%`, `%ProgramData%`, or the installer source.

## Case workspace

One case per investigation, under the session workspace:

```
re\<case-id>\
  inputs\       original installer copy (hash it, keep it read-only)
  extracted\    unzipped/MSI-admin-install/project output
  profile\      profile.json, state.json, per-table CSVs
  evidence\     raw tool stdout/stderr, argv, versions, hashes
  report.md     the deliverable
```

```powershell
New-Item -ItemType Directory -Force re\<case-id>\{inputs,extracted,profile,evidence} | Out-Null
Copy-Item -LiteralPath <installer> re\<case-id>\inputs\
Get-FileHash -Algorithm SHA256 -LiteralPath re\<case-id>\inputs\<file> |
  Tee-Object re\<case-id>\evidence\hashes.txt
```

Windows blocks local scripts by default, so invoke every bundled script with the bypass flag:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\<name>.ps1" <args>
```

(On a `pwsh` 7 host the same flags work; drop nothing — the scripts are written for both.)

## Step 1 — probe the toolchain

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\probe-tools.ps1"
```

Decide from the result, not from assumptions:

| Missing | Consequence |
|---|---|
| `7z` | can't unpack NSIS/Inno/7z-SFX payloads; MSI work is still possible |
| `lessmsi`/`dark`/`innoextract` | use the native fallbacks below; do not install without asking |
| `sigcheck`/`signtool` | Authenticode status still comes from `Get-AuthenticodeSignature` |
| `Procmon`, `accesschk` | no dynamic lane; state that runtime claims are unverified |

`msiexec`, `reg`, `sc`, `wevtutil`, `eventvwr` are built into Windows. **`export-msi-tables.ps1` needs no external tool** — it drives the `WindowsInstaller.Installer` COM server directly, which is the authoritative source for MSI installs and also works on a product's cached MSI in `C:\Windows\Installer\` when the original setup media is lost.

## Step 2 — classify the installer

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\detect-installer.ps1" -Path <installer>
```

Read `candidates[0]` and `extraction[]`. The script scores embedded markers (NSIS, Inno Setup, InstallShield, WiX Burn, Squirrel/Electron, InstallAware, Wise, Advanced Installer, IExpress, 7z/RAR SFX, PyInstaller, MSIX/APPX) and PE headers (architecture, GUI vs console, CLR/.NET). If it returns `confidence: low`, list the archive first (`7z l`) and recurse `detect-installer` on the payload.

Signature status is part of the profile: an unsigned or `HashMismatch` installer is a finding in itself (supply-chain, tampering, or "vendor ships unsigned builds" — say which).

## Step 3 — extract (static, never run)

| Type | Command |
|---|---|
| MSI / MSP | `msiexec /a "<msi>" /qn TARGETDIR="<dest>"` — administrative install, lays out the file tree without registering the product |
| MSI tables | `export-msi-tables.ps1 -MsiPath <msi> -OutDir <dest>` |
| NSIS | `7z x "<exe>" -o"<dest>" -y` (payload only, script not recovered) |
| Inno Setup | `innoextract "<exe>" -d "<dest>"`, fallback `7z x` |
| WiX Burn | `dark.exe -x "<dest>" "<exe>"`, fallback `7z x` |
| InstallShield | `7z x` (often works), else `"<exe>" /s /extract_all:"<dest>"` — treat as uncertain |
| Squirrel/Electron | `7z x` → find `app-<ver>.nupkg` / `app.asar`; `npx @electron/asar extract` |
| MSIX/APPX | `makeappx unpack /p <pkg> /d <dest> /o`, or plain zip extraction |
| 7z/RAR SFX, IExpress | `7z x`; recurse on the payload |

For EXE-based installers the script is not recoverable, so derive behavior from evidence instead:

- `strings`/`objdump -x` for registry paths (`SOFTWARE\...`), service names, `EventMessageFile`, log paths, URLs, product codes;
- the extracted payload's `.ini/.config/.json/.xml` defaults;
- the vendor's own install log if one is written (`%TEMP%\*.log`, `%ProgramData%\<vendor>\Install.log`).

## Step 3.5 — mine the binary's own strings (EXE-based installers, installed apps)

MSI has a readable database; an EXE does not. Before calling an EXE installer opaque, mine it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\mine-strings.ps1" -Path <installer or app dir> [-Recurse] [-MaxFiles 20]
```

It extracts printable ASCII **and UTF-16LE** runs (Windows stores paths and messages wide), deduplicates globally, and classifies them: registry paths, absolute / `%VAR%` paths, log files, service names, event-log hints, URLs, GUIDs, mutexes, error templates — plus markers for .NET / Electron / PyInstaller / UPX / packed binaries.

Rules that keep it honest:

- On a compressed or self-extracting installer the payload is compressed: **mine the extracted files, not the stub**. `7z x` / `innoextract` first, then run it on the output.
- Every hit is a **lead, not a fact**: a registry path may be read-only, conditional or legacy. Confirm with the probe plan, a registry diff, or Procmon.
- Registry hits become probe-plan candidates; log paths become watch paths; error templates become grep patterns for the app log and Event Log.
- `markers.protected` or `upx` true means the interesting strings are packed; stop guessing and say so.

## Optional deeper analysis: when the installer is itself an application

A .NET bootstrap, an Electron/Squirrel app, or a native loader may not reveal its config keys, log paths or error strings through strings alone. Package the handoff instead of writing a vague note:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\build-handoff.ps1" `
  -Target <exe-or-dir> [-Profile <profile.json>] [-ProbePlan <probe-plan.json>] [-Strings <strings-evidence.json>] [-State <state.json>] -OutDir <dest>
```

It classifies the target (dotnet / electron / pyinstaller / native, plus packed), lists the facts already established, turns the gaps into branch-specific questions, emits the exact decompile commands with tool availability, and writes `handoff.md` (paste-ready) + `handoff.json`. The brief forbids redoing the profiling and requires `[verified]/[inferred]/[unknown]` tags with file/method evidence.

- **If the `reverse-engineering` skill is installed**, paste `handoff.md` into that session and let it work.
- **If it is not installed**, stop at strings evidence and mark every internal-behaviour claim `[inferred]`. Do not install decompilers silently.
- **One skill, one job**: `install-profiler` decides *what to observe*; `reverse-engineering` decides *how to read the code*. The handoff carries `profile.json` + `probe-plan.json` so the second skill does not redo discovery.
- Licensing applies to both: reading an authorized copy for diagnostics is fine; using decompilation to bypass licensing, activation or DRM is refused.

## Step 4 — build the profile (MSI: authoritative)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\export-msi-tables.ps1" -MsiPath <msi> -OutDir <dest>
```

Produces `profile.json` plus one CSV per table under `tables\`. Extract these facts into the report:

- **Product identity** — `ProductName`, `ProductVersion`, `Manufacturer`, `ProductCode`, `UpgradeCode`, `ALLUSERS`, architecture from `Template`.
- **Install layout** — resolved `Directory` paths, `File` rows with sizes/versions, component→directory mapping. Note that folder properties (`ProgramFilesFolder`, `ProgramDataFolder`, …) resolve per machine.
- **Registry** — `Registry` table rows: hive, key, value name, value. Group by purpose: uninstall/ARP, file associations, COM/ProgId, shell extensions, policy, services, EventLog.
- **Services/drivers** — `ServiceInstall` (name, display name, start type, service type bits, account, binary path), `ServiceControl`, `MsiServiceConfig`/`FailureActions`.
- **Startup and shortcuts** — `Shortcut`, `Environment` (PATH/variable writes), `RemoveFile`/`RemoveRegistry` (uninstall leftovers).
- **Install order and conditions** — `InstallExecuteSequence` (sorted), `LaunchCondition` (blocking prerequisites), `Upgrade` (major-upgrade rules), `CustomAction` (what runs outside MSI's own engine).
- **Logs and event sources** — MSI has no EventLog table. Event source registration appears as a `Registry` row under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\...`, or the app creates it at first run. Log paths come from strings + config defaults.

## Step 5 — collect runtime state (installed, misbehaving app)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\collect-state.ps1" -Name '<product/app/service fragment>' -OutDir <dest> [-InstallDir '<path>']
```

Returns `state.json` with uninstall entries, services/drivers (state, start mode, account, binary existence), startup entries, scheduled tasks, Event Log source registrations, app data/log directories, newest log files, WER crash folders, recent MSI logs, pending-reboot flags, plus an `issues[]` list of concrete anomalies.

Compare the runtime state against the profile: a service registered by the MSI but absent on the machine, a binary missing, an `Auto` service stopped, a log file that stopped growing — each is a lead, not yet a conclusion.

## Step 6 — turn the profile into a dynamic probe

Static facts say what *should* happen; the fault lives in what *actually* happens. Do not guess what to watch — derive it from the evidence you have:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill base>\scripts\build-probe-plan.ps1" `
  [-Profile <profile.json>] [-AppDir <app-directory>] [-State <state.json>] [-Strings <strings-evidence.json>] -OutDir <dest>
```

At least one source is required. MSI packages use `-Profile`. Portable, PyInstaller and Electron apps have no MSI — use `-AppDir` plus whatever `collect-state` and `mine-strings` produced; the plan then watches real machine paths instead of MSI logical ones. Mixing sources is expected: `-AppDir` for the tree, `-State` for the data directories that only exist at runtime, `-Strings` for registry keys mined from the binary.

It emits `probe-plan.json` + `probe-plan.md` naming, concretely:

- **real install paths** — MSI `Directory` roots resolved through folder properties (`ProgramFilesFolder` → `C:\Program Files` or `(x86)` by architecture), plus data/log subdirectories;
- **registry keys to snapshot** — ARP/uninstall, `CurrentControlSet\Services\*`, EventLog sources, `Run`/`RunOnce`, COM/associations, and the remaining component keys;
- **services** with expected start type/account versus their current live state on this machine;
- **process names**, candidate **config files**, binary candidates, and log locations;
- **Event Log** providers and IDs (app source, WER 1000/1001, Service Control Manager 7000/7001/7009/7031, MsiInstaller);
- **Procmon filter expressions** (`ACCESS DENIED`, `NAME NOT FOUND`, `Process Create`);
- **checks** with the exact command and the expected result for each.

Then run the loop:

1. **Baseline** — `capture-snapshot.ps1 -Plan <plan> -Label before`
2. **Reproduce exactly one failing action.** Not "try everything" — a diff needs a narrow window and one variable.
3. **Capture** — `capture-snapshot.ps1 -Plan <plan> -Label after -SinceMinutes <window>`
4. **Diff** — `diff-snapshots.ps1 -Before ...\before.json -After ...\after.json`
5. Read `findings[]` by severity. Each `error`/`warn` is a **hypothesis with an owner**, not a verdict.

Why it works: every finding is anchored to something the installer promised. A file missing from an install root is not noise — it is a broken install, a rolled-back custom action, or an AV quarantine. A value deleted under `Services\<name>` has a known owner. A new WER folder plus a disappeared process is a crash, not a guess. A service that went `Running -> Stopped` with Event 7031 has a mechanism.

Read the diff against the playbook before writing conclusions (`references/fault-playbook.md` section 8). Keep the snapshot window short, snapshot in the same elevation context, and if **nothing** changed, the observation surface was wrong — extend the plan with the path/key the app actually touched instead of concluding "no problem".

## Step 7 — diagnose

Read `references/fault-playbook.md` for the full symptom→cause→check→fix tables. The short form — always in this order, because the cheaper explanations come first:

1. **Dependency** — is the prerequisite actually present? (VC++ runtime, .NET version, driver, port, upstream service)
2. **Permission** — can the account that runs it do the thing? (service account, ACL on install/log dirs, UAC, AppLocker/WDAC/Defender ASR)
3. **State** — is the machine in a state that blocks the operation? (pending reboot, MSI cached package missing, another instance/upgrade in progress, disk full, file locked)

Then verify with the specific command for that layer before proposing a fix. A fix without a mechanism is a guess; state the mechanism in one sentence ("MSI re-reads the cached .msi during repair; the cache was purged by the cleanup tool, so repair fails at file resolution").

## Output contract

Deliver `report.md` following `assets/report-template.md`, plus the machine-readable `profile.json`/`state.json`. The report has: identity + hash + signature, install map, registry map, services, config/log/event map, fault analysis (symptom → evidence → mechanism → fix → verification), and residual unknowns.

Keep chat output bounded: summarize the top findings and point at files. Quote at most a few lines of raw tool output.

## Known traps (learned the hard way)

- PowerShell 5.1: MSI COM `Execute()`/`Close()` leak empty values into the pipeline — always prefix `[void]`. Otherwise table reads return phantom columns and row data shifts.
- PowerShell 5.1 reads a `.ps1` file **without BOM as ANSI**; keep bundled scripts ASCII-only or the Chinese in comments/strings turns into mojibake before it ever reaches output.
- On Windows `npx` resolves to `npx.ps1`, which a restricted ExecutionPolicy blocks; use `cmd /c npx ...` (or `npx.cmd`). The same applies to `npm`. Electron `app.asar` extraction needs this.
- electron-builder ships an NSIS installer whose payload is `$PLUGINSDIR\app-64.7z` (or `app-32.7z`) holding `resources/app.asar`. `detect-installer` will say `nsis` — that is correct for the outer layer; extract it and continue as an Electron app.
- `@($someGenericList)` and pipelines over `List[object]` can throw the misleading `Argument types do not match` (`PSToObjectArrayBinder`); call `.ToArray()` first.
- `try { } catch { }` is a statement, not an expression — it cannot sit inside a hashtable literal.
- `strings`-style scanning is only meaningful on uncompressed data; a packed or SFX payload yields garbage, and mistaking that garbage for evidence is worse than saying "packed".
- Tighten string filters before trusting them: a drive-letter regex `^[A-Za-z]:\\` matches random binary runs, so require at least 4 alphanumerics, a word character after the separator, and a minimum length.
- PowerShell variable names are case-insensitive: a local `$allTables` collides with a `[switch]$AllTables` script parameter and throws a misleading "cannot convert Object[] to SwitchParameter". Keep script parameters and locals distinct.
- `Record.FieldCount` is not reliably exposed through late binding; use the `_Columns` row count.
- `Directory.DefaultDir` is `target:source`, each side optionally `short|long` — split on `:` before `|`.
- `MSI ServiceInstall.StartType` uses Win32 semantics: 0 boot, 1 system, 2 auto, 3 demand, 4 disabled.
- `powershell -File` does not split comma lists; pass `-Tables A,B` only because the script normalizes it, and prefer one table per call when unsure.

## Limits — say these out loud

- EXE installers (NSIS/Inno/InstallShield) hide their script; the profile is inferred from payload + strings, not read from source.
- MSI records install-time truth, not what the app does later (first-run writes, auto-updates, runtime config). Those need runtime state or a VM trace.
- Event IDs and log formats come from the application, not the installer; they can only be observed on a running system.
- Server-side behavior, license servers, and cloud features are out of scope by construction.
