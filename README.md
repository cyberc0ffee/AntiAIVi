# AntiAiVi

AntiAiVi is a defensive, open source antivirus/EDR reference implementation based on the supplied technical specification:

- Static Detection Engine
- Behavioral Detection Engine
- Threat Intelligence Engine
- Correlation Engine
- Decision Engine
- Response Engine
- Update Engine

The main CLI now runs through Python so Windows/Sysmon collectors can be integrated without native Node.js dependencies. The original dependency-free JavaScript implementation remains in `src/` as a reference.

## Quick Start

```powershell
.\antiai.cmd scan C:\path\to\file-or-folder
.\antiai.cmd replay examples\events.jsonl
.\antiai.cmd watch C:\path\to\folder
```

Run the Python self-test:

```powershell
.\antiai.cmd scan examples\events.jsonl --debug
& "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" scripts\python_selftest.py
```

Use JSON output for automation:

```powershell
.\antiai.cmd scan C:\path\to\folder --json
.\antiai.cmd replay examples\events.jsonl --json
```

Show every static check performed on a file:

```powershell
.\antiai.cmd scan C:\path\to\file --debug
.\antiai.cmd scan C:\path\to\file --debug --json
```

VirusTotal hash lookup is available but disabled by default. Put your API key in `config/virustotal.json`, then run:

```powershell
.\antiai.cmd scan C:\path\to\file --virustotal
.\antiai.cmd scan C:\path\to\file --virustotal --debug
```

This integration only sends file hashes to VirusTotal. It does not upload file contents.

Realtime protection watches folders and scans files when they are created or modified:

```powershell
.\antiai.cmd watch C:\Users\admin\Downloads
.\antiai.cmd watch C:\Users\admin\Downloads --debug
.\antiai.cmd watch C:\Users\admin\Downloads --quarantine
.\antiai.cmd watch C:\Users\admin\Downloads --initial-scan
```

The current realtime mode protects the filesystem. Process, registry, memory, and network telemetry still require a Windows ETW/Sysmon collector.

Sysmon collector:

```powershell
.\antiai.cmd sysmon --out examples\sysmon-events.jsonl --since-minutes 30
.\antiai.cmd replay examples\sysmon-events.jsonl
.\antiai.cmd sysmon --out examples\sysmon-events.jsonl --follow
.\antiai.cmd sysmon --out examples\sysmon-events.jsonl --follow --analyze
```

The collector reads `Microsoft-Windows-Sysmon/Operational` with PowerShell `Get-WinEvent`, converts supported Sysmon events to AntiAiVi JSONL, and can then replay them through the behavior engine.

Central EDR server:

```powershell
.\antiai.cmd server --host 127.0.0.1 --port 8765 --api-key cambia-questa-chiave
```

Open the web dashboard:

```text
http://127.0.0.1:8765/
```

If the server was started with `--api-key`, paste the same key into the dashboard API key field and press `Salva`. The page shows total clients, active clients, total logs, and a client table. Double-click a client row to load its latest logs.

Send agent logs to the central server:

```powershell
.\antiai.cmd scan C:\Users\admin\Downloads --server-url http://127.0.0.1:8765 --api-key cambia-questa-chiave
.\antiai.cmd watch C:\Users\admin\Downloads --server-url http://127.0.0.1:8765 --api-key cambia-questa-chiave
.\antiai.cmd sysmon --follow --analyze --server-url http://127.0.0.1:8765 --api-key cambia-questa-chiave
```

`watch` sends an `agent.heartbeat` immediately and then every 60 seconds by default, so the dashboard can show the client even when no file changes occur. Heartbeats are stored as client state and overwrite the previous heartbeat for that client; they do not fill the event log history. You can tune it:

```powershell
.\antiai.cmd watch C:\Users\admin\Downloads --server-url http://127.0.0.1:8765 --api-key cambia-questa-chiave --heartbeat-interval 30
```

Dashboard heartbeat status:

- Green: last heartbeat within 3 minutes.
- Yellow: last heartbeat within 30 minutes.
- Red: no heartbeat or heartbeat older than 30 minutes.

Query server state:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/v1/health
Invoke-RestMethod http://127.0.0.1:8765/api/v1/events -Headers @{ "X-API-Key" = "cambia-questa-chiave" }
```

The server stores events in SQLite by default at `.antiai/server/edr.sqlite`. Use `--db` and `--jsonl` to override storage paths.

Quarantine is opt-in because it modifies files:

```powershell
.\antiai.cmd scan C:\path\to\suspicious.exe --quarantine
```

## Current Capabilities

Static scanning:

- SHA-256, SHA-1, and MD5 hashing.
- Local IOC hash lookup.
- YARA-like rule matching without native dependencies.
- Script analysis for PowerShell, JavaScript, VBScript, batch, and CMD files.
- Portable Executable parsing for headers, sections, entropy, suspicious imports, packer markers, and embedded signature presence.

Behavioral replay:

- Process tree analysis, including Office-to-LOLBIN chains.
- File activity thresholds for ransomware-like bursts.
- Registry persistence detection.
- Memory API sequence detection for injection and hollowing patterns.
- LSASS access detection.
- DNS and network IOC checks.
- Beacon interval detection.

Response and update:

- AES-256-GCM quarantine store with metadata.
- Update manifest validation with optional Ed25519 signature verification.
- Scoring thresholds matching the supplied design.

## Roadmap

1. Replace JSONL replay with Windows ETW collectors.
2. Add native libyara bindings or a Rust scanner service.
3. Add SQLite/RocksDB-backed IOC and event stores.
4. Add Windows Filtering Platform enforcement for domains and IPs.
5. Add a Tauri UI over the service API.
6. Add signed update publishing and rollback.

## Safety Model

The default CLI only scans and reports. Actions that alter the system, such as quarantine, require explicit flags. Process termination, suspension, and firewall blocking are represented as response actions in this prototype and should be connected to OS-specific enforcement only after policy review and tests.
