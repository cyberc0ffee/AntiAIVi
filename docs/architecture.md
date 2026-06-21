# Architecture

AntiAiVi follows an event-driven architecture with small engines that emit detection signals into a common scoring pipeline.

```text
CLI / UI
  |
  v
Antivirus Service
  |
  +--> Static Engine
  +--> Behavioral Engine
  +--> Threat Intel Store
          |
          v
    Correlation Engine
          |
          v
      Decision Engine
          |
          v
      Response Engine
```

## Static Detection Engine

Pipeline:

```text
file -> hash -> IOC lookup -> YARA-lite rules -> PE analysis -> script analysis -> signals
```

Implemented modules:

- `src/static/hash-scanner.js`
- `src/static/yara-lite.js`
- `src/static/pe-analyzer.js`
- `src/static/script-analyzer.js`
- `src/static/static-engine.js`

The YARA-lite module is deliberately simple. It keeps rule categories and matching semantics in place while the native `libyara` integration is unavailable.

## Behavioral Detection Engine

Pipeline:

```text
event -> state update -> behavior rule -> signal -> correlation
```

Implemented modules:

- `src/behavior/event-collector.js`
- `src/behavior/behavior-engine.js`

The current collector reads JSONL replay files. On Windows this boundary should be replaced with ETW providers:

- `Microsoft-Windows-Kernel-Process`
- `Microsoft-Windows-Kernel-File`
- `Microsoft-Windows-Kernel-Network`
- `Microsoft-Windows-Kernel-Registry`
- `Microsoft-Windows-Threat-Intelligence`

## Threat Intelligence Engine

Local IOC files are stored in `data/ioc`:

- `hashes.json`
- `domains.json`
- `ips.json`

The store supports exact lookups and basic wildcard domain suffixes. Production deployments should move this to SQLite or RocksDB and add scheduled feed refresh.

## Correlation And Decision

Signals carry:

- source
- category
- score
- severity
- subject
- message
- evidence
- timestamp

The decision engine sums scores and maps them to actions:

```text
0-39      allow
40-69     monitor
70-99     suspend
100+      kill_quarantine
```

## Response Engine

Implemented:

- Encrypted file quarantine.
- Response planning for suspend, kill, domain block, and IP block actions.

Not yet implemented:

- Live process termination or suspension.
- WFP firewall enforcement.
- Rollback of registry and file actions.

## Update Engine

Update manifests are JSON documents with a version and optional `rules`, `iocs`, and `signature` fields. Ed25519 verification is supported when a public key is supplied.
