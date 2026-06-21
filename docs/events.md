# Behavioral Event Schema

The replay collector consumes newline-delimited JSON. Each line is an event with a `type` and an optional ISO-8601 `timestamp`.

## Process Events

```json
{
  "type": "process.start",
  "timestamp": "2026-01-01T10:00:00.000Z",
  "pid": 1200,
  "ppid": 800,
  "image": "powershell.exe",
  "commandline": "powershell.exe -EncodedCommand ...",
  "signer": "Unknown"
}
```

```json
{
  "type": "process.access",
  "pid": 1200,
  "image": "tool.exe",
  "signer": "Unknown",
  "target_pid": 500,
  "target_image": "lsass.exe",
  "api": "MiniDumpWriteDump"
}
```

## File Events

```json
{
  "type": "file.write",
  "pid": 1200,
  "path": "C:\\Users\\Alice\\Documents\\a.docx",
  "bytes": 4096,
  "entropy_delta": 1.8
}
```

```json
{
  "type": "file.rename",
  "pid": 1200,
  "old_path": "C:\\Users\\Alice\\Documents\\a.docx",
  "new_path": "C:\\Users\\Alice\\Documents\\a.docx.locked",
  "new_extension": ".locked"
}
```

## Registry Events

```json
{
  "type": "registry.set",
  "pid": 1200,
  "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "value": "Updater",
  "data": "C:\\Users\\Alice\\AppData\\Roaming\\updater.exe"
}
```

## Memory Events

```json
{
  "type": "memory.api",
  "pid": 1200,
  "target_pid": 4321,
  "api": "WriteProcessMemory"
}
```

## Network Events

```json
{
  "type": "network.dns",
  "pid": 1200,
  "query": "malicious.test",
  "rcode": "NOERROR",
  "ttl": 60
}
```

```json
{
  "type": "network.connect",
  "pid": 1200,
  "remote_ip": "203.0.113.66",
  "remote_port": 443,
  "protocol": "tcp",
  "bytes_out": 512,
  "bytes_in": 128
}
```
