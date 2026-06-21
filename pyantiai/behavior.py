import json
import re
from pathlib import Path

from .severity import decide, signal


OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
LOLBINS = {"powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "wscript.exe", "cscript.exe", "cmd.exe"}


class BehaviorEngine:
    def __init__(self, ioc_store):
        self.ioc_store = ioc_store
        self.processes = {}
        self.memory_ops = {}
        self.emitted = set()

    def ingest(self, event):
        kind = event.get("type")
        if kind == "process.start":
            return self._process_start(event)
        if kind == "registry.set":
            return self._registry(event)
        if kind == "memory.api":
            return self._memory(event)
        if kind == "process.access":
            return self._process_access(event)
        if kind == "network.dns":
            return self._dns(event)
        if kind == "network.connect":
            return self._connect(event)
        return []

    def _process_start(self, event):
        pid = int(event.get("pid", 0))
        ppid = int(event.get("ppid", 0))
        image = basename(event.get("image"))
        self.processes[pid] = {"image": image, **event}
        parent = self.processes.get(ppid, {})
        commandline = event.get("commandline", "")
        out = []
        if parent.get("image") in OFFICE and image in LOLBINS:
            out.append(self.once(f"office-lolbin:{pid}", signal("behavior.process", "office_lolbin_chain", 65, subject(pid, image), "Office process spawned a LOLBIN child process.", "high", {"parent": parent.get("image"), "child": image})))
        if re.search(r"(?:-|/)(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", commandline, re.I):
            out.append(self.once(f"encoded:{pid}", signal("behavior.process", "powershell_encoded_command", 30, subject(pid, image), "Encoded command line detected.", "high", {"commandline": commandline})))
        return [item for item in out if item]

    def _registry(self, event):
        key = str(event.get("key", "")).lower()
        if not any(marker in key for marker in ["\\currentversion\\run", "\\currentversion\\runonce", "\\services\\", "\\startup"]):
            return []
        pid = int(event.get("pid", 0))
        return [self.once(f"persistence:{pid}:{key}", signal("behavior.registry", "persistence", 25, subject(pid, self.processes.get(pid, {}).get("image")), "Persistence registry location modified.", "medium", {"key": event.get("key"), "value": event.get("value"), "data": event.get("data")}))]

    def _memory(self, event):
        pid = int(event.get("pid", 0))
        target = int(event.get("target_pid", 0))
        key = f"{pid}:{target}"
        ops = self.memory_ops.setdefault(key, [])
        ops.append(str(event.get("api", "")))
        if has_sequence(ops, ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]):
            return [self.once(f"injection:{key}", signal("behavior.memory", "process_injection", 75, subject(pid, self.processes.get(pid, {}).get("image")), "Remote process injection API sequence detected.", "high", {"target_pid": target}))]
        return []

    def _process_access(self, event):
        target = basename(event.get("target_image"))
        if target == "lsass.exe":
            pid = int(event.get("pid", 0))
            return [self.once(f"lsass:{pid}", signal("behavior.credential", "lsass_access", 90, subject(pid, basename(event.get("image"))), "Process accessed LSASS.", "critical", {"target_image": target}))]
        return []

    def _dns(self, event):
        domain = event.get("query") or event.get("domain")
        pid = int(event.get("pid", 0))
        hit = self.ioc_store.check_domain(domain) if domain else None
        if hit:
            return [self.once(f"domain:{domain}", signal("behavior.network", "known_c2_domain", int(hit.get("score", 90)), subject(pid, self.processes.get(pid, {}).get("image")), "DNS query matched threat intelligence domain IOC.", hit.get("severity", "critical"), {"domain": domain, "family": hit.get("family")}))]
        return []

    def _connect(self, event):
        ip = event.get("remote_ip") or event.get("ip")
        pid = int(event.get("pid", 0))
        hit = self.ioc_store.check_ip(ip) if ip else None
        if hit:
            return [self.once(f"ip:{ip}", signal("behavior.network", "known_c2_ip", int(hit.get("score", 90)), subject(pid, self.processes.get(pid, {}).get("image")), "Network connection matched threat intelligence IP IOC.", hit.get("severity", "critical"), {"ip": ip, "family": hit.get("family")}))]
        return []

    def once(self, key, value):
        if key in self.emitted:
            return None
        self.emitted.add(key)
        return value


def replay_jsonl(path, ioc_store):
    engine = BehaviorEngine(ioc_store)
    signals = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        signals.extend(engine.ingest(json.loads(line)))
    return {"file": str(Path(path).resolve()), "signals": signals, "detection": decide(path, signals)}


def basename(value):
    return Path(str(value or "")).name.lower()


def subject(pid, image):
    return f"{image}:{pid}" if image else f"pid:{pid}"


def has_sequence(values, sequence):
    cursor = 0
    for value in values:
        if str(value).lower() == sequence[cursor].lower():
            cursor += 1
            if cursor == len(sequence):
                return True
    return False
