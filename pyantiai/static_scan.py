import hashlib
import json
import math
import re
from pathlib import Path

from .severity import signal


SCRIPT_EXTENSIONS = {".ps1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd"}
SUSPICIOUS_IMPORTS = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "OpenProcess",
    "ReadProcessMemory",
    "MiniDumpWriteDump",
    "QueueUserAPC",
    "MapViewOfFile",
    "SetWindowsHookEx",
]
PACKER_MARKERS = ["UPX0", "UPX1", "Themida", "VMProtect", "ASPack"]
SCRIPT_RULES = [
    ("powershell_encoded_command", 30, "high", {".ps1", ".bat", ".cmd"}, re.compile(r"(?:-|/)(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I), "PowerShell encoded command detected."),
    ("powershell_downloader", 35, "high", {".ps1"}, re.compile(r"\b(?:IEX|Invoke-Expression)\b[\s\S]{0,120}\b(?:DownloadString|Invoke-WebRequest|curl|wget)\b", re.I), "PowerShell download-and-execute pattern detected."),
    ("base64_payload", 25, "medium", {".ps1", ".js", ".vbs"}, re.compile(r"\b(?:FromBase64String|atob)\s*\(", re.I), "Base64 decoding primitive detected."),
    ("js_activex", 35, "high", {".js", ".jse", ".vbs", ".vbe"}, re.compile(r"\bActiveXObject\b[\s\S]{0,200}\b(?:WScript\.Shell|MSXML2\.XMLHTTP|ADODB\.Stream)\b", re.I), "Windows Script Host ActiveX automation pattern detected."),
    ("lolbin_download", 30, "medium", {".bat", ".cmd", ".ps1"}, re.compile(r"\b(?:certutil|bitsadmin)\b[\s\S]{0,120}\b(?:-urlcache|-split|/transfer|http://|https://)", re.I), "LOLBIN download command detected."),
    ("shadow_copy_delete", 80, "critical", {".bat", ".cmd", ".ps1"}, re.compile(r"\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no)\b", re.I), "Shadow copy deletion or recovery disabling command detected."),
]


class StaticScanner:
    def __init__(self, ioc_store, rules_file, virustotal=None):
        self.ioc_store = ioc_store
        self.rules_file = Path(rules_file)
        self.rules = self._load_rules()
        self.virustotal = virustotal

    def _load_rules(self):
        if not self.rules_file.exists():
            return []
        data = json.loads(self.rules_file.read_text(encoding="utf-8"))
        return data.get("rules", [])

    def scan_file(self, file_path, debug=False):
        path = Path(file_path)
        stat = path.stat()
        trace = []
        if debug:
            trace.append({"check": "file.stat", "status": "ok", "message": "File metadata loaded.", "details": {"size": stat.st_size, "modified": stat.st_mtime}})

        hashes = hash_file(path)
        signals = []
        if debug:
            for algorithm, value in hashes.items():
                trace.append({"check": f"hash.{algorithm}", "status": "ok", "message": f"{algorithm.upper()} calculated.", "details": {"value": value}})

        for algorithm, value in hashes.items():
            hit = self.ioc_store.check_hash(algorithm, value)
            if debug:
                trace.append({"check": f"ioc.hash.{algorithm}", "status": "hit" if hit else "clean", "message": f"{'Hash IOC hit' if hit else 'No hash IOC match'} for {algorithm}.", "details": {"hash": value, "family": hit.get("family") if hit else None}})
            if hit:
                signals.append(signal("static.hash", "known_malware_hash", int(hit.get("score", 100)), path, f"Known malicious/test hash matched ({algorithm}).", hit.get("severity", "critical"), {"algorithm": algorithm, "hash": value, "family": hit.get("family")}))

        if self.virustotal:
            vt = self.virustotal.lookup(path, hashes, debug=debug)
            signals.extend(vt["signals"])
            trace.extend(vt["debug"])
            vt_report = vt["report"]
        else:
            vt_report = None
            if debug:
                trace.append({"check": "virustotal.config", "status": "skipped", "message": "VirusTotal lookup is disabled.", "details": {}})

        yara = self._scan_yara_lite(path, debug)
        signals.extend(yara["signals"])
        trace.extend(yara["debug"])

        pe = self._scan_pe(path, debug)
        signals.extend(pe["signals"])
        trace.extend(pe["debug"])

        script = self._scan_script(path, debug)
        signals.extend(script["signals"])
        trace.extend(script["debug"])

        result = {
            "file": str(path),
            "size": stat.st_size,
            "hashes": hashes,
            "virustotal": vt_report,
            "pe": pe["details"],
            "signals": signals,
        }
        if debug:
            result["debug_trace"] = trace
        return result

    def _scan_yara_lite(self, path, debug):
        data = path.read_bytes()[: 10 * 1024 * 1024]
        latin = data.decode("latin1", errors="ignore")
        utf8 = data.decode("utf-8", errors="ignore")
        signals = []
        trace = []
        if debug:
            trace.append({"check": "yara-lite.scan-window", "status": "ok", "message": "Loaded file bytes for YARA-lite matching.", "details": {"rules_loaded": len(self.rules), "bytes_scanned": len(data)}})
        for rule in self.rules:
            results = [match_pattern(pattern, latin, utf8) for pattern in rule.get("patterns", [])]
            matched = all(results) if rule.get("match") == "all" else any(results)
            matched_patterns = [rule.get("patterns", [])[idx].get("text") or rule.get("patterns", [])[idx].get("regex") or rule.get("patterns", [])[idx].get("hex") for idx, ok in enumerate(results) if ok]
            if debug:
                trace.append({"check": f"yara-lite.rule.{rule.get('id', 'unnamed')}", "status": "hit" if matched else "clean", "message": f"Rule {'matched' if matched else 'did not match'}: {rule.get('name', rule.get('id', 'unnamed'))}.", "details": {"category": rule.get("category", "signature"), "matched_patterns": matched_patterns}})
            if matched:
                signals.append(signal("static.yara-lite", rule.get("category", "signature"), int(rule.get("score", 50)), path, f"Rule matched: {rule.get('name', rule.get('id', 'unnamed'))}.", rule.get("severity"), {"rule_id": rule.get("id"), "matched_patterns": matched_patterns}))
        return {"signals": signals, "debug": trace}

    def _scan_script(self, path, debug):
        extension = path.suffix.lower()
        trace = []
        signals = []
        if extension not in SCRIPT_EXTENSIONS:
            if debug:
                trace.append({"check": "script.extension", "status": "skipped", "message": "File extension is not handled by the script analyzer.", "details": {"extension": extension or "(none)"}})
            return {"signals": signals, "debug": trace}
        content = path.read_text(encoding="utf-8", errors="ignore")
        if debug:
            trace.append({"check": "script.extension", "status": "ok", "message": "File extension is handled by the script analyzer.", "details": {"extension": extension}})
        for category, score, severity, extensions, regex, message in SCRIPT_RULES:
            if extension not in extensions:
                if debug:
                    trace.append({"check": f"script.rule.{category}", "status": "skipped", "message": "Rule does not apply to this script extension.", "details": {"extension": extension}})
                continue
            found = regex.search(content)
            if debug:
                trace.append({"check": f"script.rule.{category}", "status": "hit" if found else "clean", "message": message if found else "Script heuristic did not match.", "details": {"score": score, "severity": severity}})
            if found:
                signals.append(signal("static.script", category, score, path, message, severity, {"extension": extension}))
        return {"signals": signals, "debug": trace}

    def _scan_pe(self, path, debug):
        data = path.read_bytes()
        trace = []
        signals = []
        details = None
        if len(data) < 64 or data[:2] != b"MZ":
            if debug:
                trace.append({"check": "pe.format", "status": "skipped", "message": "File is not a Portable Executable.", "details": {"bytes_checked": min(len(data), 64)}})
            return {"signals": signals, "debug": trace, "details": details}
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset <= 0 or pe_offset + 4 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
            if debug:
                trace.append({"check": "pe.format", "status": "skipped", "message": "MZ header found but PE signature is missing.", "details": {}})
            return {"signals": signals, "debug": trace, "details": details}
        details = parse_pe(data, pe_offset)
        if debug:
            trace.append({"check": "pe.format", "status": "ok", "message": "Portable Executable headers detected.", "details": {"section_count": len(details["sections"]), "has_embedded_signature": details["has_embedded_signature"]}})
        high_entropy = [item for item in details["sections"] if item["entropy"] > 7.2 and item["raw_size"] > 0]
        if debug:
            trace.append({"check": "pe.entropy", "status": "hit" if high_entropy else "clean", "message": "High entropy PE section detected." if high_entropy else "No PE sections exceed the entropy threshold.", "details": {"threshold": 7.2, "sections": details["sections"]}})
        if high_entropy:
            signals.append(signal("static.pe", "high_entropy", 20, path, "High entropy PE section detected.", "medium", {"sections": high_entropy}))
        text = data.decode("latin1", errors="ignore")
        imports = [name for name in SUSPICIOUS_IMPORTS if name in text]
        if debug:
            trace.append({"check": "pe.suspicious-imports", "status": "hit" if imports else "clean", "message": "Suspicious API imports or strings were found." if imports else "No suspicious API imports or strings were found.", "details": {"matched_imports": imports}})
        if imports:
            signals.append(signal("static.pe", "suspicious_imports", min(60, 10 + len(imports) * 10), path, "Suspicious Windows API imports or strings detected.", "high" if len(imports) >= 4 else "medium", {"imports": imports}))
        markers = [name for name in PACKER_MARKERS if name in text]
        if debug:
            trace.append({"check": "pe.packer-markers", "status": "hit" if markers else "clean", "message": "Common packer markers were found." if markers else "No common packer markers were found.", "details": {"matched_markers": markers}})
        if markers:
            signals.append(signal("static.pe", "packer_marker", 30, path, "Common packer marker detected.", "medium", {"markers": markers}))
        return {"signals": signals, "debug": trace, "details": details}


def hash_file(path):
    hashes = {"sha256": hashlib.sha256(), "sha1": hashlib.sha1(), "md5": hashlib.md5()}
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for item in hashes.values():
                item.update(chunk)
    return {name: item.hexdigest() for name, item in hashes.items()}


def match_pattern(pattern, latin, utf8):
    if "text" in pattern:
        haystack = latin.lower() if pattern.get("nocase") else latin
        needle = pattern["text"].lower() if pattern.get("nocase") else pattern["text"]
        return needle in haystack
    if "regex" in pattern:
        flags = re.I if pattern.get("nocase") else 0
        return re.search(pattern["regex"], utf8, flags) is not None
    if "hex" in pattern:
        return re.sub(r"[^a-fA-F0-9]", "", pattern["hex"]).lower() in latin.encode("latin1", errors="ignore").hex()
    return False


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    value = 0.0
    for count in counts:
        if count:
            p = count / len(data)
            value -= p * math.log2(p)
    return value


def parse_pe(data, pe_offset):
    file_header = pe_offset + 4
    sections_count = int.from_bytes(data[file_header + 2:file_header + 4], "little")
    optional_size = int.from_bytes(data[file_header + 16:file_header + 18], "little")
    optional_offset = file_header + 20
    section_table = optional_offset + optional_size
    optional_magic = int.from_bytes(data[optional_offset:optional_offset + 2], "little")
    data_dir = optional_offset + (112 if optional_magic == 0x20B else 96)
    security_dir = data_dir + 8 * 4
    signature_offset = int.from_bytes(data[security_dir:security_dir + 4], "little") if security_dir + 8 <= len(data) else 0
    signature_size = int.from_bytes(data[security_dir + 4:security_dir + 8], "little") if security_dir + 8 <= len(data) else 0
    sections = []
    for index in range(sections_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="ignore")
        raw_size = int.from_bytes(data[offset + 16:offset + 20], "little")
        raw_ptr = int.from_bytes(data[offset + 20:offset + 24], "little")
        body = data[raw_ptr:raw_ptr + raw_size] if raw_ptr and raw_ptr + raw_size <= len(data) else b""
        sections.append({"name": name, "raw_size": raw_size, "entropy": round(entropy(body), 3)})
    return {"sections": sections, "has_embedded_signature": signature_offset > 0 and signature_size > 0}
