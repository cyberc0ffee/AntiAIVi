import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from .severity import signal


class VirusTotalClient:
    def __init__(self, config_path, force_enabled=False):
        path = Path(config_path)
        if not path.exists() and not force_enabled:
            self.enabled = False
            return
        if not path.exists():
            raise RuntimeError(f"VirusTotal config not found: {path}")
        config = json.loads(path.read_text(encoding="utf-8"))
        self.enabled = force_enabled or config.get("enabled") is True
        self.api_key = os.environ.get("VIRUSTOTAL_API_KEY") or config.get("api_key", "")
        self.base_url = config.get("base_url", "https://www.virustotal.com/api/v3").rstrip("/")
        self.timeout = float(config.get("timeout_ms", 15000)) / 1000.0
        self.minimum_malicious = int(config.get("minimum_malicious", 1))
        self.minimum_suspicious = int(config.get("minimum_suspicious", 3))
        if self.enabled and (not self.api_key or "INSERISCI_LA_TUA_CHIAVE" in self.api_key):
            raise RuntimeError(f"VirusTotal API key missing. Edit {path} or set VIRUSTOTAL_API_KEY.")

    @classmethod
    def maybe(cls, config_path, force_enabled=False):
        client = cls(config_path, force_enabled=force_enabled)
        return client if client.enabled else None

    def lookup(self, file_path, hashes, debug=False):
        trace = []
        signals = []
        sha256 = hashes.get("sha256")
        if debug:
            trace.append({"check": "virustotal.lookup.request", "status": "ok", "message": "VirusTotal hash report lookup requested.", "details": {"endpoint": f"{self.base_url}/files/{{id}}", "uploads_file_content": False}})
        try:
            request = urllib.request.Request(
                f"{self.base_url}/files/{sha256}",
                headers={"accept": "application/json", "x-apikey": self.api_key},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                if debug:
                    trace.append({"check": "virustotal.lookup.response", "status": "clean", "message": "VirusTotal has no report for this hash.", "details": {"http_status": 404}})
                return {"signals": signals, "debug": trace, "report": None}
            if debug:
                trace.append({"check": "virustotal.lookup.error", "status": "error", "message": "VirusTotal lookup failed.", "details": {"http_status": error.code}})
            return {"signals": signals, "debug": trace, "report": None}
        except Exception as error:
            if debug:
                trace.append({"check": "virustotal.lookup.error", "status": "error", "message": "VirusTotal lookup failed.", "details": {"error": str(error)}})
            return {"signals": signals, "debug": trace, "report": None}

        attributes = body.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(value or 0) for value in stats.values())
        hit = malicious >= self.minimum_malicious or suspicious >= self.minimum_suspicious
        if debug:
            trace.append({"check": "virustotal.lookup.response", "status": "hit" if hit else "clean", "message": "VirusTotal report reached threshold." if hit else "VirusTotal report is below threshold.", "details": {"malicious": malicious, "suspicious": suspicious, "total_engines": total}})
        if hit:
            score = min(100, 40 + malicious * 10 + suspicious * 5)
            severity = "critical" if malicious >= 5 else "high"
            signals.append(signal("threat-intel.virustotal", "virustotal_detection", score, file_path, "VirusTotal report contains malicious or suspicious detections.", severity, {"sha256": sha256, "malicious": malicious, "suspicious": suspicious, "total_engines": total, "permalink": f"https://www.virustotal.com/gui/file/{sha256}"}))
        return {"signals": signals, "debug": trace, "report": {"malicious": malicious, "suspicious": suspicious, "total_engines": total}}
