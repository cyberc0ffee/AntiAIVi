import json
from pathlib import Path


class IocStore:
    def __init__(self, ioc_dir):
        self.ioc_dir = Path(ioc_dir)
        hashes = self._load("hashes.json", {})
        domains = self._load("domains.json", {})
        ips = self._load("ips.json", {})
        self.hashes = {
            "sha256": self._norm(hashes.get("sha256", {})),
            "sha1": self._norm(hashes.get("sha1", {})),
            "md5": self._norm(hashes.get("md5", {})),
        }
        self.domains = self._norm(domains.get("domains", domains))
        self.ips = {str(key): value for key, value in ips.get("ips", ips).items()}

    def _load(self, name, fallback):
        path = self.ioc_dir / name
        if not path.exists():
            return fallback
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _norm(mapping):
        return {str(key).lower(): value for key, value in mapping.items()}

    def check_hash(self, algorithm, value):
        return self.hashes.get(algorithm, {}).get(str(value).lower())

    def check_domain(self, domain):
        value = str(domain).lower().rstrip(".")
        if value in self.domains:
            return self.domains[value]
        for pattern, hit in self.domains.items():
            if pattern.startswith("*.") and value.endswith(pattern[1:]):
                return hit
        return None

    def check_ip(self, ip):
        return self.ips.get(str(ip))
