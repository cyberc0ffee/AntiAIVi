from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IOC_DIR = PROJECT_ROOT / "data" / "ioc"
DEFAULT_RULES_FILE = PROJECT_ROOT / "data" / "rules" / "yara-lite-rules.json"
DEFAULT_STATE_DIR = PROJECT_ROOT / ".antiai"
DEFAULT_VIRUSTOTAL_CONFIG = PROJECT_ROOT / "config" / "virustotal.json"
