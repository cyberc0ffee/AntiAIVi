import json
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path


SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def collect_sysmon(out_path, since_minutes=10, follow=False, interval=5, on_events=None):
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    while True:
        events = query_sysmon_xml(since_minutes)
        with out.open("a", encoding="utf-8") as handle:
            for xml in events:
                event_id = event_record_id(xml)
                if event_id in seen:
                    continue
                seen.add(event_id)
                converted = convert_sysmon_event(xml)
                for item in converted:
                    handle.write(json.dumps(item, ensure_ascii=False) + "\n")
                if converted and on_events:
                    on_events(converted)
        if not follow:
            return len(seen)
        time.sleep(interval)


def query_sysmon_xml(since_minutes):
    script = (
        "$events = Get-WinEvent -FilterHashtable @{"
        f"LogName='{SYSMON_LOG}'; StartTime=(Get-Date).AddMinutes(-{int(since_minutes)})"
        "} -ErrorAction Stop; "
        "$events | ForEach-Object { $_.ToXml(); '---ANTIAI-EVENT---' }"
    )
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Get-WinEvent failed. Is Sysmon installed?")
    return [chunk.strip() for chunk in proc.stdout.split("---ANTIAI-EVENT---") if chunk.strip()]


def convert_sysmon_event(xml_text):
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)
    event_id = int(system.findtext("e:EventID", default="0", namespaces=NS))
    timestamp = system.find("e:TimeCreated", NS).attrib.get("SystemTime")
    fields = {}
    for item in root.findall("e:EventData/e:Data", NS):
        fields[item.attrib.get("Name", "")] = item.text or ""

    if event_id == 1:
        return [{
            "type": "process.start",
            "timestamp": timestamp,
            "pid": number(fields.get("ProcessId")),
            "ppid": number(fields.get("ParentProcessId")),
            "image": fields.get("Image"),
            "commandline": fields.get("CommandLine"),
            "signer": fields.get("Signature") or "Unknown",
        }]
    if event_id == 3:
        events = [{
            "type": "network.connect",
            "timestamp": timestamp,
            "pid": number(fields.get("ProcessId")),
            "image": fields.get("Image"),
            "remote_ip": fields.get("DestinationIp"),
            "remote_port": number(fields.get("DestinationPort")),
            "protocol": fields.get("Protocol"),
        }]
        if fields.get("DestinationHostname"):
            events.append({
                "type": "network.dns",
                "timestamp": timestamp,
                "pid": number(fields.get("ProcessId")),
                "query": fields.get("DestinationHostname"),
            })
        return events
    if event_id == 8:
        return [{
            "type": "memory.api",
            "timestamp": timestamp,
            "pid": number(fields.get("SourceProcessId")),
            "target_pid": number(fields.get("TargetProcessId")),
            "api": "CreateRemoteThread",
        }]
    if event_id == 10:
        return [{
            "type": "process.access",
            "timestamp": timestamp,
            "pid": number(fields.get("SourceProcessId")),
            "image": fields.get("SourceImage"),
            "target_pid": number(fields.get("TargetProcessId")),
            "target_image": fields.get("TargetImage"),
            "api": "OpenProcess",
            "granted_access": fields.get("GrantedAccess"),
        }]
    if event_id == 11:
        return [{
            "type": "file.write",
            "timestamp": timestamp,
            "pid": number(fields.get("ProcessId")),
            "path": fields.get("TargetFilename"),
        }]
    if event_id in {12, 13, 14}:
        return [{
            "type": "registry.set",
            "timestamp": timestamp,
            "pid": number(fields.get("ProcessId")),
            "key": fields.get("TargetObject"),
            "value": fields.get("Details") or fields.get("NewName"),
            "data": fields.get("Details"),
        }]
    if event_id == 22:
        return [{
            "type": "network.dns",
            "timestamp": timestamp,
            "pid": number(fields.get("ProcessId")),
            "query": fields.get("QueryName"),
            "rcode": fields.get("QueryStatus"),
        }]
    return []


def event_record_id(xml_text):
    root = ET.fromstring(xml_text)
    return root.findtext("e:System/e:EventRecordID", default="", namespaces=NS)


def number(value):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return 0
