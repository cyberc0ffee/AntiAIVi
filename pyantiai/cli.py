import argparse
import json
import signal as signal_module
import sys
from pathlib import Path

from .behavior import BehaviorEngine, replay_jsonl
from .edr_server import DEFAULT_DB, run_server
from .ioc import IocStore
from .logshipper import LogShipper
from .paths import DEFAULT_IOC_DIR, DEFAULT_RULES_FILE, DEFAULT_STATE_DIR, DEFAULT_VIRUSTOTAL_CONFIG
from .realtime import PollingRealtimeWatcher
from .response import apply_response
from .severity import decide
from .static_scan import StaticScanner
from .sysmon import collect_sysmon
from .virustotal import VirusTotalClient


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return command_scan(args)
        if args.command == "watch":
            return command_watch(args)
        if args.command == "replay":
            return command_replay(args)
        if args.command == "sysmon":
            return command_sysmon(args)
        if args.command == "server":
            return command_server(args)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


def build_parser():
    parser = argparse.ArgumentParser(prog="antiai.py")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan")
    add_scan_options(scan)
    scan.add_argument("targets", nargs="+")

    watch = sub.add_parser("watch")
    add_scan_options(watch)
    watch.add_argument("--interval", type=float, default=1.0)
    watch.add_argument("--heartbeat-interval", type=float, default=60.0)
    watch.add_argument("--initial-scan", action="store_true")
    watch.add_argument("targets", nargs="+")

    replay = sub.add_parser("replay")
    add_forwarding_options(replay)
    replay.add_argument("--ioc-dir", default=str(DEFAULT_IOC_DIR))
    replay.add_argument("--json", action="store_true")
    replay.add_argument("events")

    sysmon = sub.add_parser("sysmon")
    add_forwarding_options(sysmon)
    sysmon.add_argument("--out", default="examples/sysmon-events.jsonl")
    sysmon.add_argument("--since-minutes", type=int, default=10)
    sysmon.add_argument("--follow", action="store_true")
    sysmon.add_argument("--analyze", action="store_true")
    sysmon.add_argument("--json", action="store_true")
    sysmon.add_argument("--interval", type=int, default=5)

    server = sub.add_parser("server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.add_argument("--db", default=str(DEFAULT_DB))
    server.add_argument("--api-key")
    server.add_argument("--jsonl")
    return parser


def add_scan_options(parser):
    add_forwarding_options(parser)
    parser.add_argument("--ioc-dir", default=str(DEFAULT_IOC_DIR))
    parser.add_argument("--rules", default=str(DEFAULT_RULES_FILE))
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--virustotal", action="store_true")
    parser.add_argument("--virustotal-config", default=str(DEFAULT_VIRUSTOTAL_CONFIG))
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quarantine", action="store_true")


def add_forwarding_options(parser):
    parser.add_argument("--server-url", help="Central EDR server URL, for example http://127.0.0.1:8765.")
    parser.add_argument("--agent-id", help="Agent identifier sent to the central EDR server.")
    parser.add_argument("--api-key", help="API key for the central EDR server.")


def command_scan(args):
    scanner = create_scanner(args)
    shipper = create_shipper(args)
    results = []
    for target in args.targets:
        for file_path in walk_files(Path(target)):
            result = scan_one(scanner, file_path, args)
            results.append(result)
            ship_log(shipper, {"type": "scan.result", "result": result, "detection": result["detection"]})
            if not args.json:
                print_scan(result, debug=args.debug)
    if args.json:
        print(json.dumps(results, indent=2))
    return 0


def command_watch(args):
    scanner = create_scanner(args)
    shipper = create_shipper(args)

    def scan_file(path):
        return scan_one(scanner, path, args)

    def on_result(result):
        ship_log(shipper, {"type": "realtime.scan", "result": result, "detection": result["detection"]})
        if args.json:
            print(json.dumps({"type": "realtime.scan", "result": result}, indent=2), flush=True)
        else:
            print_scan(result, debug=args.debug, prefix="realtime ")

    def on_heartbeat(event):
        ship_log(shipper, event)
        if shipper.enabled and not args.json:
            print("Heartbeat sent to EDR server.", flush=True)

    watcher = PollingRealtimeWatcher(
        args.targets,
        scan_file,
        on_result,
        interval=args.interval,
        initial_scan=args.initial_scan,
        on_heartbeat=on_heartbeat if shipper.enabled else None,
        heartbeat_interval=args.heartbeat_interval,
    )
    stopped = {"value": False}

    def stop(_signum, _frame):
        stopped["value"] = True
        watcher.stop()

    signal_module.signal(signal_module.SIGINT, stop)
    signal_module.signal(signal_module.SIGTERM, stop)
    if not args.json:
        print("Realtime protection active through Python polling watcher. Press Ctrl+C to stop.")
    watcher.start()
    return 130 if stopped["value"] else 0


def command_replay(args):
    shipper = create_shipper(args)
    result = replay_jsonl(args.events, IocStore(args.ioc_dir))
    ship_log(shipper, {"type": "replay.result", "result": result, "detection": result["detection"]})
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Replay: {result['file']}")
        print(f"score={result['detection']['score']} severity={result['detection']['severity']} action={result['detection']['action']}")
        for item in result["signals"]:
            print(f"- [{item['severity']}] {item['source']}/{item['category']}: {item['message']}")
    return 0


def command_sysmon(args):
    behavior = BehaviorEngine(IocStore(DEFAULT_IOC_DIR)) if args.analyze else None
    shipper = create_shipper(args)

    def on_events(events):
        ship_log(shipper, {"type": "sysmon.events", "events": events})
        for event in events:
            ship_log(shipper, {"type": "sysmon.event", "event": event})
            if not behavior:
                continue
            signals = behavior.ingest(event)
            if not signals:
                continue
            detection = decide(event.get("type", "sysmon"), signals)
            ship_log(shipper, {"type": "sysmon.detection", "event": event, "signals": signals, "detection": detection})
            if args.json:
                print(json.dumps({"type": "sysmon.detection", "event": event, "signals": signals, "detection": detection}, indent=2), flush=True)
            else:
                print(f"Sysmon detection: score={detection['score']} severity={detection['severity']} action={detection['action']}", flush=True)
                for item in signals:
                    print(f"- [{item['severity']}] {item['source']}/{item['category']}: {item['message']}", flush=True)

    count = collect_sysmon(
        args.out,
        since_minutes=args.since_minutes,
        follow=args.follow,
        interval=args.interval,
        on_events=on_events if (args.analyze or shipper.enabled) else None,
    )
    if not args.follow:
        print(f"Wrote {count} Sysmon event records to {args.out}")
    return 0


def command_server(args):
    return run_server(host=args.host, port=args.port, db_path=args.db, api_key=args.api_key, jsonl_path=args.jsonl)


def create_scanner(args):
    vt = VirusTotalClient.maybe(args.virustotal_config, force_enabled=args.virustotal)
    return StaticScanner(IocStore(args.ioc_dir), args.rules, virustotal=vt)


def create_shipper(args):
    return LogShipper(
        server_url=getattr(args, "server_url", None),
        agent_id=getattr(args, "agent_id", None),
        api_key=getattr(args, "api_key", None),
    )


def ship_log(shipper, event):
    if not shipper.enabled:
        return
    result = shipper.send(event)
    if not result.get("sent"):
        print(f"Warning: failed to ship log to EDR server: {result.get('error') or result.get('status')}", file=sys.stderr)


def scan_one(scanner, file_path, args):
    result = scanner.scan_file(file_path, debug=args.debug)
    detection = decide(file_path, result["signals"])
    actions = apply_response(detection, file_path=file_path, quarantine=args.quarantine, state_dir=args.state_dir)
    if args.debug:
        result.setdefault("debug_trace", []).append({"check": "decision.scoring", "status": "clean" if detection["action"] == "allow" else "hit", "message": "Signals were scored and mapped to a response threshold.", "details": {"total_score": detection["score"], "severity": detection["severity"], "action": detection["action"]}})
        result["debug_trace"].append({"check": "response.actions", "status": "ok" if actions else "skipped", "message": "Response actions were planned or applied." if actions else "No response action needed.", "details": {"actions": [f"{item['type']}:{item['status']}" for item in actions]}})
    return {**result, "detection": detection, "actions": actions}


def walk_files(target):
    target = Path(target)
    if target.is_file():
        yield target
    elif target.is_dir():
        for path in target.rglob("*"):
            if path.is_file():
                yield path


def print_scan(result, debug=False, prefix=""):
    print(str(result["file"]))
    print(f"  {prefix}score={result['detection']['score']} severity={result['detection']['severity']} action={result['detection']['action']}")
    print(f"  sha256={result['hashes']['sha256']}")
    if debug:
        print("  debug checks:")
        for item in result.get("debug_trace", []):
            print(f"    - {item['status'].upper()} {item['check']}: {item['message']}")
    for item in result["signals"]:
        print(f"  - [{item['severity']}] {item['category']}: {item['message']}")
    for action in result["actions"]:
        note = f" ({action['note']})" if action.get("note") else ""
        print(f"  action: {action['type']} {action['status']}{note}")
