import time
from pathlib import Path


class PollingRealtimeWatcher:
    def __init__(
        self,
        targets,
        scan_file,
        on_result,
        interval=1.0,
        initial_scan=False,
        on_heartbeat=None,
        heartbeat_interval=60.0,
    ):
        self.targets = [Path(item).resolve() for item in targets]
        self.scan_file = scan_file
        self.on_result = on_result
        self.interval = interval
        self.initial_scan = initial_scan
        self.on_heartbeat = on_heartbeat
        self.heartbeat_interval = heartbeat_interval
        self.last_heartbeat = 0.0
        self.seen = {}
        self.running = False

    def start(self):
        self.running = True
        self.emit_heartbeat(force=True)
        if not self.initial_scan:
            self.seen = self.snapshot()
        while self.running:
            self.emit_heartbeat()
            current = self.snapshot()
            for path, stamp in current.items():
                if self.seen.get(path) != stamp:
                    result = self.scan_file(path)
                    self.on_result(result)
            self.seen = current
            time.sleep(self.interval)

    def stop(self):
        self.running = False

    def emit_heartbeat(self, force=False):
        if not self.on_heartbeat:
            return
        now = time.monotonic()
        if not force and now - self.last_heartbeat < self.heartbeat_interval:
            return
        self.last_heartbeat = now
        self.on_heartbeat(
            {
                "type": "agent.heartbeat",
                "mode": "watch",
                "targets": [str(item) for item in self.targets],
                "interval": self.interval,
            }
        )

    def snapshot(self):
        out = {}
        for target in self.targets:
            if target.is_file():
                add_file(out, target)
            elif target.is_dir():
                for path in target.rglob("*"):
                    if path.is_file():
                        add_file(out, path)
        return out


def add_file(mapping, path):
    try:
        stat = path.stat()
        mapping[str(path)] = (stat.st_size, stat.st_mtime_ns)
    except OSError:
        return
