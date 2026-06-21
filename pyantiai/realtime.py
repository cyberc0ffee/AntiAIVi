import time
from pathlib import Path


class PollingRealtimeWatcher:
    def __init__(self, targets, scan_file, on_result, interval=1.0, initial_scan=False):
        self.targets = [Path(item).resolve() for item in targets]
        self.scan_file = scan_file
        self.on_result = on_result
        self.interval = interval
        self.initial_scan = initial_scan
        self.seen = {}
        self.running = False

    def start(self):
        self.running = True
        if not self.initial_scan:
            self.seen = self.snapshot()
        while self.running:
            current = self.snapshot()
            for path, stamp in current.items():
                if self.seen.get(path) != stamp:
                    result = self.scan_file(path)
                    self.on_result(result)
            self.seen = current
            time.sleep(self.interval)

    def stop(self):
        self.running = False

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
