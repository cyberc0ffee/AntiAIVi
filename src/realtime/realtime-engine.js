import { promises as fs, watch as watchFs } from "node:fs";
import path from "node:path";

export class RealtimeProtectionEngine {
  constructor({
    targets,
    scanFile,
    onResult,
    onError = defaultErrorHandler,
    debounceMs = 750,
    initialScan = false
  }) {
    this.targets = targets.map((target) => path.resolve(target));
    this.scanFile = scanFile;
    this.onResult = onResult;
    this.onError = onError;
    this.debounceMs = debounceMs;
    this.initialScan = initialScan;
    this.watchers = [];
    this.pending = new Map();
    this.inFlight = new Set();
    this.stopped = false;
  }

  async start() {
    if (this.targets.length === 0) {
      throw new Error("watch requires at least one file or directory");
    }

    for (const target of this.targets) {
      const stat = await fs.stat(target);
      if (stat.isDirectory()) {
        await this.watchDirectory(target);
      } else if (stat.isFile()) {
        await this.watchFile(target);
      }
    }
  }

  async stop() {
    this.stopped = true;
    for (const timer of this.pending.values()) clearTimeout(timer);
    this.pending.clear();
    for (const watcher of this.watchers) watcher.close();
    this.watchers = [];
  }

  async watchDirectory(directory) {
    if (this.initialScan) {
      await this.scheduleExistingFiles(directory);
    }

    const watcher = watchFs(directory, { recursive: true }, (eventType, filename) => {
      if (!filename) return;
      const fullPath = path.resolve(directory, filename.toString());
      this.schedule(fullPath, eventType);
    });
    watcher.on("error", (error) => this.onError(error, { target: directory }));
    this.watchers.push(watcher);
  }

  async watchFile(filePath) {
    if (this.initialScan) {
      this.schedule(filePath, "initial");
    }

    const watcher = watchFs(filePath, {}, (eventType) => {
      this.schedule(filePath, eventType);
    });
    watcher.on("error", (error) => this.onError(error, { target: filePath }));
    this.watchers.push(watcher);
  }

  async scheduleExistingFiles(directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await this.scheduleExistingFiles(fullPath);
      } else if (entry.isFile()) {
        this.schedule(fullPath, "initial");
      }
    }
  }

  schedule(filePath, eventType) {
    if (this.stopped) return;
    const normalized = path.resolve(filePath);
    const existing = this.pending.get(normalized);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(() => {
      this.pending.delete(normalized);
      this.scanWhenReady(normalized, eventType).catch((error) => {
        this.onError(error, { target: normalized, eventType });
      });
    }, this.debounceMs);
    this.pending.set(normalized, timer);
  }

  async scanWhenReady(filePath, eventType) {
    if (this.inFlight.has(filePath)) {
      this.schedule(filePath, "rescheduled");
      return;
    }

    this.inFlight.add(filePath);
    try {
      const stat = await fs.stat(filePath).catch((error) => {
        if (error.code === "ENOENT" || error.code === "EPERM" || error.code === "EACCES") return null;
        throw error;
      });
      if (!stat || !stat.isFile()) return;

      await waitForStableSize(filePath, this.debounceMs);
      const result = await this.scanFile(filePath, { eventType });
      await this.onResult(result);
    } finally {
      this.inFlight.delete(filePath);
    }
  }
}

async function waitForStableSize(filePath, delayMs) {
  const first = await fs.stat(filePath);
  await new Promise((resolve) => setTimeout(resolve, Math.min(delayMs, 1000)));
  const second = await fs.stat(filePath);
  if (first.size !== second.size || first.mtimeMs !== second.mtimeMs) {
    await new Promise((resolve) => setTimeout(resolve, Math.min(delayMs, 1000)));
  }
}

function defaultErrorHandler(error) {
  console.error(`Realtime protection error: ${error.message}`);
}
