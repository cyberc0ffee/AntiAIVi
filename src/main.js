#!/usr/bin/env node
import path from "node:path";
import { StaticEngine } from "./static/static-engine.js";
import { IocStore } from "./threat-intel/ioc-store.js";
import { DecisionEngine } from "./decision/decision-engine.js";
import { ResponseEngine } from "./response/response-engine.js";
import { BehaviorEngine } from "./behavior/behavior-engine.js";
import { replayJsonl } from "./behavior/event-collector.js";
import { CorrelationEngine } from "./correlation/correlation-engine.js";
import { UpdateEngine } from "./update/update-engine.js";
import { QuarantineStore } from "./response/quarantine.js";
import { VirusTotalClient } from "./threat-intel/virustotal-client.js";
import { RealtimeProtectionEngine } from "./realtime/realtime-engine.js";
import { walkTargets } from "./core/file-walk.js";
import { defaultIocDir, defaultRulesFile, defaultStateDir, defaultVirusTotalConfig } from "./core/paths.js";

async function main() {
  const [command, ...args] = process.argv.slice(2);
  try {
    switch (command) {
      case "scan":
        await scanCommand(args);
        break;
      case "watch":
        await watchCommand(args);
        break;
      case "replay":
        await replayCommand(args);
        break;
      case "update":
        await updateCommand(args);
        break;
      case "quarantine":
        await quarantineCommand(args);
        break;
      case "help":
      case undefined:
        printHelp();
        break;
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  }
}

async function scanCommand(args) {
  const options = parseOptions(args, {
    boolean: new Set(["json", "quarantine", "debug", "virustotal"]),
    value: new Set(["ioc-dir", "rules", "state-dir", "virustotal-config"])
  });
  if (options.positionals.length === 0) {
    throw new Error("scan requires at least one file or directory");
  }

  const scanContext = await createScanContext(options);
  const results = [];
  for await (const file of walkTargets(options.positionals)) {
    const result = await runStaticScan(file, scanContext, {
      debug: options.flags.debug,
      virustotalConfig: options.values["virustotal-config"] ?? defaultVirusTotalConfig
    });
    results.push(result);
    if (!options.flags.json) printScanResult(result, { debug: options.flags.debug });
  }

  if (options.flags.json) {
    console.log(JSON.stringify(results, null, 2));
  }
}

async function watchCommand(args) {
  const options = parseOptions(args, {
    boolean: new Set(["json", "quarantine", "debug", "virustotal", "initial-scan"]),
    value: new Set(["ioc-dir", "rules", "state-dir", "virustotal-config", "debounce-ms"])
  });
  if (options.positionals.length === 0) {
    throw new Error("watch requires at least one file or directory");
  }

  const scanContext = await createScanContext(options);
  const virustotalConfig = options.values["virustotal-config"] ?? defaultVirusTotalConfig;
  const watcher = new RealtimeProtectionEngine({
    targets: options.positionals,
    debounceMs: Number(options.values["debounce-ms"] ?? 750),
    initialScan: options.flags["initial-scan"],
    scanFile: async (file, { eventType }) => {
      return runStaticScan(file, scanContext, {
        debug: options.flags.debug,
        virustotalConfig,
        realtimeEvent: eventType
      });
    },
    onResult: async (result) => {
      if (options.flags.json) {
        console.log(JSON.stringify({ type: "realtime.scan", result }, null, 2));
      } else {
        printRealtimeResult(result, { debug: options.flags.debug });
      }
    },
    onError: (error, context) => {
      const target = context?.target ? ` ${context.target}` : "";
      console.error(`Realtime protection error${target}: ${error.message}`);
    }
  });

  await watcher.start();
  if (!options.flags.json) {
    console.log("Realtime protection active. Press Ctrl+C to stop.");
    for (const target of options.positionals) {
      console.log(`  watching: ${path.resolve(target)}`);
    }
  }

  await waitUntilInterrupted(async () => watcher.stop());
}

async function createScanContext(options) {
  const iocStore = await IocStore.load(options.values["ioc-dir"] ?? defaultIocDir);
  const virustotalConfig = options.values["virustotal-config"] ?? defaultVirusTotalConfig;
  const virustotalClient = await VirusTotalClient.fromConfig(virustotalConfig, {
    forceEnabled: options.flags.virustotal
  });
  const staticEngine = await StaticEngine.create({
    iocStore,
    rulesFile: options.values.rules ?? defaultRulesFile,
    virustotalClient
  });
  const decisionEngine = new DecisionEngine();
  const responseEngine = new ResponseEngine({
    stateDir: options.values["state-dir"] ?? defaultStateDir,
    enableQuarantine: options.flags.quarantine
  });

  return {
    staticEngine,
    decisionEngine,
    responseEngine,
    virustotalClient
  };
}

async function runStaticScan(file, context, { debug = false, virustotalConfig = defaultVirusTotalConfig, realtimeEvent = null } = {}) {
  const result = await context.staticEngine.scanFile(file, { debug });
  const detection = context.decisionEngine.decide({ subject: file, signals: result.signals });
  const actions = await context.responseEngine.apply(detection, { file });
  if (debug) {
    if (realtimeEvent) {
      result.debug_trace.push({
        check: "realtime.event",
        status: "ok",
        message: "File system event triggered this scan.",
        details: { event_type: realtimeEvent }
      });
    }
    if (!context.virustotalClient) {
      result.debug_trace.push({
        check: "virustotal.config",
        status: "skipped",
        message: "VirusTotal lookup is disabled.",
        details: {
          config: virustotalConfig,
          enable_with: "--virustotal or config enabled=true"
        }
      });
    }
    result.debug_trace.push({
      check: "decision.scoring",
      status: detection.action === "allow" ? "clean" : "hit",
      message: "Signals were scored and mapped to a response threshold.",
      details: {
        total_score: detection.score,
        severity: detection.severity,
        action: detection.action,
        signals_count: result.signals.length,
        thresholds: "0-39 allow, 40-69 monitor, 70-99 suspend, 100+ kill_quarantine"
      }
    });
    result.debug_trace.push({
      check: "response.actions",
      status: actions.length > 0 ? "ok" : "skipped",
      message: actions.length > 0 ? "Response actions were planned or applied." : "No response action needed.",
      details: {
        actions: actions.map((action) => `${action.type}:${action.status}`)
      }
    });
  }
  return { ...result, detection, actions };
}

async function replayCommand(args) {
  const options = parseOptions(args, {
    boolean: new Set(["json"]),
    value: new Set(["ioc-dir", "ransomware-threshold"])
  });
  const file = options.positionals[0];
  if (!file) throw new Error("replay requires a JSONL event file");

  const iocStore = await IocStore.load(options.values["ioc-dir"] ?? defaultIocDir);
  const behavior = new BehaviorEngine({
    iocStore,
    ransomwareFileThreshold: Number(options.values["ransomware-threshold"] ?? 500)
  });
  const correlation = new CorrelationEngine();
  const allSignals = [];

  await replayJsonl(file, async (event) => {
    const signals = behavior.ingest(event);
    const derived = correlation.addSignals(signals);
    allSignals.push(...signals, ...derived);
  });

  const decision = new DecisionEngine().decide({
    subject: path.resolve(file),
    signals: allSignals
  });

  const result = { file: path.resolve(file), signals: allSignals, detection: decision };
  if (options.flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printReplayResult(result);
  }
}

async function updateCommand(args) {
  const [subcommand, ...rest] = args;
  if (subcommand !== "validate") {
    throw new Error("update currently supports: update validate <manifest>");
  }
  const options = parseOptions(rest, {
    boolean: new Set(["json"]),
    value: new Set(["public-key"])
  });
  const manifest = options.positionals[0];
  if (!manifest) throw new Error("update validate requires a manifest path");
  const result = await new UpdateEngine().validateManifest(manifest, {
    publicKeyPath: options.values["public-key"]
  });
  if (options.flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(result.ok ? `Manifest OK: ${result.version}` : `Manifest invalid: ${result.errors.join("; ")}`);
  }
}

async function quarantineCommand(args) {
  const [subcommand, ...rest] = args;
  const options = parseOptions(rest, {
    boolean: new Set(["json"]),
    value: new Set(["state-dir"])
  });
  const store = new QuarantineStore(options.values["state-dir"] ?? defaultStateDir);

  if (subcommand === "list") {
    const entries = await store.list();
    if (options.flags.json) console.log(JSON.stringify(entries, null, 2));
    else printQuarantineList(entries);
    return;
  }

  if (subcommand === "restore") {
    const [id, destination] = options.positionals;
    if (!id || !destination) throw new Error("quarantine restore requires <id> <destination>");
    const result = await store.restore(id, destination);
    if (options.flags.json) console.log(JSON.stringify(result, null, 2));
    else console.log(`Restored ${id} to ${result.restored_to}`);
    return;
  }

  throw new Error("quarantine supports: list, restore <id> <destination>");
}

function parseOptions(args, schema) {
  const flags = {};
  const values = {};
  const positionals = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }

    const key = arg.slice(2);
    if (schema.boolean.has(key)) {
      flags[key] = true;
      continue;
    }
    if (schema.value.has(key)) {
      const value = args[index + 1];
      if (!value) throw new Error(`Missing value for --${key}`);
      values[key] = value;
      index += 1;
      continue;
    }
    throw new Error(`Unknown option: --${key}`);
  }

  return { flags, values, positionals };
}

function printScanResult(result, { debug = false } = {}) {
  const relative = path.relative(process.cwd(), result.file) || result.file;
  console.log(`${relative}`);
  console.log(`  score=${result.detection.score} severity=${result.detection.severity} action=${result.detection.action}`);
  console.log(`  sha256=${result.hashes.sha256}`);
  if (debug) {
    console.log("  debug checks:");
    for (const item of result.debug_trace ?? []) {
      console.log(`    - ${item.status.toUpperCase()} ${item.check}: ${item.message}`);
      const detailText = formatDebugDetails(item.details);
      if (detailText) console.log(`      ${detailText}`);
    }
  }
  for (const signal of result.signals) {
    console.log(`  - [${signal.severity}] ${signal.category}: ${signal.message}`);
  }
  for (const action of result.actions) {
    console.log(`  action: ${action.type} ${action.status}${action.note ? ` (${action.note})` : ""}`);
  }
}

function printRealtimeResult(result, { debug = false } = {}) {
  const timestamp = new Date().toISOString();
  const relative = path.relative(process.cwd(), result.file) || result.file;
  console.log(`[${timestamp}] ${relative}`);
  console.log(`  realtime score=${result.detection.score} severity=${result.detection.severity} action=${result.detection.action}`);
  if (debug) {
    console.log("  debug checks:");
    for (const item of result.debug_trace ?? []) {
      console.log(`    - ${item.status.toUpperCase()} ${item.check}: ${item.message}`);
      const detailText = formatDebugDetails(item.details);
      if (detailText) console.log(`      ${detailText}`);
    }
  }
  for (const signal of result.signals) {
    console.log(`  - [${signal.severity}] ${signal.category}: ${signal.message}`);
  }
  for (const action of result.actions) {
    console.log(`  action: ${action.type} ${action.status}${action.note ? ` (${action.note})` : ""}`);
  }
}

function formatDebugDetails(details) {
  if (!details || typeof details !== "object") return "";
  const entries = Object.entries(details).filter(([, value]) => value !== undefined);
  if (entries.length === 0) return "";
  return entries
    .map(([key, value]) => `${key}=${formatDebugValue(value)}`)
    .join(" ");
}

function formatDebugValue(value) {
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const preview = value.slice(0, 6).map((item) => {
      if (item && typeof item === "object") return JSON.stringify(item);
      return String(item);
    });
    return `[${preview.join(", ")}${value.length > preview.length ? ", ..." : ""}]`;
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function printReplayResult(result) {
  console.log(`Replay: ${result.file}`);
  console.log(`score=${result.detection.score} severity=${result.detection.severity} action=${result.detection.action}`);
  for (const signal of result.signals) {
    console.log(`- [${signal.severity}] ${signal.source}/${signal.category}: ${signal.message}`);
  }
}

function printQuarantineList(entries) {
  if (entries.length === 0) {
    console.log("Quarantine is empty.");
    return;
  }
  for (const entry of entries) {
    console.log(`${entry.id} score=${entry.detection_score} ${entry.original_path}`);
  }
}

function printHelp() {
  console.log(`AntiAiVi

Usage:
  node src/main.js scan <file-or-dir...> [--json] [--debug] [--virustotal] [--quarantine]
  node src/main.js watch <file-or-dir...> [--debug] [--virustotal] [--quarantine]
  node src/main.js replay <events.jsonl> [--json]
  node src/main.js update validate <manifest.json> [--public-key public.pem]
  node src/main.js quarantine list [--json]
  node src/main.js quarantine restore <id> <destination>

Options:
  --ioc-dir <dir>              Override IOC directory.
  --rules <file>               Override YARA-lite rules file.
  --state-dir <dir>            Override response/quarantine state directory.
  --virustotal                 Query VirusTotal by file hash using config/virustotal.json.
  --virustotal-config <file>   Override VirusTotal config path.
  --ransomware-threshold <n>   File events per minute threshold for replay.
  --initial-scan               Scan existing files when watch starts.
  --debounce-ms <n>            Realtime scan delay after a file event.
  --debug                      Show every static scan check for each file.
`);
}

function waitUntilInterrupted(onStop) {
  return new Promise((resolve) => {
    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      await onStop();
      resolve();
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
}

await main();
