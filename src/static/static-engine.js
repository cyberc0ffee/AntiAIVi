import { promises as fs } from "node:fs";
import { scanHashes } from "./hash-scanner.js";
import { analyzeScript } from "./script-analyzer.js";
import { analyzePe } from "./pe-analyzer.js";
import { loadYaraLiteRules, scanYaraLite } from "./yara-lite.js";

export class StaticEngine {
  constructor({ iocStore, rules = [], virustotalClient = null }) {
    this.iocStore = iocStore;
    this.rules = rules;
    this.virustotalClient = virustotalClient;
  }

  static async create({ iocStore, rulesFile, virustotalClient = null }) {
    const rules = rulesFile ? await loadYaraLiteRules(rulesFile) : [];
    return new StaticEngine({ iocStore, rules, virustotalClient });
  }

  async scanFile(filePath, { debug = false } = {}) {
    const stat = await fs.stat(filePath);
    const trace = debug
      ? [
          {
            check: "file.stat",
            status: "ok",
            message: "File metadata loaded.",
            details: {
              size: stat.size,
              modified: stat.mtime.toISOString(),
              created: stat.birthtime.toISOString()
            }
          }
        ]
      : [];
    const hashResult = await scanHashes(filePath, this.iocStore, { debug });
    const virustotalResult = this.virustotalClient
      ? await this.virustotalClient.scanHashes(filePath, hashResult.hashes, { debug })
      : { signals: [], debug: [], report: null };
    const yaraResult = await scanYaraLite(filePath, this.rules, { debug });
    const peResult = await analyzePe(filePath, { debug });
    const scriptResult = await analyzeScript(filePath, { debug });
    trace.push(
      ...hashResult.debug,
      ...virustotalResult.debug,
      ...yaraResult.debug,
      ...peResult.debug,
      ...scriptResult.debug
    );

    const result = {
      file: filePath,
      size: stat.size,
      hashes: hashResult.hashes,
      virustotal: virustotalResult.report,
      pe: peResult.details,
      signals: [
        ...hashResult.signals,
        ...virustotalResult.signals,
        ...yaraResult.signals,
        ...peResult.signals,
        ...scriptResult.signals
      ]
    };
    if (debug) result.debug_trace = trace;
    return result;
  }
}
