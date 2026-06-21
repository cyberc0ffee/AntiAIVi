import { promises as fs } from "node:fs";
import { loadJson } from "../core/json.js";
import { createSignal } from "../core/severity.js";

const MAX_TEXT_BYTES = 10 * 1024 * 1024;

export async function loadYaraLiteRules(rulesFile) {
  const ruleset = await loadJson(rulesFile, { rules: [] });
  return Array.isArray(ruleset.rules) ? ruleset.rules : [];
}

export async function scanYaraLite(filePath, rules, { debug = false } = {}) {
  if (!rules.length) {
    return {
      signals: [],
      debug: debug
        ? [
            {
              check: "yara-lite.rules",
              status: "skipped",
              message: "No YARA-lite rules loaded.",
              details: { rules_loaded: 0 }
            }
          ]
        : []
    };
  }

  const handle = await fs.open(filePath, "r");
  try {
    const stat = await handle.stat();
    const size = Math.min(stat.size, MAX_TEXT_BYTES);
    const buffer = Buffer.alloc(size);
    await handle.read(buffer, 0, size, 0);
    const binaryText = buffer.toString("latin1");
    const utf8Text = buffer.toString("utf8");
    return matchRules(filePath, binaryText, utf8Text, rules, {
      debug,
      bytesScanned: size,
      truncated: stat.size > MAX_TEXT_BYTES
    });
  } finally {
    await handle.close();
  }
}

function matchRules(filePath, binaryText, utf8Text, rules, { debug = false, bytesScanned = 0, truncated = false } = {}) {
  const signals = [];
  const trace = [];

  if (debug) {
    trace.push({
      check: "yara-lite.scan-window",
      status: "ok",
      message: "Loaded file bytes for YARA-lite matching.",
      details: {
        rules_loaded: rules.length,
        bytes_scanned: bytesScanned,
        truncated
      }
    });
  }

  for (const rule of rules) {
    const patternResults = (rule.patterns ?? []).map((pattern) => matchPattern(pattern, binaryText, utf8Text));
    const matched = rule.match === "all" ? patternResults.every(Boolean) : patternResults.some(Boolean);
    if (debug) {
      trace.push({
        check: `yara-lite.rule.${rule.id ?? rule.name ?? "unnamed"}`,
        status: matched ? "hit" : "clean",
        message: matched
          ? `Rule matched: ${rule.name ?? rule.id ?? "unnamed"}.`
          : `Rule did not match: ${rule.name ?? rule.id ?? "unnamed"}.`,
        details: {
          category: rule.category ?? "signature",
          match_mode: rule.match ?? "any",
          patterns_checked: (rule.patterns ?? []).length,
          matched_patterns: (rule.patterns ?? [])
            .filter((_, index) => patternResults[index])
            .map((pattern) => pattern.text ?? pattern.regex ?? pattern.hex)
        }
      });
    }
    if (!matched) continue;

    signals.push(
      createSignal({
        source: "static.yara-lite",
        category: rule.category ?? "signature",
        score: rule.score ?? 50,
        severity: rule.severity,
        subject: filePath,
        message: `Rule matched: ${rule.name ?? rule.id ?? "unnamed"}.`,
        evidence: {
          rule_id: rule.id,
          rule_name: rule.name,
          matched_patterns: (rule.patterns ?? [])
            .filter((_, index) => patternResults[index])
            .map((pattern) => pattern.text ?? pattern.regex ?? pattern.hex)
        }
      })
    );
  }

  return { signals, debug: trace };
}

function matchPattern(pattern, binaryText, utf8Text) {
  if (pattern.text !== undefined) {
    const needle = pattern.nocase ? pattern.text.toLowerCase() : pattern.text;
    const haystack = pattern.nocase ? binaryText.toLowerCase() : binaryText;
    return haystack.includes(needle);
  }

  if (pattern.regex !== undefined) {
    const flags = pattern.nocase ? "i" : "";
    return new RegExp(pattern.regex, flags).test(utf8Text);
  }

  if (pattern.hex !== undefined) {
    const normalized = pattern.hex.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
    return Buffer.from(binaryText, "latin1").toString("hex").includes(normalized);
  }

  return false;
}
