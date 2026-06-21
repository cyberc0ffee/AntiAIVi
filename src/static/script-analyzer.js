import path from "node:path";
import { promises as fs } from "node:fs";
import { createSignal, Severity } from "../core/severity.js";

const SCRIPT_EXTENSIONS = new Set([".ps1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd"]);

const RULES = [
  {
    category: "powershell_encoded_command",
    score: 30,
    severity: Severity.HIGH,
    extensions: [".ps1", ".bat", ".cmd"],
    regex: /(?:-|\/)(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i,
    message: "PowerShell encoded command detected."
  },
  {
    category: "powershell_downloader",
    score: 35,
    severity: Severity.HIGH,
    extensions: [".ps1"],
    regex: /\b(?:IEX|Invoke-Expression)\b[\s\S]{0,120}\b(?:DownloadString|Invoke-WebRequest|curl|wget)\b/i,
    message: "PowerShell download-and-execute pattern detected."
  },
  {
    category: "base64_payload",
    score: 25,
    severity: Severity.MEDIUM,
    extensions: [".ps1", ".js", ".vbs"],
    regex: /\b(?:FromBase64String|atob)\s*\(/i,
    message: "Base64 decoding primitive detected."
  },
  {
    category: "js_activex",
    score: 35,
    severity: Severity.HIGH,
    extensions: [".js", ".jse", ".vbs", ".vbe"],
    regex: /\bActiveXObject\b[\s\S]{0,200}\b(?:WScript\.Shell|MSXML2\.XMLHTTP|ADODB\.Stream)\b/i,
    message: "Windows Script Host ActiveX automation pattern detected."
  },
  {
    category: "lolbin_download",
    score: 30,
    severity: Severity.MEDIUM,
    extensions: [".bat", ".cmd", ".ps1"],
    regex: /\b(?:certutil|bitsadmin)\b[\s\S]{0,120}\b(?:-urlcache|-split|\/transfer|http:\/\/|https:\/\/)/i,
    message: "LOLBIN download command detected."
  },
  {
    category: "shadow_copy_delete",
    score: 80,
    severity: Severity.CRITICAL,
    extensions: [".bat", ".cmd", ".ps1"],
    regex: /\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+\/set\s+\{default\}\s+recoveryenabled\s+no)\b/i,
    message: "Shadow copy deletion or recovery disabling command detected."
  }
];

export async function analyzeScript(filePath, { debug = false } = {}) {
  const extension = path.extname(filePath).toLowerCase();
  if (!SCRIPT_EXTENSIONS.has(extension)) {
    return {
      isScript: false,
      signals: [],
      debug: debug
        ? [
            {
              check: "script.extension",
              status: "skipped",
              message: "File extension is not handled by the script analyzer.",
              details: {
                extension: extension || "(none)",
                supported_extensions: [...SCRIPT_EXTENSIONS]
              }
            }
          ]
        : []
    };
  }

  const content = await fs.readFile(filePath, "utf8");
  const signals = [];
  const trace = debug
    ? [
        {
          check: "script.extension",
          status: "ok",
          message: "File extension is handled by the script analyzer.",
          details: { extension }
        },
        {
          check: "script.read",
          status: "ok",
          message: "Script content loaded for heuristic rules.",
          details: { bytes: Buffer.byteLength(content, "utf8") }
        }
      ]
    : [];

  for (const rule of RULES) {
    if (!rule.extensions.includes(extension)) {
      if (debug) {
        trace.push({
          check: `script.rule.${rule.category}`,
          status: "skipped",
          message: "Rule does not apply to this script extension.",
          details: { extension, rule_extensions: rule.extensions }
        });
      }
      continue;
    }
    const match = content.match(rule.regex);
    if (debug) {
      trace.push({
        check: `script.rule.${rule.category}`,
        status: match ? "hit" : "clean",
        message: match ? rule.message : "Script heuristic did not match.",
        details: {
          extension,
          score: rule.score,
          severity: rule.severity,
          excerpt: match ? excerpt(content, match.index ?? 0) : undefined
        }
      });
    }
    if (!match) continue;
    signals.push(
      createSignal({
        source: "static.script",
        category: rule.category,
        score: rule.score,
        severity: rule.severity,
        subject: filePath,
        message: rule.message,
        evidence: {
          extension,
          excerpt: excerpt(content, match.index ?? 0)
        }
      })
    );
  }

  return { isScript: true, signals, debug: trace };
}

function excerpt(content, index) {
  const start = Math.max(0, index - 40);
  const end = Math.min(content.length, index + 120);
  return content.slice(start, end).replace(/\s+/g, " ").trim();
}
