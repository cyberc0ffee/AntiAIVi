import { promises as fs } from "node:fs";
import { createSignal, Severity } from "../core/severity.js";
import { loadJson } from "../core/json.js";

const DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3";

export class VirusTotalClient {
  constructor({
    apiKey,
    baseUrl = DEFAULT_BASE_URL,
    timeoutMs = 15000,
    minimumMalicious = 1,
    minimumSuspicious = 3
  }) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeoutMs = timeoutMs;
    this.minimumMalicious = minimumMalicious;
    this.minimumSuspicious = minimumSuspicious;
  }

  static async fromConfig(configPath, { forceEnabled = false } = {}) {
    const exists = await fileExists(configPath);
    if (!exists && !forceEnabled) return null;
    if (!exists && forceEnabled) {
      throw new Error(`VirusTotal config not found: ${configPath}`);
    }

    const config = await loadJson(configPath);
    const enabled = forceEnabled || config.enabled === true;
    if (!enabled) return null;

    const apiKey = process.env.VIRUSTOTAL_API_KEY || config.api_key;
    if (!apiKey || apiKey.includes("INSERISCI_LA_TUA_CHIAVE")) {
      throw new Error(`VirusTotal API key missing. Edit ${configPath} or set VIRUSTOTAL_API_KEY.`);
    }

    return new VirusTotalClient({
      apiKey,
      baseUrl: config.base_url ?? DEFAULT_BASE_URL,
      timeoutMs: Number(config.timeout_ms ?? 15000),
      minimumMalicious: Number(config.minimum_malicious ?? 1),
      minimumSuspicious: Number(config.minimum_suspicious ?? 3)
    });
  }

  async scanHashes(filePath, hashes, { debug = false } = {}) {
    const trace = [];
    const signals = [];
    const hash = hashes.sha256 || hashes.sha1 || hashes.md5;

    if (debug) {
      trace.push({
        check: "virustotal.lookup.request",
        status: "ok",
        message: "VirusTotal hash report lookup requested.",
        details: {
          endpoint: `${this.baseUrl}/files/{id}`,
          id_type: hashes.sha256 ? "sha256" : hashes.sha1 ? "sha1" : "md5",
          uploads_file_content: false
        }
      });
    }

    try {
      const report = await this.getFileReport(hash);
      if (!report.found) {
        if (debug) {
          trace.push({
            check: "virustotal.lookup.response",
            status: "clean",
            message: "VirusTotal has no report for this hash.",
            details: { http_status: report.status }
          });
        }
        return { signals, debug: trace, report: null };
      }

      const attributes = report.data?.attributes ?? {};
      const stats = attributes.last_analysis_stats ?? {};
      const malicious = Number(stats.malicious ?? 0);
      const suspicious = Number(stats.suspicious ?? 0);
      const totalEngines = Object.values(stats).reduce((sum, value) => sum + Number(value ?? 0), 0);
      const hit = malicious >= this.minimumMalicious || suspicious >= this.minimumSuspicious;

      if (debug) {
        trace.push({
          check: "virustotal.lookup.response",
          status: hit ? "hit" : "clean",
          message: hit
            ? "VirusTotal report reached the configured detection threshold."
            : "VirusTotal report is below the configured detection threshold.",
          details: {
            malicious,
            suspicious,
            harmless: Number(stats.harmless ?? 0),
            undetected: Number(stats.undetected ?? 0),
            timeout: Number(stats.timeout ?? 0),
            total_engines: totalEngines,
            reputation: attributes.reputation,
            first_submission_date: formatUnixDate(attributes.first_submission_date),
            last_analysis_date: formatUnixDate(attributes.last_analysis_date),
            threshold: `${this.minimumMalicious}+ malicious or ${this.minimumSuspicious}+ suspicious`
          }
        });
      }

      if (hit) {
        signals.push(
          createSignal({
            source: "threat-intel.virustotal",
            category: "virustotal_detection",
            score: scoreFromStats(malicious, suspicious),
            severity: severityFromStats(malicious, suspicious),
            subject: filePath,
            message: "VirusTotal report contains malicious or suspicious detections.",
            evidence: {
              sha256: hashes.sha256,
              malicious,
              suspicious,
              total_engines: totalEngines,
              reputation: attributes.reputation,
              permalink: hashes.sha256 ? `https://www.virustotal.com/gui/file/${hashes.sha256}` : undefined
            }
          })
        );
      }

      return {
        signals,
        debug: trace,
        report: {
          id: report.data?.id,
          type: report.data?.type,
          malicious,
          suspicious,
          total_engines: totalEngines
        }
      };
    } catch (error) {
      if (debug) {
        trace.push({
          check: "virustotal.lookup.error",
          status: "error",
          message: "VirusTotal lookup failed.",
          details: { error: error.message }
        });
      }
      return { signals, debug: trace, report: null };
    }
  }

  async getFileReport(id) {
    if (typeof fetch !== "function") {
      throw new Error("This Node.js runtime does not provide fetch().");
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl}/files/${encodeURIComponent(id)}`, {
        method: "GET",
        headers: {
          accept: "application/json",
          "x-apikey": this.apiKey
        },
        signal: controller.signal
      });

      const body = await response.json().catch(() => ({}));
      if (response.status === 404) return { found: false, status: response.status };
      if (!response.ok) {
        const message = body?.error?.message || body?.message || response.statusText;
        throw new Error(`HTTP ${response.status}: ${message}`);
      }
      return { found: true, status: response.status, data: body.data };
    } finally {
      clearTimeout(timer);
    }
  }
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function scoreFromStats(malicious, suspicious) {
  return Math.min(100, 40 + malicious * 10 + suspicious * 5);
}

function severityFromStats(malicious, suspicious) {
  if (malicious >= 5) return Severity.CRITICAL;
  if (malicious >= 1 || suspicious >= 3) return Severity.HIGH;
  if (suspicious > 0) return Severity.MEDIUM;
  return Severity.LOW;
}

function formatUnixDate(value) {
  if (!value) return undefined;
  return new Date(Number(value) * 1000).toISOString();
}
