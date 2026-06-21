import path from "node:path";
import { createSignal, Severity } from "../core/severity.js";

const OFFICE_IMAGES = new Set(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"]);
const LOLBINS = new Set([
  "powershell.exe",
  "pwsh.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "certutil.exe",
  "wscript.exe",
  "cscript.exe",
  "cmd.exe"
]);

const PERSISTENCE_KEYS = [
  "\\currentversion\\run",
  "\\currentversion\\runonce",
  "\\services\\",
  "\\scheduled tasks\\",
  "\\startup"
];

export class BehaviorEngine {
  constructor({ iocStore, ransomwareFileThreshold = 500 } = {}) {
    this.iocStore = iocStore;
    this.ransomwareFileThreshold = ransomwareFileThreshold;
    this.processes = new Map();
    this.fileWindows = new Map();
    this.memoryOps = new Map();
    this.networkWindows = new Map();
    this.emittedKeys = new Set();
  }

  ingest(event) {
    switch (event.type) {
      case "process.start":
        return this.handleProcessStart(event);
      case "process.access":
        return this.handleProcessAccess(event);
      case "file.write":
      case "file.rename":
      case "file.delete":
        return this.handleFileEvent(event);
      case "registry.set":
      case "registry.create":
        return this.handleRegistryEvent(event);
      case "memory.api":
        return this.handleMemoryEvent(event);
      case "network.dns":
        return this.handleDnsEvent(event);
      case "network.connect":
        return this.handleNetworkConnect(event);
      default:
        return [];
    }
  }

  handleProcessStart(event) {
    const image = basename(event.image);
    const parent = this.processes.get(Number(event.ppid));
    const commandline = event.commandline ?? "";
    this.processes.set(Number(event.pid), { ...event, image });

    const signals = [];
    if (parent && OFFICE_IMAGES.has(parent.image) && LOLBINS.has(image)) {
      signals.push(this.once(`office-lolbin:${event.pid}`, {
        source: "behavior.process",
        category: "office_lolbin_chain",
        score: 65,
        severity: Severity.HIGH,
        subject: pidSubject(event.pid, image),
        message: "Office process spawned a LOLBIN child process.",
        evidence: { parent: parent.image, child: image, commandline }
      }));
    }

    if (LOLBINS.has(image) && /(?:downloadstring|invoke-webrequest|curl|wget|http:\/\/|https:\/\/)/i.test(commandline)) {
      signals.push(this.once(`lolbin-download:${event.pid}`, {
        source: "behavior.lolbin",
        category: "lolbin_download_execute",
        score: 70,
        severity: Severity.HIGH,
        subject: pidSubject(event.pid, image),
        message: "LOLBIN command line contains network download indicators.",
        evidence: { image, commandline }
      }));
    }

    if (/(?:-|\/)(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i.test(commandline)) {
      signals.push(this.once(`encoded-command:${event.pid}`, {
        source: "behavior.process",
        category: "powershell_encoded_command",
        score: 30,
        severity: Severity.HIGH,
        subject: pidSubject(event.pid, image),
        message: "Encoded command line detected.",
        evidence: { image, commandline }
      }));
    }

    if (/\\appdata\\/i.test(commandline) && !isTrustedSigner(event.signer)) {
      signals.push(this.once(`appdata-exec:${event.pid}`, {
        source: "behavior.process",
        category: "appdata_execution",
        score: 15,
        severity: Severity.MEDIUM,
        subject: pidSubject(event.pid, image),
        message: "Unsigned process launched from AppData path.",
        evidence: { image, signer: event.signer, commandline }
      }));
    }

    return compact(signals);
  }

  handleProcessAccess(event) {
    const target = basename(event.target_image);
    if (target !== "lsass.exe") return [];
    const suspiciousApi = /^(OpenProcess|ReadProcessMemory|MiniDumpWriteDump)$/i.test(event.api ?? "");
    if (!suspiciousApi || isTrustedSigner(event.signer)) return [];

    return compact([
      this.once(`lsass:${event.pid}:${event.api}`, {
        source: "behavior.credential",
        category: "lsass_access",
        score: 90,
        severity: Severity.CRITICAL,
        subject: pidSubject(event.pid, basename(event.image)),
        message: "Unsigned process accessed LSASS with credential-theft API.",
        evidence: {
          api: event.api,
          target_pid: event.target_pid,
          signer: event.signer
        }
      })
    ]);
  }

  handleFileEvent(event) {
    const pid = Number(event.pid ?? 0);
    const timestamp = Date.parse(event.timestamp);
    const window = this.fileWindows.get(pid) ?? [];
    window.push(event);
    const recent = window.filter((item) => timestamp - Date.parse(item.timestamp) <= 60_000);
    this.fileWindows.set(pid, recent);

    const writes = recent.filter((item) => item.type === "file.write").length;
    const renames = recent.filter((item) => item.type === "file.rename").length;
    const entropyDelta = recent.some((item) => Number(item.entropy_delta ?? 0) >= 1.0);
    const newExtensions = new Set(recent.map((item) => item.new_extension).filter(Boolean));

    if (writes + renames >= this.ransomwareFileThreshold && entropyDelta && newExtensions.size > 0) {
      return compact([
        this.once(`ransomware:${pid}:${Math.floor(timestamp / 60_000)}`, {
          source: "behavior.file",
          category: "ransomware_file_burst",
          score: 95,
          severity: Severity.CRITICAL,
          subject: pidSubject(pid, this.processes.get(pid)?.image),
          message: "Ransomware-like file modification burst detected.",
          evidence: {
            writes,
            renames,
            extensions: [...newExtensions],
            threshold: this.ransomwareFileThreshold
          }
        })
      ]);
    }

    return [];
  }

  handleRegistryEvent(event) {
    const key = String(event.key ?? "").toLowerCase();
    if (!PERSISTENCE_KEYS.some((indicator) => key.includes(indicator))) return [];
    return compact([
      this.once(`persistence:${event.pid}:${key}:${event.value ?? ""}`, {
        source: "behavior.registry",
        category: "persistence",
        score: 25,
        severity: Severity.MEDIUM,
        subject: pidSubject(event.pid, this.processes.get(Number(event.pid))?.image),
        message: "Persistence registry location modified.",
        evidence: {
          key: event.key,
          value: event.value,
          data: event.data
        }
      })
    ]);
  }

  handleMemoryEvent(event) {
    const pid = Number(event.pid ?? 0);
    const targetPid = Number(event.target_pid ?? 0);
    const key = `${pid}:${targetPid}`;
    const ops = this.memoryOps.get(key) ?? [];
    ops.push(String(event.api ?? ""));
    this.memoryOps.set(key, ops.slice(-12));

    const signals = [];
    if (hasAllInOrder(ops, ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])) {
      signals.push(this.once(`dll-injection:${key}`, {
        source: "behavior.memory",
        category: "process_injection",
        score: 75,
        severity: Severity.HIGH,
        subject: pidSubject(pid, this.processes.get(pid)?.image),
        message: "Remote process injection API sequence detected.",
        evidence: { target_pid: targetPid, sequence: ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] }
      }));
    }

    if (hasAllInOrder(ops, ["CreateProcessSuspended", "NtUnmapViewOfSection", "WriteProcessMemory", "ResumeThread"])) {
      signals.push(this.once(`hollowing:${key}`, {
        source: "behavior.memory",
        category: "process_hollowing",
        score: 80,
        severity: Severity.CRITICAL,
        subject: pidSubject(pid, this.processes.get(pid)?.image),
        message: "Process hollowing API sequence detected.",
        evidence: { target_pid: targetPid, sequence: ["CreateProcessSuspended", "NtUnmapViewOfSection", "WriteProcessMemory", "ResumeThread"] }
      }));
    }

    return compact(signals);
  }

  handleDnsEvent(event) {
    const domain = event.query ?? event.domain;
    if (!domain) return [];
    const signals = [];
    const pid = Number(event.pid ?? 0);
    const hit = this.iocStore?.checkDomain(domain);
    if (hit) {
      signals.push(this.once(`domain-ioc:${domain}`, {
        source: "behavior.network",
        category: "known_c2_domain",
        score: hit.score ?? 90,
        severity: hit.severity ?? Severity.CRITICAL,
        subject: pidSubject(pid, this.processes.get(pid)?.image),
        message: "DNS query matched threat intelligence domain IOC.",
        evidence: { domain, family: hit.family, description: hit.description }
      }));
    }

    if (looksLikeDga(domain)) {
      signals.push(this.once(`dga:${domain}`, {
        source: "behavior.network",
        category: "dga_domain",
        score: 30,
        severity: Severity.MEDIUM,
        subject: String(domain).toLowerCase(),
        message: "Domain has DGA-like lexical features.",
        evidence: { domain }
      }));
    }

    return compact(signals);
  }

  handleNetworkConnect(event) {
    const signals = [];
    const pid = Number(event.pid ?? 0);
    const remoteIp = event.remote_ip ?? event.ip;
    const hit = remoteIp ? this.iocStore?.checkIp(remoteIp) : null;
    if (hit) {
      signals.push(this.once(`ip-ioc:${remoteIp}`, {
        source: "behavior.network",
        category: "known_c2_ip",
        score: hit.score ?? 90,
        severity: hit.severity ?? Severity.CRITICAL,
        subject: pidSubject(pid, this.processes.get(pid)?.image),
        message: "Network connection matched threat intelligence IP IOC.",
        evidence: { ip: remoteIp, port: event.remote_port, family: hit.family, description: hit.description }
      }));
    }

    const beaconSignal = this.detectBeacon(event);
    if (beaconSignal) signals.push(beaconSignal);

    return compact(signals);
  }

  detectBeacon(event) {
    const pid = Number(event.pid ?? 0);
    const remoteIp = event.remote_ip ?? event.ip;
    if (!remoteIp) return null;
    const key = `${pid}:${remoteIp}:${event.remote_port ?? ""}`;
    const timestamp = Date.parse(event.timestamp);
    const history = this.networkWindows.get(key) ?? [];
    history.push(timestamp);
    this.networkWindows.set(key, history.slice(-6));

    if (history.length < 5) return null;
    const intervals = [];
    for (let index = history.length - 4; index < history.length; index += 1) {
      intervals.push(Math.round((history[index] - history[index - 1]) / 1000));
    }
    const average = intervals.reduce((sum, value) => sum + value, 0) / intervals.length;
    const stable = intervals.every((value) => Math.abs(value - average) <= 5);
    if (!stable || average < 10) return null;

    return this.once(`beacon:${key}`, {
      source: "behavior.network",
      category: "periodic_beaconing",
      score: 55,
      severity: Severity.HIGH,
      subject: pidSubject(pid, this.processes.get(pid)?.image),
      message: "Periodic beacon-like network interval detected.",
      evidence: { remote_ip: remoteIp, remote_port: event.remote_port, intervals_seconds: intervals }
    });
  }

  once(key, signalInput) {
    if (this.emittedKeys.has(key)) return null;
    this.emittedKeys.add(key);
    return createSignal(signalInput);
  }
}

function basename(image) {
  return path.basename(String(image ?? "")).toLowerCase();
}

function pidSubject(pid, image) {
  return image ? `${image}:${pid}` : `pid:${pid}`;
}

function isTrustedSigner(signer) {
  return /^(microsoft|windows|trusted)$/i.test(String(signer ?? ""));
}

function compact(values) {
  return values.filter(Boolean);
}

function hasAllInOrder(values, sequence) {
  let cursor = 0;
  for (const value of values) {
    if (String(value).toLowerCase() === sequence[cursor].toLowerCase()) {
      cursor += 1;
      if (cursor === sequence.length) return true;
    }
  }
  return false;
}

function looksLikeDga(domain) {
  const label = String(domain).split(".")[0] ?? "";
  if (label.length < 16) return false;
  const digits = (label.match(/\d/g) ?? []).length;
  const vowels = (label.match(/[aeiou]/gi) ?? []).length;
  const consonants = (label.match(/[bcdfghjklmnpqrstvwxyz]/gi) ?? []).length;
  return digits >= 4 || (consonants >= 12 && vowels <= 3);
}
