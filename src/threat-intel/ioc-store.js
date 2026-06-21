import path from "node:path";
import { loadJson } from "../core/json.js";

export class IocStore {
  constructor({ hashes = {}, domains = {}, ips = {} } = {}) {
    this.hashes = {
      sha256: normalizeMap(hashes.sha256),
      sha1: normalizeMap(hashes.sha1),
      md5: normalizeMap(hashes.md5)
    };
    this.domains = normalizeMap(domains.domains ?? domains);
    this.ips = normalizeMap(ips.ips ?? ips);
  }

  static async load(iocDir) {
    const [hashes, domains, ips] = await Promise.all([
      loadJson(path.join(iocDir, "hashes.json"), {}),
      loadJson(path.join(iocDir, "domains.json"), {}),
      loadJson(path.join(iocDir, "ips.json"), {})
    ]);
    return new IocStore({ hashes, domains, ips });
  }

  checkHash(algorithm, value) {
    return this.hashes[algorithm]?.[String(value).toLowerCase()] ?? null;
  }

  checkDomain(domain) {
    const normalized = String(domain).toLowerCase().replace(/\.$/, "");
    if (this.domains[normalized]) return this.domains[normalized];

    for (const [pattern, value] of Object.entries(this.domains)) {
      if (!pattern.startsWith("*.")) continue;
      const suffix = pattern.slice(1);
      if (normalized.endsWith(suffix)) return value;
    }

    return null;
  }

  checkIp(ip) {
    return this.ips[String(ip)] ?? null;
  }
}

function normalizeMap(map = {}) {
  return Object.fromEntries(
    Object.entries(map).map(([key, value]) => [String(key).toLowerCase(), value])
  );
}
