import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { createSignal, Severity } from "../core/severity.js";

export async function hashFile(filePath) {
  const hashes = {
    sha256: createHash("sha256"),
    sha1: createHash("sha1"),
    md5: createHash("md5")
  };

  await new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    stream.on("data", (chunk) => {
      hashes.sha256.update(chunk);
      hashes.sha1.update(chunk);
      hashes.md5.update(chunk);
    });
    stream.on("error", reject);
    stream.on("end", resolve);
  });

  return {
    sha256: hashes.sha256.digest("hex"),
    sha1: hashes.sha1.digest("hex"),
    md5: hashes.md5.digest("hex")
  };
}

export async function scanHashes(filePath, iocStore, { debug = false } = {}) {
  const hashes = await hashFile(filePath);
  const hits = [];
  const trace = [];

  if (debug) {
    for (const [algorithm, value] of Object.entries(hashes)) {
      trace.push({
        check: `hash.${algorithm}`,
        status: "ok",
        message: `${algorithm.toUpperCase()} calculated.`,
        details: { value }
      });
    }
  }

  for (const [algorithm, value] of Object.entries(hashes)) {
    const hit = iocStore.checkHash(algorithm, value);
    if (debug) {
      trace.push({
        check: `ioc.hash.${algorithm}`,
        status: hit ? "hit" : "clean",
        message: hit ? `Hash IOC hit for ${algorithm}.` : `No ${algorithm} hash IOC match.`,
        details: hit
          ? {
              hash: value,
              family: hit.family,
              severity: hit.severity,
              score: hit.score
            }
          : { hash: value }
      });
    }
    if (!hit) continue;
    hits.push(
      createSignal({
        source: "static.hash",
        category: "known_malware_hash",
        score: hit.score ?? 100,
        severity: hit.severity ?? Severity.CRITICAL,
        subject: filePath,
        message: `Known malicious/test hash matched (${algorithm}).`,
        evidence: {
          algorithm,
          hash: value,
          family: hit.family,
          description: hit.description
        }
      })
    );
  }

  return { hashes, signals: hits, debug: trace };
}
