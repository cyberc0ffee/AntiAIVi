import { promises as fs } from "node:fs";
import { verify } from "node:crypto";
import { canonicalJson, loadJson } from "../core/json.js";

export class UpdateEngine {
  async validateManifest(manifestPath, { publicKeyPath } = {}) {
    const manifest = await loadJson(manifestPath);
    const errors = [];

    if (!manifest.version || typeof manifest.version !== "string") {
      errors.push("version must be a string");
    }
    if (manifest.rules !== undefined && !Array.isArray(manifest.rules)) {
      errors.push("rules must be an array when present");
    }
    if (manifest.iocs !== undefined && typeof manifest.iocs !== "object") {
      errors.push("iocs must be an object when present");
    }

    let signature = { checked: false, valid: null };
    if (publicKeyPath) {
      if (!manifest.signature?.algorithm || !manifest.signature?.value) {
        errors.push("signature.algorithm and signature.value are required when --public-key is used");
      } else if (manifest.signature.algorithm !== "Ed25519") {
        errors.push("only Ed25519 signatures are supported");
      } else {
        const publicKey = await fs.readFile(publicKeyPath, "utf8");
        const unsigned = { ...manifest };
        delete unsigned.signature;
        const valid = verify(
          null,
          Buffer.from(canonicalJson(unsigned), "utf8"),
          publicKey,
          Buffer.from(manifest.signature.value, "base64")
        );
        signature = { checked: true, valid };
        if (!valid) errors.push("manifest signature verification failed");
      }
    }

    return {
      ok: errors.length === 0,
      version: manifest.version,
      errors,
      signature
    };
  }
}
