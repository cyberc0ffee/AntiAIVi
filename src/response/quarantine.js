import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { hashFile } from "../static/hash-scanner.js";
import { writeJson, loadJson } from "../core/json.js";

const KEY_FILE = "secret.key";
const INDEX_FILE = "quarantine-index.json";

export class QuarantineStore {
  constructor(stateDir) {
    this.stateDir = stateDir;
    this.quarantineDir = path.join(stateDir, "quarantine");
  }

  async quarantineFile(filePath, { reason, detection }) {
    await fs.mkdir(this.quarantineDir, { recursive: true });
    const key = await this.getOrCreateKey();
    const id = `${Date.now()}-${randomBytes(6).toString("hex")}`;
    const plaintext = await fs.readFile(filePath);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const encryptedPath = path.join(this.quarantineDir, `${id}.bin`);
    await fs.writeFile(encryptedPath, encrypted);

    const hashes = await hashFile(filePath);
    const metadata = {
      id,
      original_path: path.resolve(filePath),
      sha256: hashes.sha256,
      reason,
      date: new Date().toISOString(),
      cipher: "aes-256-gcm",
      iv: iv.toString("base64"),
      auth_tag: authTag.toString("base64"),
      encrypted_path: encryptedPath,
      original_size: plaintext.length,
      detection_score: detection?.score,
      detection_action: detection?.action
    };

    await writeJson(path.join(this.quarantineDir, `${id}.json`), metadata);
    await this.appendIndex(metadata);
    await fs.unlink(filePath);
    return metadata;
  }

  async list() {
    return loadJson(path.join(this.quarantineDir, INDEX_FILE), []);
  }

  async restore(id, destination) {
    const metadata = await loadJson(path.join(this.quarantineDir, `${id}.json`));
    const key = await this.getOrCreateKey();
    const encrypted = await fs.readFile(metadata.encrypted_path);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(metadata.iv, "base64"));
    decipher.setAuthTag(Buffer.from(metadata.auth_tag, "base64"));
    const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, plaintext);
    return { ...metadata, restored_to: destination };
  }

  async getOrCreateKey() {
    await fs.mkdir(this.stateDir, { recursive: true });
    const keyPath = path.join(this.stateDir, KEY_FILE);
    try {
      return Buffer.from(await fs.readFile(keyPath, "utf8"), "base64");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const key = randomBytes(32);
      await fs.writeFile(keyPath, key.toString("base64"), { encoding: "utf8", mode: 0o600 });
      return key;
    }
  }

  async appendIndex(metadata) {
    const indexPath = path.join(this.quarantineDir, INDEX_FILE);
    const index = await loadJson(indexPath, []);
    index.push({
      id: metadata.id,
      original_path: metadata.original_path,
      sha256: metadata.sha256,
      reason: metadata.reason,
      date: metadata.date,
      detection_score: metadata.detection_score,
      detection_action: metadata.detection_action
    });
    await writeJson(indexPath, index);
  }
}
