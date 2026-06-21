import { promises as fs } from "node:fs";
import path from "node:path";

export async function* walkTargets(targets) {
  for (const target of targets) {
    yield* walkOne(path.resolve(target));
  }
}

async function* walkOne(target) {
  const stat = await fs.lstat(target);
  if (stat.isSymbolicLink()) return;
  if (stat.isFile()) {
    yield target;
    return;
  }
  if (!stat.isDirectory()) return;

  const entries = await fs.readdir(target, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(target, entry.name);
    if (entry.isDirectory()) {
      yield* walkOne(fullPath);
    } else if (entry.isFile()) {
      yield fullPath;
    }
  }
}
