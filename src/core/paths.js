import path from "node:path";
import { fileURLToPath } from "node:url";

const currentFile = fileURLToPath(import.meta.url);
const srcRoot = path.dirname(path.dirname(currentFile));

export const projectRoot = path.dirname(srcRoot);
export const defaultIocDir = path.join(projectRoot, "data", "ioc");
export const defaultRulesFile = path.join(projectRoot, "data", "rules", "yara-lite-rules.json");
export const defaultStateDir = path.join(projectRoot, ".antiai");
export const defaultVirusTotalConfig = path.join(projectRoot, "config", "virustotal.json");
