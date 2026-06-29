import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

export async function replayJsonl(filePath, onEvent) {
  const rl = createInterface({
    input: createReadStream(filePath, { encoding: "utf8" }),
    crlfDelay: Infinity
  });

  let lineNumber = 0;
  for await (const line of rl) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    let event;
    try {
      event = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`Invalid JSONL at ${filePath}:${lineNumber}: ${error.message}`);
    }
    await onEvent(normalizeEvent(event));
  }
}

function normalizeEvent(event) {
  return {
    timestamp: event.timestamp ?? new Date().toISOString(),
    ...event
  };
}
