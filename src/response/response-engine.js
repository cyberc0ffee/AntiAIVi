import { QuarantineStore } from "./quarantine.js";

export class ResponseEngine {
  constructor({ stateDir, enableQuarantine = false } = {}) {
    this.enableQuarantine = enableQuarantine;
    this.quarantine = new QuarantineStore(stateDir);
  }

  async apply(detection, context = {}) {
    const actions = [];

    if (detection.action === "monitor") {
      actions.push({ type: "monitor", status: "planned" });
    }

    if (detection.action === "suspend") {
      actions.push({ type: "suspend_process", status: "planned", note: "OS enforcement is not enabled in this prototype." });
    }

    if (detection.action === "kill_quarantine") {
      actions.push({ type: "terminate_process", status: "planned", note: "OS enforcement is not enabled in this prototype." });
      if (context.file && this.enableQuarantine) {
        const metadata = await this.quarantine.quarantineFile(context.file, {
          reason: "Decision score reached kill_quarantine threshold.",
          detection
        });
        actions.push({ type: "quarantine_file", status: "completed", metadata });
      } else if (context.file) {
        actions.push({ type: "quarantine_file", status: "skipped", note: "Pass --quarantine to move files into quarantine." });
      }
    }

    return actions;
  }
}
