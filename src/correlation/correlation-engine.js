import { createSignal, Severity } from "../core/severity.js";

export class CorrelationEngine {
  constructor() {
    this.signals = [];
    this.emitted = new Set();
  }

  addSignals(signals) {
    this.signals.push(...signals);
    return this.derive();
  }

  derive() {
    const derived = [];
    const bySubject = new Map();

    for (const signal of this.signals) {
      const key = normalizeSubject(signal.subject);
      const bucket = bySubject.get(key) ?? [];
      bucket.push(signal);
      bySubject.set(key, bucket);
    }

    for (const [subject, signals] of bySubject) {
      const categories = new Set(signals.map((signal) => signal.category));
      if (
        (categories.has("office_lolbin_chain") || categories.has("powershell_encoded_command")) &&
        categories.has("persistence") &&
        (categories.has("known_c2_ip") || categories.has("known_c2_domain") || categories.has("periodic_beaconing"))
      ) {
        const key = `intrusion-chain:${subject}`;
        if (this.emitted.has(key)) continue;
        this.emitted.add(key);
        derived.push(
          createSignal({
            source: "correlation",
            category: "intrusion_chain",
            score: 85,
            severity: Severity.CRITICAL,
            subject,
            message: "Correlated execution, persistence, and C2 indicators.",
            evidence: {
              categories: [...categories],
              signal_count: signals.length
            }
          })
        );
      }
    }

    if (derived.length > 0) {
      this.signals.push(...derived);
    }
    return derived;
  }
}

function normalizeSubject(subject) {
  const text = String(subject ?? "unknown");
  return text.replace(/:\d+$/, "");
}
