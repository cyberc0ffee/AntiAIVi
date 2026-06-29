export const Severity = Object.freeze({
  INFO: "info",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
});

const RANK = Object.freeze({
  [Severity.INFO]: 0,
  [Severity.LOW]: 1,
  [Severity.MEDIUM]: 2,
  [Severity.HIGH]: 3,
  [Severity.CRITICAL]: 4
});

export function severityRank(severity) {
  return RANK[severity] ?? RANK[Severity.INFO];
}

export function maxSeverity(values) {
  return values.reduce((current, value) => {
    return severityRank(value) > severityRank(current) ? value : current;
  }, Severity.INFO);
}

export function severityFromScore(score) {
  if (score >= 90) return Severity.CRITICAL;
  if (score >= 70) return Severity.HIGH;
  if (score >= 40) return Severity.MEDIUM;
  if (score > 0) return Severity.LOW;
  return Severity.INFO;
}

export function createSignal({
  source,
  category,
  score,
  severity,
  subject,
  message,
  evidence = {},
  timestamp = new Date().toISOString()
}) {
  return {
    source,
    category,
    score,
    severity: severity ?? severityFromScore(score),
    subject,
    message,
    evidence,
    timestamp
  };
}
