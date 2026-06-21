import { maxSeverity, severityFromScore } from "../core/severity.js";

export class DecisionEngine {
  decide({ subject, signals }) {
    const score = signals.reduce((sum, signal) => sum + Number(signal.score ?? 0), 0);
    const severity = maxSeverity([...signals.map((signal) => signal.severity), severityFromScore(score)]);
    const action = actionFromScore(score);

    return {
      subject,
      score,
      severity,
      action,
      signals
    };
  }
}

export function actionFromScore(score) {
  if (score >= 100) return "kill_quarantine";
  if (score >= 70) return "suspend";
  if (score >= 40) return "monitor";
  return "allow";
}
