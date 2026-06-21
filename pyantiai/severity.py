from datetime import datetime, timezone


RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def max_severity(values) -> str:
    result = "info"
    for value in values:
        if RANK.get(value, 0) > RANK.get(result, 0):
            result = value
    return result


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def signal(source, category, score, subject, message, severity=None, evidence=None):
    return {
        "source": source,
        "category": category,
        "score": score,
        "severity": severity or severity_from_score(score),
        "subject": str(subject),
        "message": message,
        "evidence": evidence or {},
        "timestamp": now_iso(),
    }


def decide(subject, signals):
    score = sum(int(item.get("score", 0)) for item in signals)
    action = "allow"
    if score >= 100:
        action = "kill_quarantine"
    elif score >= 70:
        action = "suspend"
    elif score >= 40:
        action = "monitor"
    return {
        "subject": str(subject),
        "score": score,
        "severity": max_severity([item.get("severity", "info") for item in signals] + [severity_from_score(score)]),
        "action": action,
        "signals": signals,
    }
