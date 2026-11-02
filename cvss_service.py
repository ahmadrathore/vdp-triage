"""CVSS v3.1 Base scoring."""


from __future__ import annotations
import math

# Base metric weights (CVSS v3.1 specification).
_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 1.0},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}

# Canonical metric order used to build the vector string.
_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

# Human-readable labels for each metric value (used in the UI + analysis basis).
_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}

# The default vector used when the model fails to recommend usable metrics.
# It is intentionally the lowest-severity network vector so it never inflates a
# score; the accompanying warning tells the analyst metrics were not derived.
_FALLBACK_METRICS = {
    "AV": "N", "AC": "H", "PR": "H", "UI": "R", "S": "U", "C": "N", "I": "N", "A": "N",
}


class CvssError(ValueError):
    """Raised when a vector or metric set is not valid CVSS v3.1."""


def _roundup(value: float) -> float:
    """FIRST Appendix A roundup using integer arithmetic (avoids float drift)."""
    integer = math.floor(value * 100000 + 0.5)
    if integer % 10000 == 0:
        return integer / 100000
    return (int(integer // 10000) + 1) / 10


def severity_of(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def normalize_metrics(metrics: dict) -> dict:
    """Validate and normalize an AI-recommended metric mapping.

    Accepts either short values ("N") or full labels ("Network"). Any metric
    that is missing/invalid falls back to the conservative default and is
    reported so the analyst knows the model did not supply it.
    """
    normalized: dict[str, str] = {}
    missing: list[str] = []
    for key in _ORDER:
        raw = metrics.get(key)
        value = _coerce_metric(key, raw)
        if value is None:
            value = _FALLBACK_METRICS[key]
            missing.append(key)
        normalized[key] = value
    return {"metrics": normalized, "missing": missing}


def _coerce_metric(key: str, raw):
    if raw is None:
        return None
    if isinstance(raw, str):
        token = raw.strip()
        upper = token.upper()
        if upper in _METRICS[key]:
            return upper
        # Try matching the human-readable label (e.g. "Network" -> "N").
        for value, label in _LABELS[key].items():
            if label.lower() == token.lower():
                return value
        # Accept a leading letter such as "N/A" ambiguity guard.
        if len(upper) == 1 and upper in _METRICS[key]:
            return upper
    return None


def build_vector(metrics: dict) -> str:
    return "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in _ORDER)


def calculate(vector: str) -> dict:
    """Compute the authoritative score/severity for a CVSS:3.1 Base vector."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise CvssError("A complete CVSS:3.1 Base vector is required.")
    parsed: dict[str, str] = {}
    for part in vector[len("CVSS:3.1/"):].split("/"):
        bits = part.split(":")
        if len(bits) != 2:
            raise CvssError("Invalid CVSS metric segment.")
        key, value = bits
        if key not in _METRICS or value not in _METRICS[key] or key in parsed:
            raise CvssError("Invalid or duplicate CVSS metric.")
        parsed[key] = value
    if len(parsed) != 8:
        raise CvssError("All eight CVSS Base metrics are required.")
    return score_from_metrics(parsed)


def score_from_metrics(m: dict) -> dict:
    iss = 1 - (1 - _METRICS["C"][m["C"]]) * (1 - _METRICS["I"][m["I"]]) * (1 - _METRICS["A"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    pr = {"N": 0.85, "L": 0.68, "H": 0.50}[m["PR"]] if m["S"] == "C" else _METRICS["PR"][m["PR"]]
    exploitability = 8.22 * _METRICS["AV"][m["AV"]] * _METRICS["AC"][m["AC"]] * pr * _METRICS["UI"][m["UI"]]
    score = 0.0 if impact <= 0 else _roundup(min((1.08 if m["S"] == "C" else 1.0) * (impact + exploitability), 10))
    vector = build_vector(m)
    return {
        "vector": vector,
        "metrics": {k: m[k] for k in _ORDER},
        "metric_labels": {k: _LABELS[k][m[k]] for k in _ORDER},
        "score": score,
        "severity": severity_of(score),
        "impact": round(impact, 4),
        "exploitability": round(exploitability, 4),
    }


def assess(recommended_metrics: dict) -> dict:
    """Turn AI-recommended metrics into a deterministic CVSS assessment."""
    normalized = normalize_metrics(recommended_metrics or {})
    result = score_from_metrics(normalized["metrics"])
    result["missing_metrics"] = normalized["missing"]
    return result
