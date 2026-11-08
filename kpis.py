"""Shared KPI definitions: SLAs, targets, scoring bands, status logic.

Kept separate from the build script so the rules are testable and reusable.
"""

# Remediation SLAs (days) per severity
SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90}

# Aging buckets for open findings
AGE_BUCKETS = ["0-30 days", "31-60 days", "61-90 days", "90+ days"]


def age_bucket(age_days: int) -> str:
    if age_days <= 30:
        return AGE_BUCKETS[0]
    if age_days <= 60:
        return AGE_BUCKETS[1]
    if age_days <= 90:
        return AGE_BUCKETS[2]
    return AGE_BUCKETS[3]


def risk_band(score: int) -> str:
    """5x5 matrix banding: Low 1-6, Medium 8-12, High 15-25."""
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"


# KPI targets: value the program commits to, and the amber tolerance.
# direction: "higher" = higher is better, "lower" = lower is better.
TARGETS = {
    "sla_pct":       {"target": 90, "amber": 80, "direction": "higher", "label": "target ≥ 90%"},
    "mttr_high":     {"target": 30, "amber": 40, "direction": "lower",  "label": "target ≤ 30 days"},
    "phish_click":   {"target": 10, "amber": 15, "direction": "lower",  "label": "target < 10%"},
    "patch_latency": {"target": 14, "amber": 21, "direction": "lower",  "label": "target ≤ 14 days"},
}


def tile_status(kpi: str, value: float) -> str:
    """Return 'good' | 'warn' | 'bad' for a KPI value against its target."""
    t = TARGETS[kpi]
    if t["direction"] == "higher":
        if value >= t["target"]:
            return "good"
        return "warn" if value >= t["amber"] else "bad"
    if value <= t["target"]:
        return "good"
    return "warn" if value <= t["amber"] else "bad"
