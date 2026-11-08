#!/usr/bin/env python3
"""Seed the risk register and KPI source data with 12 months of realistic,
improving-program numbers (Nov 2025 - Oct 2026).

Everything is deterministic (seeded) so the dashboard is reproducible.
Replace the CSVs in data/ with your own exports to use this for real.
"""
import csv
import random
from datetime import date, timedelta
from pathlib import Path

random.seed(20261108)
DATA = Path(__file__).parent / "data"
DATA.mkdir(exist_ok=True)

MONTHS = [date(2025, 11, 1), date(2025, 12, 1)] + [date(2026, m, 1) for m in range(1, 11)]

# ---------------------------------------------------------------- risks ----
ASSETS = [
    ("Customer web portal", "Web application"),
    ("Public REST API", "Web application"),
    ("Active Directory", "Identity"),
    ("AWS production account", "Cloud"),
    ("Employee endpoints", "Endpoint"),
    ("Office network / Wi-Fi", "Network"),
    ("Email platform", "SaaS"),
    ("CI/CD pipeline", "DevOps"),
    ("Customer database", "Data"),
    ("Backup infrastructure", "Data"),
    ("HR SaaS platform", "SaaS"),
    ("Payment provider integration", "Third party"),
    ("Managed SOC provider", "Third party"),
    ("Source code repositories", "DevOps"),
    ("VPN gateway", "Network"),
]
THREATS = [
    ("Credential stuffing / password spraying", "Weak or reused passwords", "A.5.17"),
    ("Phishing leading to account takeover", "Insufficient user awareness", "A.6.3"),
    ("Exploitation of unpatched software", "Delayed patching", "A.8.8"),
    ("Ransomware via endpoint compromise", "Gaps in endpoint protection", "A.8.7"),
    ("SQL injection / web exploitation", "Insecure code, missing reviews", "A.8.28"),
    ("Privilege escalation in AD", "Excessive privileges, stale accounts", "A.8.2"),
    ("Cloud misconfiguration exposure", "No baseline hardening checks", "A.8.9"),
    ("Insider data exfiltration", "Broad data access, weak monitoring", "A.8.16"),
    ("Vendor breach propagating", "No vendor security requirements", "A.5.19"),
    ("Secrets leaked in repositories", "No secret scanning in CI", "A.8.28"),
    ("DDoS against public services", "No upstream mitigation contract", "A.8.6"),
    ("Backup destruction / tampering", "Backups not isolated or tested", "A.8.13"),
    ("Session hijacking on public API", "Weak token handling", "A.8.26"),
    ("Lost / stolen laptop", "Missing disk encryption enforcement", "A.7.9"),
    ("Business email compromise (BEC)", "No payment verification process", "A.5.14"),
]
OWNERS = ["CISO", "Head of IT", "IT Operations Lead", "Engineering Lead", "HR Director", "Procurement Lead"]
TREATMENTS = ["Mitigate", "Mitigate", "Mitigate", "Accept", "Transfer"]
CONTROLS = {
    "Mitigate": [
        "MFA rollout; conditional access policies",
        "Quarterly phishing simulations; awareness training",
        "Monthly patch cycle with SLA tracking",
        "EDR deployment; attack surface reduction rules",
        "Secure code review; SAST in CI pipeline",
        "Tiered admin model; quarterly access review",
        "IaC baseline scanning; CSPM alerts",
        "DLP monitoring; least-privilege data access",
        "Vendor security clauses; annual assessment",
        "Secret scanning in CI; pre-commit hooks",
        "CDN/DDoS protection service",
        "Immutable offline backups; restore tests",
        "Short-lived tokens; session binding",
        "Full-disk encryption enforced via MDM",
        "Dual approval for payment changes",
    ],
    "Accept": ["Risk accepted at current level; annual review"],
    "Transfer": ["Cyber insurance; contractual liability clauses"],
}

rows = []
rid = 0
for ti, (threat, vuln, iso) in enumerate(THREATS):
    for _ in range(4):
        rid += 1
        asset, _cls = random.choice(ASSETS)
        lik = random.choices([1, 2, 3, 4, 5], weights=[1, 3, 4, 3, 1])[0]
        imp = random.choices([1, 2, 3, 4, 5], weights=[1, 2, 4, 4, 2])[0]
        treatment = random.choice(TREATMENTS)
        if treatment == "Mitigate":
            ctrl = CONTROLS["Mitigate"][ti]
            r_lik = max(1, lik - random.choice([1, 1, 2]))
            r_imp = max(1, imp - random.choice([0, 1]))
        else:
            ctrl = CONTROLS[treatment][0]
            r_lik, r_imp = lik, imp if treatment == "Accept" else max(1, imp - 1)
        rows.append({
            "id": f"R-{rid:03d}",
            "asset": asset,
            "threat": threat,
            "vulnerability": vuln,
            "iso_ref": iso,
            "likelihood": lik,
            "impact": imp,
            "inherent_score": lik * imp,
            "owner": random.choice(OWNERS),
            "treatment": treatment,
            "controls": ctrl,
            "residual_likelihood": r_lik,
            "residual_impact": r_imp,
            "residual_score": r_lik * r_imp,
            "status": random.choices(["Open", "In progress", "Closed"], weights=[3, 4, 2])[0],
            "next_review": (date(2026, 11, 8) + timedelta(days=random.randint(20, 160))).isoformat(),
        })

with open(DATA / "risks.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)

# ------------------------------------------------------------- findings ----
SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90}
SOURCES = ["Penetration test", "Vulnerability scan", "Internal audit", "Bug report"]
find_rows = []
fid = 0
for mi, month in enumerate(MONTHS):
    maturity = mi / (len(MONTHS) - 1)          # 0 -> 1 across the year
    for _ in range(random.randint(28, 40)):
        fid += 1
        sev = random.choices(["Critical", "High", "Medium"], weights=[1, 3, 6])[0]
        opened = month + timedelta(days=random.randint(0, 27))
        sla = SLA_DAYS[sev]
        due = opened + timedelta(days=sla)
        # closure speed improves over the year; early months frequently blow the SLA
        on_time_p = 0.32 + 0.60 * maturity
        if random.random() < 0.92 or mi < 10:   # most findings eventually close
            if random.random() < on_time_p:
                close_days = max(1, int(random.uniform(0.2, 0.95) * sla))
            else:
                close_days = int(sla * random.uniform(1.1, 2.8))
            closed = opened + timedelta(days=close_days)
            closed_s = closed.isoformat() if closed <= date(2026, 11, 8) else ""
        else:
            closed_s = ""
        find_rows.append({
            "id": f"F-{fid:04d}",
            "source": random.choice(SOURCES),
            "severity": sev,
            "opened": opened.isoformat(),
            "due": due.isoformat(),
            "closed": closed_s,
            "owner": random.choice(OWNERS),
        })

with open(DATA / "findings.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=find_rows[0].keys())
    w.writeheader(); w.writerows(find_rows)

# ------------------------------------------------------------- phishing ----
phish_rows = []
click, report = 0.24, 0.08
for month in MONTHS:
    sent = random.randint(180, 220)
    clicked = int(sent * max(0.04, random.gauss(click, 0.015)))
    reported = int(sent * min(0.6, max(0.05, random.gauss(report, 0.02))))
    phish_rows.append({
        "campaign_date": month.isoformat(),
        "sent": sent,
        "clicked": clicked,
        "reported": reported,
    })
    click = max(0.07, click - 0.014)       # training takes effect
    report = min(0.36, report + 0.024)

with open(DATA / "phishing.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=phish_rows[0].keys())
    w.writeheader(); w.writerows(phish_rows)

# ------------------------------------------------------------- patching ----
ASSET_CLASSES = {"Servers": 18, "Endpoints": 9, "Network devices": 30, "Cloud workloads": 6, "Databases ": 24}
patch_rows = []
for month in MONTHS:
    maturity = MONTHS.index(month) / (len(MONTHS) - 1)
    for cls, base in ASSET_CLASSES.items():
        for _ in range(random.randint(4, 8)):
            released = month + timedelta(days=random.randint(0, 25))
            latency = max(1, int(random.gauss(base * (1.25 - 0.5 * maturity), base * 0.3)))
            patch_rows.append({
                "asset_class": cls.strip(),
                "patch_released": released.isoformat(),
                "patch_applied": (released + timedelta(days=latency)).isoformat(),
            })

with open(DATA / "patching.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=patch_rows[0].keys())
    w.writeheader(); w.writerows(patch_rows)

print(f"risks: {len(rows)}  findings: {len(find_rows)}  phishing: {len(phish_rows)}  patching: {len(patch_rows)}")
