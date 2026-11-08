# Methodology

## Risk scoring

Risks are assessed on a **5×5 matrix**, consistent with ISO 27005 and NIST SP 800-30
qualitative scales:

| Score | Likelihood | Impact |
|---|---|---|
| 1 | Rare (not expected within 5 years) | Negligible (no business effect) |
| 2 | Unlikely (once in 2-5 years) | Minor (limited effect, handled within team) |
| 3 | Possible (once a year) | Moderate (noticeable disruption or cost) |
| 4 | Likely (several times a year) | Major (serious disruption, regulatory interest) |
| 5 | Almost certain (monthly or more) | Severe (threatens business objectives) |

**Risk score = likelihood × impact**, banded:

| Band | Score | Expectation |
|---|---|---|
| Low | 1-6 | Accept or monitor; review annually |
| Medium | 8-12 | Treatment plan required; review quarterly |
| High | 15-25 | Named owner, funded treatment, management visibility |

Each risk records both **inherent** (before controls) and **residual** (after current
treatment) scores. The dashboard leads with residual risk because treatment decisions
are about what remains. Treatments follow the standard four: **mitigate, accept,
transfer, avoid**. Each risk maps to an **ISO 27001:2022 Annex A** control reference
for audit traceability.

## KPI definitions

| KPI | Definition | Target |
|---|---|---|
| SLA compliance | % of resolved findings closed within their severity SLA, 3-month rolling | ≥ 90% |
| Remediation SLAs | Critical: 7 days · High: 30 days · Medium: 90 days from opening | - |
| MTTR | Mean days from finding opened to closed, per severity, 3-month rolling | downward trend |
| Phishing click rate | clicked / delivered per monthly simulated campaign | < 10% |
| Phishing report rate | reported / delivered (the positive behavior metric) | > 30% |
| Patch latency | Median days from vendor patch release to deployment, per asset class | < 14 days (servers) |

### Why these choices

- **Rolling window**: monthly Critical-severity samples are small; raw monthly
  percentages produce noise that reads as trend. Three months balances stability
  against responsiveness.
- **Median for patch latency**: patching distributions are right-skewed (a few
  stragglers); a mean would let outliers dominate the headline.
- **Report rate alongside click rate**: click rate measures failure, report rate
  measures the desired behavior. Programs that only track clicks miss whether users
  know what to do instead.
- **% within SLA over raw counts**: counts grow with scanning coverage; a ratio stays
  comparable as the program scales.

## Reporting cadence

The intended cadence for a program using this framework: monthly operational review
(bottom section), quarterly executive/board reporting (top section). Deltas on the
KPI tiles compare the last 3 full months against the previous 3.
