#!/usr/bin/env python3
"""Compute KPIs from data/*.csv and render a self-contained HTML dashboard
(dist/dashboard.html) with an executive layer and an operational layer.
"""
import json
from datetime import date
from pathlib import Path

import pandas as pd

from kpis import AGE_BUCKETS, TARGETS, age_bucket, tile_status

ROOT = Path(__file__).parent
DIST = ROOT / "dist"
DIST.mkdir(exist_ok=True)
TODAY = date(2026, 11, 8)

risks = pd.read_csv(ROOT / "data/risks.csv")
findings = pd.read_csv(ROOT / "data/findings.csv", parse_dates=["opened", "due", "closed"])
phishing = pd.read_csv(ROOT / "data/phishing.csv", parse_dates=["campaign_date"])
patching = pd.read_csv(ROOT / "data/patching.csv", parse_dates=["patch_released", "patch_applied"])

# ----------------------------------------------------------------- KPIs ----
findings["month"] = findings["opened"].dt.to_period("M")
findings["closed_on_time"] = findings["closed"].notna() & (findings["closed"] <= findings["due"])
findings["resolved"] = findings["closed"].notna()
findings["mttr"] = (findings["closed"] - findings["opened"]).dt.days

months = sorted(findings["month"].unique())
month_labels = [m.strftime("%b %y") for m in months]
SEVERITIES = ["Critical", "High", "Medium"]

sla_by_sev = {}
mttr_by_sev = {}
for sev in SEVERITIES:
    sla_series, mttr_series = [], []
    for i, m in enumerate(months):
        win = months[max(0, i - 2):i + 1]          # 3-month rolling window
        sub = findings[(findings["month"].isin(win)) & (findings["severity"] == sev)]
        res = sub[sub["resolved"]]
        sla_series.append(round(100 * res["closed_on_time"].mean(), 1) if len(res) else None)
        mttr_series.append(round(res["mttr"].mean(), 1) if len(res) else None)
    sla_by_sev[sev] = sla_series
    mttr_by_sev[sev] = mttr_series

# quarter deltas for tiles (last 3 months vs previous 3)
def window(df, mlist):
    return df[df["month"].isin(mlist)]

last3, prev3 = months[-3:], months[-6:-3]
res_last = window(findings, last3); res_last = res_last[res_last["resolved"]]
res_prev = window(findings, prev3); res_prev = res_prev[res_prev["resolved"]]
sla_now = round(100 * res_last["closed_on_time"].mean(), 1)
sla_prev = round(100 * res_prev["closed_on_time"].mean(), 1)
mttr_high_now = round(res_last[res_last["severity"] == "High"]["mttr"].mean(), 1)
mttr_high_prev = round(res_prev[res_prev["severity"] == "High"]["mttr"].mean(), 1)

phishing["click_rate"] = round(100 * phishing["clicked"] / phishing["sent"], 1)
phishing["report_rate"] = round(100 * phishing["reported"] / phishing["sent"], 1)
click_now = phishing["click_rate"].iloc[-1]
click_prev = phishing["click_rate"].iloc[-4]

patching["latency"] = (patching["patch_applied"] - patching["patch_released"]).dt.days
patching["month"] = patching["patch_released"].dt.to_period("M")
plat_now = int(window(patching, last3)["latency"].median())
plat_prev = int(window(patching, prev3)["latency"].median())
patch_by_class = patching[patching["month"].isin(last3)].groupby("asset_class")["latency"].median().sort_values()

# open findings aging
open_f = findings[~findings["resolved"]].copy()
open_f["age"] = (pd.Timestamp(TODAY) - open_f["opened"]).dt.days
buckets = AGE_BUCKETS
open_f["bucket"] = open_f["age"].map(age_bucket)
aging = {sev: [int(((open_f["severity"] == sev) & (open_f["bucket"] == b)).sum()) for b in buckets] for sev in SEVERITIES}

# residual risk heatmap + top risks
heat = [[0] * 5 for _ in range(5)]          # heat[impact-1][likelihood-1]
heat_items = [[[] for _ in range(5)] for _ in range(5)]
for _, r in risks.iterrows():
    li, im = int(r["residual_likelihood"]), int(r["residual_impact"])
    heat[im - 1][li - 1] += 1
    heat_items[im - 1][li - 1].append(f'{r["id"]} {r["threat"]}')
top5 = risks.sort_values("residual_score", ascending=False).head(5)
high_risks = int((risks["residual_score"] >= 15).sum())

# ------------------------------------------------- executive summary ----
def arrow(delta, up_is_good):
    good = (delta > 0) == up_is_good if delta != 0 else True
    return good

summary = (
    f"Security posture improved over the last quarter: {sla_now:.0f}% of findings were remediated within SLA "
    f"(up from {sla_prev:.0f}%), and mean time to remediate High-severity findings fell from {mttr_high_prev:.0f} "
    f"to {mttr_high_now:.0f} days. The phishing simulation click rate dropped to {click_now:.0f}% "
    f"(from {click_prev:.0f}% three months earlier) while the median patch latency is now {plat_now} days. "
    f"{high_risks} risks remain in the High band after treatment; the top residual risks below require "
    f"management decisions on ownership and funding."
)

payload = {
    "months": month_labels,
    "sla": sla_by_sev,
    "mttr": mttr_by_sev,
    "aging": {"buckets": buckets, "data": aging},
    "phishing": {
        "labels": [d.strftime("%b %y") for d in phishing["campaign_date"]],
        "click": list(phishing["click_rate"]),
        "report": list(phishing["report_rate"]),
    },
    "patch": {"labels": list(patch_by_class.index), "values": [int(v) for v in patch_by_class.values]},
    "heat": heat,
    "heatItems": heat_items,
    "targets": {"sla": TARGETS["sla_pct"]["target"], "click": TARGETS["phish_click"]["target"],
                "patch": TARGETS["patch_latency"]["target"]},
}

tiles = [
    ("Findings remediated within SLA", f"{sla_now:.0f}%", sla_now - sla_prev, "pp vs previous quarter", True, "sla_pct", sla_now),
    ("Mean time to remediate (High)", f"{mttr_high_now:.0f} days", mttr_high_now - mttr_high_prev, "days vs previous quarter", False, "mttr_high", mttr_high_now),
    ("Phishing click rate", f"{click_now:.0f}%", click_now - click_prev, "pp vs 3 months ago", False, "phish_click", click_now),
    ("Median patch latency", f"{plat_now} days", plat_now - plat_prev, "days vs previous quarter", False, "patch_latency", plat_now),
]

STATUS_META = {"good": ("\u2713", "On target"), "warn": ("!", "Attention"), "bad": ("\u2717", "Off target")}

def tile_html(label, value, delta, unit, up_good, kpi, now_value):
    good = (delta <= 0) ^ up_good if delta != 0 else True
    sign = "+" if delta > 0 else "\u2212" if delta < 0 else "\u00b1"
    cls = "good" if good else "bad"
    st = tile_status(kpi, now_value)
    icon, word = STATUS_META[st]
    tgt = TARGETS[kpi]["label"]
    return (f'<div class="tile"><div class="tile-label">{label}</div>'
            f'<div class="tile-value">{value}</div>'
            f'<div class="tile-delta {cls}">{sign}{abs(delta):.0f} {unit}</div>'
            f'<div class="tile-status st-{st}"><span class="st-ic">{icon}</span> {word} \u00b7 {tgt}</div></div>')

tiles_html = "".join(tile_html(*t) for t in tiles)

def table_html(headers, rows_):
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows_)
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'

top5_html = table_html(
    ["ID", "Asset", "Threat", "Owner", "Treatment", "Residual"],
    [[r["id"], r["asset"], r["threat"], r["owner"], r["treatment"],
      f'<span class="score s{min(25, r["residual_score"])//1}">{r["residual_score"]}</span>'] for _, r in top5.iterrows()],
)
register_html = table_html(
    ["ID", "Asset", "Threat", "ISO 27001", "L", "I", "Inherent", "Treatment", "Residual", "Owner", "Status"],
    [[r["id"], r["asset"], r["threat"], r["iso_ref"], r["likelihood"], r["impact"], r["inherent_score"],
      r["treatment"], r["residual_score"], r["owner"], r["status"]] for _, r in
     risks.sort_values("residual_score", ascending=False).iterrows()],
)

def data_table(headers, rows_):
    return f'<details class="tbl"><summary>View data as table</summary>{table_html(headers, rows_)}</details>'

sla_table = data_table(["Month"] + SEVERITIES,
    [[month_labels[i]] + [sla_by_sev[s][i] if sla_by_sev[s][i] is not None else "–" for s in SEVERITIES] for i in range(len(months))])
mttr_table = data_table(["Month"] + SEVERITIES,
    [[month_labels[i]] + [mttr_by_sev[s][i] if mttr_by_sev[s][i] is not None else "–" for s in SEVERITIES] for i in range(len(months))])
aging_table = data_table(["Age"] + SEVERITIES, [[b] + [aging[s][i] for s in SEVERITIES] for i, b in enumerate(buckets)])
phish_table = data_table(["Campaign", "Click rate %", "Report rate %"],
    [[payload["phishing"]["labels"][i], payload["phishing"]["click"][i], payload["phishing"]["report"][i]]
     for i in range(len(phishing))])
patch_table = data_table(["Asset class", "Median latency (days)"],
    list(zip(payload["patch"]["labels"], payload["patch"]["values"])))

HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Risk & KPI Dashboard</title>
<script>__CHARTJS__</script>
<style>
:root {
  color-scheme: light;
  --plane: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --border: rgba(11,11,11,0.10);
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a;
  --good: #006300; --bad: #d03b3b;
  --heat0: #f0efec;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --plane: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink2: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
    --s1: #3987e5; --s2: #d95926; --s3: #199e70;
    --good: #0ca30c; --bad: #e66767;
    --heat0: #262625;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --plane: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink2: #c3c2b7;
  --muted: #898781; --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
  --s1: #3987e5; --s2: #d95926; --s3: #199e70;
  --good: #0ca30c; --bad: #e66767;
  --heat0: #262625;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--plane); color: var(--ink);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px 16px 60px; }
header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
h1 { font-size: 22px; margin: 0; }
.sub { color: var(--ink2); font-size: 13px; }
#themeBtn { margin-left: auto; border: 1px solid var(--border); background: var(--surface);
  color: var(--ink2); border-radius: 8px; padding: 5px 12px; cursor: pointer; font: inherit; font-size: 13px; }
h2 { font-size: 15px; margin: 26px 0 10px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }
.summary { font-size: 14.5px; color: var(--ink); }
.summary b { color: var(--ink); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.tile-label { color: var(--ink2); font-size: 12.5px; }
.tile-value { font-size: 30px; font-weight: 600; margin: 2px 0; }
.tile-delta { font-size: 12.5px; font-weight: 600; }
.tile-delta.good { color: var(--good); } .tile-delta.bad { color: var(--bad); }
.tile-status { margin-top: 7px; font-size: 11.5px; color: var(--ink2); border-top: 1px solid var(--grid);
  padding-top: 6px; }
.tile-status .st-ic { display: inline-flex; align-items: center; justify-content: center;
  width: 14px; height: 14px; border-radius: 50%; color: #fff; font-size: 9px; font-weight: 700;
  vertical-align: 1px; margin-right: 2px; }
.st-good .st-ic { background: #0ca30c; } .st-warn .st-ic { background: #fab219; color: #0b0b0b; }
.st-bad .st-ic { background: #d03b3b; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 860px) { .grid2 { grid-template-columns: 1fr; } }
.chart-card h3, .card h3 { font-size: 13.5px; margin: 0 0 2px; }
.chart-card .note, .card .note { color: var(--muted); font-size: 12px; margin: 0 0 10px; }
.chart-box { position: relative; height: 240px; }
/* heatmap */
.heat { display: grid; grid-template-columns: auto repeat(5, 1fr); gap: 3px; }
.heat .cell { aspect-ratio: 1.6; border-radius: 6px; display: flex; align-items: center;
  justify-content: center; font-weight: 600; font-size: 14px; position: relative; cursor: default; }
.heat .axis { display: flex; align-items: center; justify-content: center;
  color: var(--muted); font-size: 11px; font-weight: 500; }
.heat-foot { color: var(--muted); font-size: 11px; display: flex; justify-content: space-between; margin-top: 6px; }
#heatTip { position: fixed; z-index: 10; background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 8px 10px; font-size: 12px; max-width: 300px; box-shadow: 0 4px 14px rgba(0,0,0,.15);
  pointer-events: none; display: none; }
#heatTip b { display: block; margin-bottom: 2px; }
table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
th { text-align: left; color: var(--ink2); font-weight: 600; border-bottom: 1px solid var(--grid); padding: 6px 8px; }
td { border-bottom: 1px solid var(--grid); padding: 5px 8px; font-variant-numeric: tabular-nums; }
details.tbl { margin-top: 8px; }
details.tbl summary, details.reg summary { color: var(--ink2); font-size: 12.5px; cursor: pointer; }
details.reg { margin-top: 14px; }
details.reg .card-inner { overflow-x: auto; margin-top: 10px; }
footer { color: var(--muted); font-size: 12px; margin-top: 30px; }
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Security Risk &amp; KPI Dashboard</h1>
  <span class="sub">Example Corp · reporting period Nov 2025 – Oct 2026 · generated __TODAY__</span>
  <button id="themeBtn" type="button">Toggle theme</button>
</header>

<h2>Executive summary</h2>
<div class="card summary">__SUMMARY__</div>
<div class="tiles">__TILES__</div>

<div class="grid2" style="margin-top:14px">
  <div class="card">
    <h3>Residual risk heatmap</h3>
    <p class="note">Count of risks after treatment · likelihood × impact</p>
    <div class="heat" id="heat"></div>
    <div class="heat-foot"><span>Likelihood →</span><span>↑ Impact</span></div>
  </div>
  <div class="card">
    <h3>Top residual risks</h3>
    <p class="note">Highest risk after current treatment · full register below</p>
    <div style="overflow-x:auto">__TOP5__</div>
  </div>
</div>

<h2>Operational metrics</h2>
<div class="grid2">
  <div class="card chart-card">
    <h3>Findings remediated within SLA</h3>
    <p class="note">% closed within SLA, 3-month rolling (SLA: Critical 7d · High 30d · Medium 90d)</p>
    <div class="chart-box"><canvas id="slaChart"></canvas></div>
    __SLA_TABLE__
  </div>
  <div class="card chart-card">
    <h3>Mean time to remediate</h3>
    <p class="note">Average days from opened to closed, 3-month rolling</p>
    <div class="chart-box"><canvas id="mttrChart"></canvas></div>
    __MTTR_TABLE__
  </div>
  <div class="card chart-card">
    <h3>Open findings by age</h3>
    <p class="note">Currently open findings, stacked by severity</p>
    <div class="chart-box"><canvas id="agingChart"></canvas></div>
    __AGING_TABLE__
  </div>
  <div class="card chart-card">
    <h3>Phishing simulation results</h3>
    <p class="note">Monthly campaigns · ~200 recipients each</p>
    <div class="chart-box"><canvas id="phishChart"></canvas></div>
    __PHISH_TABLE__
  </div>
</div>
<div class="card chart-card" style="margin-top:14px">
  <h3>Median patch latency by asset class</h3>
  <p class="note">Days from patch release to deployment · last quarter</p>
  <div class="chart-box" style="height:210px"><canvas id="patchChart"></canvas></div>
  __PATCH_TABLE__
</div>

<details class="reg">
  <summary>Full risk register (__NRISKS__ risks)</summary>
  <div class="card card-inner">__REGISTER__</div>
</details>

<footer>Methodology: 5×5 scoring aligned to ISO 27005 / NIST SP 800-30 · data is synthetic demo data ·
built with Python + Chart.js · <span id="src">github.com/fsn4k3/risk-kpi-dashboard</span></footer>
</div>

<div id="heatTip"></div>
<script>
const DATA = __PAYLOAD__;

/* ---------- theme ---------- */
const root = document.documentElement;
const btn = document.getElementById('themeBtn');
btn.addEventListener('click', () => {
  const dark = getComputedStyle(root).colorScheme.includes('dark');
  root.dataset.theme = dark ? 'light' : 'dark';
  renderAll();
});
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', renderAll);

function cssVar(name) { return getComputedStyle(root).getPropertyValue(name).trim(); }

/* ---------- heatmap ---------- */
const heatRampLight = ['#cde2fb','#9ec5f4','#6da7ec','#3987e5','#256abf','#184f95'];
const heatRampDark  = ['#184f95','#1c5cab','#256abf','#2a78d6','#3987e5','#5598e7'];
const tip = document.getElementById('heatTip');
function renderHeat() {
  const dark = getComputedStyle(root).colorScheme.includes('dark');
  const ramp = dark ? heatRampDark : heatRampLight;
  const el = document.getElementById('heat');
  el.replaceChildren();
  const maxc = Math.max(...DATA.heat.flat());
  for (let im = 4; im >= 0; im--) {
    const ax = document.createElement('div');
    ax.className = 'axis'; ax.textContent = im + 1;
    el.appendChild(ax);
    for (let li = 0; li < 5; li++) {
      const c = DATA.heat[im][li];
      const cell = document.createElement('div');
      cell.className = 'cell';
      if (c === 0) { cell.style.background = cssVar('--heat0'); cell.style.color = cssVar('--muted'); }
      else {
        const idx = Math.min(ramp.length - 1, Math.round((c / maxc) * (ramp.length - 1)));
        cell.style.background = ramp[idx];
        cell.style.color = dark ? '#ffffff' : (idx >= 3 ? '#ffffff' : '#0b0b0b');
      }
      cell.textContent = c;
      const items = DATA.heatItems[im][li];
      if (items.length) {
        cell.addEventListener('pointermove', e => {
          tip.replaceChildren();
          const b = document.createElement('b');
          b.textContent = `Likelihood ${li+1} × Impact ${im+1} — ${c} risk${c>1?'s':''}`;
          tip.appendChild(b);
          items.slice(0, 6).forEach(t => { const d = document.createElement('div'); d.textContent = t; tip.appendChild(d); });
          if (items.length > 6) { const d = document.createElement('div'); d.textContent = `… and ${items.length-6} more`; tip.appendChild(d); }
          tip.style.display = 'block';
          tip.style.left = Math.min(e.clientX + 14, innerWidth - 320) + 'px';
          tip.style.top = (e.clientY + 14) + 'px';
        });
        cell.addEventListener('pointerleave', () => tip.style.display = 'none');
      }
      el.appendChild(cell);
    }
  }
  const corner = document.createElement('div'); corner.className = 'axis'; corner.textContent = '';
  el.appendChild(corner);
  for (let li = 1; li <= 5; li++) { const ax = document.createElement('div'); ax.className = 'axis'; ax.textContent = li; el.appendChild(ax); }
}

/* ---------- charts ---------- */
let charts = [];
function baseOpts(yTitle, pct, barLegend) {
  return {
    responsive: true, maintainAspectRatio: false, animation: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { labels: { color: cssVar('--ink2'),
        boxWidth: barLegend ? 12 : 18, boxHeight: barLegend ? 12 : 3, font: { size: 12 } } },
      tooltip: { backgroundColor: cssVar('--surface'), titleColor: cssVar('--ink'),
        bodyColor: cssVar('--ink'), borderColor: cssVar('--grid'), borderWidth: 1,
        boxWidth: 10, boxHeight: 2, usePointStyle: false }
    },
    scales: {
      x: { grid: { display: false }, ticks: { color: cssVar('--muted'), font: { size: 11 } },
           border: { color: cssVar('--grid') } },
      y: { grid: { color: cssVar('--grid'), lineWidth: 1 }, border: { display: false },
           ticks: { color: cssVar('--muted'), font: { size: 11 },
                    callback: v => pct ? v + '%' : v },
           title: yTitle ? { display: true, text: yTitle, color: cssVar('--muted'), font: { size: 11 } } : undefined,
           beginAtZero: true, max: pct ? 100 : undefined }
    }
  };
}
function line(ds, color) {
  return { ...ds, borderColor: color, backgroundColor: color, borderWidth: 2,
    pointRadius: 0, pointHoverRadius: 5, pointHoverBorderColor: cssVar('--surface'),
    pointHoverBorderWidth: 2, tension: 0.25, spanGaps: true };
}
const targetLine = {
  id: 'targetLine',
  afterDatasetsDraw(chart, args, opts) {
    if (!opts || opts.value == null) return;
    const { ctx, chartArea, scales } = chart;
    const horiz = opts.axis === 'x';
    const scale = horiz ? scales.x : scales.y;
    const pos = scale.getPixelForValue(opts.value);
    ctx.save();
    ctx.strokeStyle = cssVar('--muted'); ctx.lineWidth = 1;
    ctx.setLineDash([5, 4]);
    ctx.beginPath();
    if (horiz) { ctx.moveTo(pos, chartArea.top); ctx.lineTo(pos, chartArea.bottom); }
    else { ctx.moveTo(chartArea.left, pos); ctx.lineTo(chartArea.right, pos); }
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = cssVar('--muted');
    ctx.font = '10px system-ui, sans-serif';
    if (horiz) { ctx.textAlign = 'left'; ctx.fillText(opts.label, pos + 4, chartArea.top + 10); }
    else { ctx.textAlign = 'right'; ctx.fillText(opts.label, chartArea.right, pos - 4); }
    ctx.restore();
  }
};
Chart.register(targetLine);

function renderCharts() {
  charts.forEach(c => c.destroy()); charts = [];
  const C = [cssVar('--s1'), cssVar('--s2'), cssVar('--s3')];
  const SEV = ['Critical', 'High', 'Medium'];

  charts.push(new Chart(slaChart, { type: 'line',
    data: { labels: DATA.months,
      datasets: SEV.map((s, i) => line({ label: s, data: DATA.sla[s] }, C[i])) },
    options: { ...baseOpts(null, true), plugins: { ...baseOpts(null, true).plugins,
      targetLine: { value: DATA.targets.sla, label: 'target ' + DATA.targets.sla + '%' } } } }));

  charts.push(new Chart(mttrChart, { type: 'line',
    data: { labels: DATA.months,
      datasets: SEV.map((s, i) => line({ label: s, data: DATA.mttr[s] }, C[i])) },
    options: baseOpts('days', false) }));

  const agingBase = baseOpts(null, false, true);
  charts.push(new Chart(agingChart, { type: 'bar',
    data: { labels: DATA.aging.buckets,
      datasets: SEV.map((s, i) => ({ label: s, data: DATA.aging.data[s], backgroundColor: C[i],
        maxBarThickness: 24, borderColor: cssVar('--surface'), borderWidth: 1,
        borderRadius: 3, stack: 'a' })) },
    options: { ...agingBase,
      scales: { ...agingBase.scales,
        x: { ...agingBase.scales.x, stacked: true },
        y: { ...agingBase.scales.y, stacked: true } } } }));

  charts.push(new Chart(phishChart, { type: 'line',
    data: { labels: DATA.phishing.labels,
      datasets: [ line({ label: 'Click rate', data: DATA.phishing.click }, C[1]),
                  line({ label: 'Report rate', data: DATA.phishing.report }, C[0]) ] },
    options: { ...baseOpts('%', false), plugins: { ...baseOpts('%', false).plugins,
      targetLine: { value: DATA.targets.click, label: 'click target < ' + DATA.targets.click + '%' } } } }));

  charts.push(new Chart(patchChart, { type: 'bar',
    data: { labels: DATA.patch.labels,
      datasets: [{ label: 'Median days', data: DATA.patch.values, backgroundColor: C[0],
        maxBarThickness: 20, borderRadius: { topRight: 4, bottomRight: 4 }, borderSkipped: 'start' }] },
    options: { ...baseOpts(null, false), indexAxis: 'y',
      plugins: { ...baseOpts(null, false).plugins, legend: { display: false },
        targetLine: { value: DATA.targets.patch, label: 'target ' + DATA.targets.patch + 'd', axis: 'x' } },
      scales: { x: { grid: { color: cssVar('--grid') }, border: { display: false },
                     ticks: { color: cssVar('--muted'), font: { size: 11 } }, beginAtZero: true,
                     title: { display: true, text: 'days', color: cssVar('--muted'), font: { size: 11 } } },
                y: { grid: { display: false }, border: { color: cssVar('--grid') },
                     ticks: { color: cssVar('--ink2'), font: { size: 12 } } } } } }));
}
function renderAll() { renderHeat(); renderCharts(); }
renderAll();
</script>
</body>
</html>
"""

chartjs = (ROOT / "vendor/chart.umd.js").read_text()
html = (HTML
    .replace("__CHARTJS__", chartjs)
    .replace("__PAYLOAD__", json.dumps(payload))
    .replace("__SUMMARY__", summary)
    .replace("__TILES__", tiles_html)
    .replace("__TOP5__", top5_html)
    .replace("__SLA_TABLE__", sla_table)
    .replace("__MTTR_TABLE__", mttr_table)
    .replace("__AGING_TABLE__", aging_table)
    .replace("__PHISH_TABLE__", phish_table)
    .replace("__PATCH_TABLE__", patch_table)
    .replace("__REGISTER__", register_html)
    .replace("__NRISKS__", str(len(risks)))
    .replace("__TODAY__", TODAY.isoformat()))

(DIST / "dashboard.html").write_text(html)
print(f"dist/dashboard.html written ({len(html)//1024} KB)")
print("Summary:", summary)
