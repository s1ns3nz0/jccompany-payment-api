#!/usr/bin/env python3
"""
Risk Assessment Dashboard Generator
====================================
Reads risk-release-result.json (or any phase) and generates a single-file
HTML dashboard for risk.miata.cloud (CloudFront + S3).

Outputs:
  - index.html      (interactive dashboard)
  - data/latest.json (trimmed JSON for client-side rendering)
  - data/history.json (manifest of past runs, appended each time)

Usage:
  python risk-dashboard-gen.py \
    --result risk-release-result.json \
    --output-dir ./risk-site \
    --commit abc1234 \
    --run-id 12345
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(description="Risk Dashboard Generator")
    p.add_argument("--result", required=True, help="Path to risk-release-result.json")
    p.add_argument("--output-dir", default="./risk-site", help="Output directory")
    p.add_argument("--commit", default="unknown")
    p.add_argument("--run-id", default="0")
    p.add_argument("--history-json", default="", help="Path to existing history.json from S3")
    return p.parse_args()


def load_result(path):
    with open(path) as f:
        return json.load(f)


def build_latest_json(data, commit, run_id):
    """Extract display-relevant data into a smaller JSON for the frontend."""
    gate = data.get("gate", {})
    fc = gate.get("findings_count", {})
    auth = data.get("authorization", {})
    sar = data.get("sar", {})
    poam = data.get("poam", {})
    sp = data.get("sp800_30_report", {})

    # Top POA&M items sorted by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "info": 5}
    poam_items = sorted(
        poam.get("items", []),
        key=lambda x: (severity_order.get(x.get("severity", "unknown"), 9), -(x.get("weakness_detail", {}).get("cvss_score", 0) or 0))
    )

    # Trim poam items to essential display fields
    display_items = []
    for item in poam_items:
        wd = item.get("weakness_detail", {})
        sd = item.get("source_detail", {})
        lc = item.get("lifecycle", {})
        display_items.append({
            "id": item.get("id", ""),
            "finding_id": item.get("finding_id", ""),
            "weakness": item.get("weakness", "")[:120],
            "severity": item.get("severity", "unknown"),
            "source": item.get("source", ""),
            "scan_type": sd.get("scan_type", ""),
            "package": wd.get("package", ""),
            "cvss": wd.get("cvss_score", 0),
            "epss": wd.get("epss_score", 0),
            "supply_chain": wd.get("supply_chain", False),
            "due_date": lc.get("due_date", ""),
            "sla_days": lc.get("sla_days", 0),
            "phase": sd.get("phase", ""),
        })

    # SAR control assessments summary
    ca = sar.get("control_assessments", [])
    controls_by_status = {}
    for c in ca:
        st = c.get("status", "unknown")
        controls_by_status.setdefault(st, []).append({
            "id": c.get("control_id", ""),
            "title": c.get("title", "")[:80],
            "assessor": c.get("assessor", ""),
            "findings": c.get("findings_count", 0),
        })

    # Scanner distribution
    scanner_counts = {}
    for item in poam.get("items", []):
        s = item.get("source", "unknown")
        scanner_counts[s] = scanner_counts.get(s, 0) + 1

    # Threshold results
    thresholds = gate.get("threshold_results", [])

    return {
        "meta": {
            "assessment_id": data.get("assessment_id", ""),
            "product": data.get("product", ""),
            "mode": data.get("mode", ""),
            "created_at": data.get("created_at", ""),
            "duration_seconds": data.get("duration_seconds", 0),
            "commit": commit,
            "run_id": run_id,
        },
        "decision": {
            "authorization": auth.get("decision", "UNKNOWN"),
            "risk_level": auth.get("risk_level", "unknown"),
            "reasoning": auth.get("reasoning", ""),
            "valid_until": auth.get("valid_until", ""),
        },
        "findings": {
            "total": data.get("findings_count", 0),
            "critical": fc.get("critical", 0),
            "high": fc.get("high", 0),
            "medium": fc.get("medium", 0),
            "low": fc.get("low", 0),
        },
        "thresholds": thresholds,
        "sar": {
            "total": sar.get("total_controls", 0),
            "satisfied": sar.get("satisfied", 0),
            "other": sar.get("other_than_satisfied", 0),
            "not_assessed": sar.get("not_assessed", 0),
            "controls_by_status": controls_by_status,
        },
        "cia": data.get("sp800_30_report", {}).get("cia_impact_levels", {}),
        "scanner_counts": scanner_counts,
        "recommendations": sp.get("recommendations", [])[:5],
        "executive_summary": sp.get("executive_summary", ""),
        "poam_items": display_items,
    }


def update_history(history_path, latest, commit, run_id):
    """Append current run to history manifest."""
    history = []
    if history_path and os.path.exists(history_path):
        try:
            with open(history_path) as f:
                history = json.load(f)
        except (json.JSONDecodeError, OSError):
            history = []

    entry = {
        "assessment_id": latest["meta"]["assessment_id"],
        "created_at": latest["meta"]["created_at"],
        "commit": commit[:7],
        "run_id": run_id,
        "decision": latest["decision"]["authorization"],
        "findings": latest["findings"]["total"],
        "critical": latest["findings"]["critical"],
        "sar_satisfied": latest["sar"]["satisfied"],
        "sar_total": latest["sar"]["total"],
    }

    history.insert(0, entry)
    history = history[:20]  # Keep last 20 runs
    return history


def generate_html(latest_json):
    """Generate single-file HTML dashboard with embedded data."""
    data_json = json.dumps(latest_json, default=str)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Risk Assessment — {latest_json["meta"]["product"]}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --bg:#0a0e17;--surface:#111827;--surface2:#1a2332;--border:#1e2d3d;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6;
  --green:#22c55e;--red:#ef4444;--accent:#6366f1;
}}
body{{font-family:'Plus Jakarta Sans',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}}
.mono{{font-family:'JetBrains Mono',monospace}}

/* Layout */
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.grid{{display:grid;gap:16px}}
.grid-4{{grid-template-columns:repeat(4,1fr)}}
.grid-3{{grid-template-columns:repeat(3,1fr)}}
.grid-2{{grid-template-columns:1fr 1fr}}
@media(max-width:768px){{.grid-4,.grid-3,.grid-2{{grid-template-columns:1fr}}}}

/* Header */
.header{{display:flex;justify-content:space-between;align-items:center;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:24px}}
.header h1{{font-size:20px;font-weight:700}}
.header h1 span{{color:var(--text3);font-weight:400}}
.badge{{display:inline-flex;align-items:center;gap:6px;padding:6px 16px;border-radius:6px;font-weight:700;font-size:14px;letter-spacing:1px}}
.badge-ato{{background:#052e16;color:#22c55e;border:1px solid #166534}}
.badge-dato{{background:#2d0a0a;color:#ef4444;border:1px solid #7f1d1d}}

/* Cards */
.card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px}}
.card-title{{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:8px}}
.card-value{{font-size:32px;font-weight:700}}
.card-sub{{font-size:12px;color:var(--text2);margin-top:4px}}

/* Severity colors */
.sev-critical{{color:var(--critical)}}.sev-high{{color:var(--high)}}
.sev-medium{{color:var(--medium)}}.sev-low{{color:var(--low)}}

/* Bar chart */
.bar-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
.bar-label{{width:70px;font-size:12px;color:var(--text2);text-align:right;text-transform:uppercase;font-weight:600}}
.bar-track{{flex:1;height:28px;background:var(--surface2);border-radius:4px;overflow:hidden;position:relative}}
.bar-fill{{height:100%;border-radius:4px;display:flex;align-items:center;padding-left:10px;font-size:12px;font-weight:600;min-width:30px;transition:width .6s ease}}
.bar-fill.critical{{background:var(--critical)}}.bar-fill.high{{background:var(--high)}}
.bar-fill.medium{{background:var(--medium)}}.bar-fill.low{{background:var(--low)}}

/* Progress ring */
.progress-container{{display:flex;align-items:center;gap:20px}}
.progress-ring{{position:relative;width:100px;height:100px}}
.progress-ring svg{{transform:rotate(-90deg)}}
.progress-ring .value{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700}}

/* Table */
.table-wrap{{overflow-x:auto;margin-top:12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:10px 12px;border-bottom:2px solid var(--border);color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:600}}
td{{padding:10px 12px;border-bottom:1px solid var(--border)}}
tr:hover{{background:var(--surface2)}}
.pill{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase}}
.pill-critical{{background:#2d0a0a;color:var(--critical)}}.pill-high{{background:#2d1a0a;color:var(--high)}}
.pill-medium{{background:#2d2a0a;color:var(--medium)}}.pill-low{{background:#0a1a2d;color:var(--low)}}

/* Sections */
.section{{margin-bottom:24px}}
.section-title{{font-size:14px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.section-title .icon{{width:20px;height:20px;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:12px}}

/* Meta */
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}}
.meta-item{{padding:8px 12px;background:var(--surface2);border-radius:4px}}
.meta-item .label{{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:1px}}
.meta-item .val{{font-size:13px;margin-top:2px}}

/* Gate thresholds */
.threshold{{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px}}
.threshold .dot{{width:8px;height:8px;border-radius:50%}}
.dot-pass{{background:var(--green)}}.dot-fail{{background:var(--red)}}

/* Tabs */
.tabs{{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px}}
.tab{{padding:8px 16px;cursor:pointer;font-size:13px;color:var(--text3);border-bottom:2px solid transparent;transition:all .2s}}
.tab.active{{color:var(--text);border-bottom-color:var(--accent)}}
.tab-content{{display:none}}.tab-content.active{{display:block}}

/* Exec summary */
.exec-summary{{padding:16px;background:var(--surface2);border-radius:6px;font-size:13px;line-height:1.8;color:var(--text2);border-left:3px solid var(--accent)}}

/* Footer */
.footer{{margin-top:32px;padding:16px 0;border-top:1px solid var(--border);font-size:11px;color:var(--text3);text-align:center}}
</style>
</head>
<body>
<div class="container" id="app"></div>
<script>
const DATA = {data_json};

function render() {{
  const d = DATA;
  const isATO = d.decision.authorization === 'ATO';
  const badgeClass = isATO ? 'badge-ato' : 'badge-dato';
  const sarPct = d.sar.total > 0 ? Math.round(d.sar.satisfied / d.sar.total * 100) : 0;
  const maxFinding = Math.max(d.findings.critical, d.findings.high, d.findings.medium, d.findings.low, 1);
  const ts = d.meta.created_at ? new Date(d.meta.created_at).toLocaleString() : '-';

  document.getElementById('app').innerHTML = `
    <div class="header">
      <h1>Risk Assessment <span>// ${{d.meta.product}}</span></h1>
      <span class="badge ${{badgeClass}}">
        ${{isATO ? '&#x2713;' : '&#x2717;'}} ${{d.decision.authorization}}
      </span>
    </div>

    <!-- Meta -->
    <div class="section">
      <div class="meta-grid">
        <div class="meta-item"><div class="label">Assessment ID</div><div class="val mono">${{d.meta.assessment_id}}</div></div>
        <div class="meta-item"><div class="label">Timestamp</div><div class="val">${{ts}}</div></div>
        <div class="meta-item"><div class="label">Commit</div><div class="val mono">${{d.meta.commit.slice(0,7)}}</div></div>
        <div class="meta-item"><div class="label">Mode</div><div class="val">${{d.meta.mode}}</div></div>
        <div class="meta-item"><div class="label">Risk Level</div><div class="val" style="color:${{d.decision.risk_level==='unacceptable'?'var(--critical)':'var(--medium)'}}">${{d.decision.risk_level}}</div></div>
        <div class="meta-item"><div class="label">Duration</div><div class="val">${{d.meta.duration_seconds}}s</div></div>
        <div class="meta-item"><div class="label">Run ID</div><div class="val mono">${{d.meta.run_id}}</div></div>
        <div class="meta-item"><div class="label">Valid Until</div><div class="val">${{d.decision.valid_until || '-'}}</div></div>
      </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-4 section">
      <div class="card"><div class="card-title">Total Findings</div><div class="card-value">${{d.findings.total}}</div></div>
      <div class="card"><div class="card-title">Critical + High</div><div class="card-value sev-critical">${{d.findings.critical + d.findings.high}}</div><div class="card-sub">C=${{d.findings.critical}} H=${{d.findings.high}}</div></div>
      <div class="card"><div class="card-title">SAR Coverage</div>
        <div class="progress-container">
          <div class="progress-ring">
            <svg width="100" height="100"><circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface2)" stroke-width="8"/>
            <circle cx="50" cy="50" r="42" fill="none" stroke="${{sarPct>=80?'var(--green)':sarPct>=50?'var(--medium)':'var(--critical)'}}" stroke-width="8" stroke-dasharray="${{sarPct*2.64}} 264" stroke-linecap="round"/></svg>
            <div class="value">${{sarPct}}%</div>
          </div>
          <div><div style="font-size:13px;color:var(--text2)">${{d.sar.satisfied}} / ${{d.sar.total}}</div></div>
        </div>
      </div>
      <div class="card"><div class="card-title">CIA Impact</div>
        <div style="font-size:14px;margin-top:8px">
          <div>C: <span style="color:var(--${{d.cia.confidentiality==='high'?'critical':'medium'}})">&#9646; ${{d.cia.confidentiality||'-'}}</span></div>
          <div>I: <span style="color:var(--${{d.cia.integrity==='high'?'critical':'medium'}})">&#9646; ${{d.cia.integrity||'-'}}</span></div>
          <div>A: <span style="color:var(--${{d.cia.availability==='high'?'critical':'medium'}})">&#9646; ${{d.cia.availability||'-'}}</span></div>
        </div>
      </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
      <div class="section-title">Executive Summary (SP 800-30)</div>
      <div class="exec-summary">${{d.executive_summary||'No summary available.'}}</div>
    </div>

    <!-- Findings Breakdown -->
    <div class="grid grid-2 section">
      <div class="card">
        <div class="card-title">Findings by Severity</div>
        <div style="margin-top:12px">
          ${{['critical','high','medium','low'].map(s => `
            <div class="bar-row">
              <div class="bar-label">${{s}}</div>
              <div class="bar-track"><div class="bar-fill ${{s}}" style="width:${{Math.max(d.findings[s]/maxFinding*100,2)}}%">${{d.findings[s]}}</div></div>
            </div>`).join('')}}
        </div>
      </div>
      <div class="card">
        <div class="card-title">Gate Thresholds</div>
        <div style="margin-top:8px">
          ${{d.thresholds.map(t => `
            <div class="threshold">
              <div class="dot ${{t.passed?'dot-pass':'dot-fail'}}"></div>
              <span style="flex:1">${{t.name}}</span>
              <span class="mono" style="color:${{t.passed?'var(--green)':'var(--critical)'}}">${{t.actual}}/${{t.limit}}</span>
            </div>`).join('')}}
        </div>
        <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border);font-size:12px;color:var(--text3)">
          ${{d.decision.reasoning}}
        </div>
      </div>
    </div>

    <!-- Findings by Scanner -->
    <div class="section">
      <div class="card">
        <div class="card-title">Findings by Scanner</div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:12px">
          ${{Object.entries(d.scanner_counts).sort((a,b)=>b[1]-a[1]).map(([s,c])=>`
            <div style="padding:8px 16px;background:var(--surface2);border-radius:6px;text-align:center">
              <div style="font-size:20px;font-weight:700">${{c}}</div>
              <div style="font-size:11px;color:var(--text3);text-transform:uppercase">${{s}}</div>
            </div>`).join('')}}
        </div>
      </div>
    </div>

    <!-- Tabs: POA&M / SAR -->
    <div class="section">
      <div class="tabs">
        <div class="tab active" onclick="switchTab(this,'tab-poam')">POA&M Items (${{d.poam_items.length}})</div>
        <div class="tab" onclick="switchTab(this,'tab-sar')">SAR Controls (${{d.sar.total}})</div>
      </div>

      <div class="tab-content active" id="tab-poam">
        <div class="table-wrap"><table>
          <tr><th>Severity</th><th>Finding</th><th>Scanner</th><th>Package</th><th>CVSS</th><th>EPSS</th><th>SLA</th></tr>
          ${{d.poam_items.slice(0,80).map(i => `<tr>
            <td><span class="pill pill-${{i.severity}}">${{i.severity}}</span></td>
            <td class="mono" style="font-size:12px">${{i.finding_id}}</td>
            <td>${{i.source}}</td>
            <td style="color:var(--text2)">${{i.package||'-'}}</td>
            <td class="mono">${{i.cvss||'-'}}</td>
            <td class="mono">${{i.epss?i.epss.toFixed(3):'-'}}</td>
            <td style="color:var(--text3)">${{i.sla_days}}d</td>
          </tr>`).join('')}}
        </table></div>
        ${{d.poam_items.length>80?`<div style="text-align:center;padding:12px;color:var(--text3);font-size:12px">Showing 80 of ${{d.poam_items.length}} items</div>`:''}}
      </div>

      <div class="tab-content" id="tab-sar">
        <div class="grid grid-3" style="margin-bottom:16px">
          <div class="card" style="border-left:3px solid var(--green)"><div class="card-title">Satisfied</div><div class="card-value" style="color:var(--green)">${{d.sar.satisfied}}</div></div>
          <div class="card" style="border-left:3px solid var(--critical)"><div class="card-title">Other than Satisfied</div><div class="card-value" style="color:var(--critical)">${{d.sar.other}}</div></div>
          <div class="card" style="border-left:3px solid var(--text3)"><div class="card-title">Not Assessed</div><div class="card-value" style="color:var(--text3)">${{d.sar.not_assessed}}</div></div>
        </div>
        <div class="table-wrap"><table>
          <tr><th>Status</th><th>Control</th><th>Title</th><th>Assessor</th><th>Findings</th></tr>
          ${{Object.entries(d.sar.controls_by_status).flatMap(([status, ctrls]) =>
            ctrls.slice(0,30).map(c => `<tr>
              <td><span class="pill pill-${{status==='satisfied'?'low':status==='other_than_satisfied'?'critical':'medium'}}">${{status.replace(/_/g,' ')}}</span></td>
              <td class="mono">${{c.id}}</td>
              <td style="color:var(--text2);font-size:12px">${{c.title}}</td>
              <td>${{c.assessor}}</td>
              <td class="mono">${{c.findings}}</td>
            </tr>`)).join('')}}
        </table></div>
      </div>
    </div>

    <div class="footer">
      NIST SP 800-30 Rev 1 | SP 800-37 RMF | DoD DevSecOps Guidebook v2.5 | SSDF SP 800-218 | SP 800-204D<br>
      Generated ${{new Date().toISOString()}} | Assessment ${{d.meta.assessment_id}}
    </div>
  `;
}}

function switchTab(el, id) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(id).classList.add('active');
}}

render();
</script>
</body>
</html>'''


def main():
    args = parse_args()

    print(f"[INFO] Loading result: {args.result}")
    data = load_result(args.result)

    print(f"[INFO] Building dashboard data...")
    latest = build_latest_json(data, args.commit, args.run_id)

    # Create output directory
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "data").mkdir(exist_ok=True)

    # Write latest.json
    with open(out / "data" / "latest.json", "w") as f:
        json.dump(latest, f, indent=2, default=str)
    print(f"[OK] data/latest.json ({len(latest['poam_items'])} items)")

    # Update history
    history = update_history(args.history_json, latest, args.commit, args.run_id)
    with open(out / "data" / "history.json", "w") as f:
        json.dump(history, f, indent=2, default=str)
    print(f"[OK] data/history.json ({len(history)} runs)")

    # Generate HTML
    html = generate_html(latest)
    with open(out / "index.html", "w") as f:
        f.write(html)
    print(f"[OK] index.html ({len(html)} bytes)")

    print(f"[INFO] Output directory: {out}")


if __name__ == "__main__":
    main()
