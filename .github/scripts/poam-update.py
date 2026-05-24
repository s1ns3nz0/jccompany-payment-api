#!/usr/bin/env python3
"""
Risk Dashboard Data Generator
==============================
Reads all phase risk results and generates per-phase JSON for the React dashboard.

Output structure:
  data/latest/{phase}.json      (latest commit data)
  data/latest/manifest.json
  data/latest/projects.json
  data/{short-sha}/{phase}.json (commit-specific snapshot)
  data/{short-sha}/manifest.json
  data/{short-sha}/projects.json

Usage:
  python risk-dashboard-gen.py \
    --results-dir ./risk-results \
    --output-dir ./risk-site \
    --commit abc1234def \
    --run-id 26352376746
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(description="Risk Dashboard Data Generator")
    p.add_argument("--results-dir", required=True, help="Directory with risk result artifacts")
    p.add_argument("--output-dir", default="./risk-site", help="Output directory")
    p.add_argument("--commit", default="unknown", help="Git commit SHA")
    p.add_argument("--run-id", default="0", help="GitHub Actions run ID")
    return p.parse_args()


# ── Phase discovery ──

PHASE_PATTERNS = [
    ("DEVELOP", "risk-assess-develop-*/risk-develop-result.json"),
    ("BUILD",   "risk-assess-build-*/risk-build-result.json"),
    ("TEST",    "risk-assess-test-*/risk-test-result.json"),
    ("RELEASE", "release-artifacts-*/risk-release-result.json"),
    ("DELIVER", "risk-assess-deliver-*/risk-deliver-response.json"),
]


def discover_phases(results_dir):
    """Find all phase result files."""
    found = []
    for phase_name, pattern in PHASE_PATTERNS:
        import glob
        matches = glob.glob(os.path.join(results_dir, pattern))
        if matches:
            try:
                with open(matches[0]) as f:
                    data = json.load(f)
                # Skip error responses
                if "detail" in data and len(data) <= 2:
                    print(f"  [SKIP] {phase_name}: error response")
                    continue
                found.append((phase_name, data))
                print(f"  [OK] {phase_name}: {os.path.basename(matches[0])}")
            except Exception as e:
                print(f"  [ERROR] {phase_name}: {e}")
    return found


# ── Supply chain analysis ──

def norm_pkg(name):
    """Normalize package name: strip maven group prefix."""
    if ":" in name:
        return name.split(":")[-1]
    return name


def build_sc_packages(poam_items):
    """Build deduplicated supply chain package breakdown."""
    sc_items = [i for i in poam_items if i.get("weakness_detail", {}).get("supply_chain")]
    pkg_map = defaultdict(lambda: {"cves": set(), "severities": [], "cvss_max": 0, "epss_max": 0, "fix": ""})

    for item in sc_items:
        wd = item.get("weakness_detail", {})
        pkg = norm_pkg(wd.get("package", "unknown"))
        cve = wd.get("cve_id", "")
        if cve and cve in pkg_map[pkg]["cves"]:
            continue
        pkg_map[pkg]["cves"].add(cve or item.get("finding_id", ""))
        pkg_map[pkg]["severities"].append(item.get("severity", ""))
        cvss = wd.get("cvss_score", 0) or 0
        epss = wd.get("epss_score", 0) or 0
        if cvss > pkg_map[pkg]["cvss_max"]:
            pkg_map[pkg]["cvss_max"] = cvss
        if epss > pkg_map[pkg]["epss_max"]:
            pkg_map[pkg]["epss_max"] = epss
        plan = item.get("remediation", {}).get("plan", "")
        m = re.search(r"to (\d+\.\S+)", plan)
        if m and not pkg_map[pkg]["fix"]:
            pkg_map[pkg]["fix"] = m.group(1).rstrip(".")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    packages = []
    for pkg, info in pkg_map.items():
        sev = Counter(info["severities"])
        worst = min(sev.keys(), key=lambda s: sev_order.get(s, 9)) if sev else "unknown"
        packages.append({
            "package": pkg, "cve_count": len(info["cves"]),
            "critical": sev.get("critical", 0), "high": sev.get("high", 0),
            "medium": sev.get("medium", 0), "low": sev.get("low", 0),
            "cvss_max": info["cvss_max"], "epss_max": round(info["epss_max"], 4),
            "fix": info["fix"], "worst": worst,
        })
    packages.sort(key=lambda x: (sev_order.get(x["worst"], 9), -x["cvss_max"]))
    return packages


# ── Phase data trimming ──

def trim_phase(raw, phase_name, commit, run_id):
    """Convert raw risk platform response to trimmed display JSON."""
    sp = raw.get("sp800_30_report", {})
    poam = raw.get("poam", {}).get("items", [])

    # Threat sources
    ts_all = [
        {"id": t["id"], "type": t["type"], "name": t["name"],
         "capability": t.get("capability", ""), "intent": t.get("intent", ""),
         "targeting": t.get("targeting", "")}
        for t in sp.get("threat_sources", [])
    ]

    # Supply chain map from poam
    sc_map = {}
    for item in poam:
        fid = item.get("finding_id", "")
        sc_map[fid] = item.get("weakness_detail", {}).get("supply_chain", False)

    # Risk chain
    tes = sp.get("threat_events", [])
    tss = sp.get("threat_sources", [])
    las = sp.get("likelihood_assessments", [])
    ias = sp.get("impact_assessments", [])
    rds = sp.get("risk_determinations", [])
    rrs = sp.get("risk_responses", [])

    chain = []
    for i in range(len(tes)):
        te = tes[i] if i < len(tes) else {}
        ts = tss[i] if i < len(tss) else {}
        la = las[i] if i < len(las) else {}
        ia = ias[i] if i < len(ias) else {}
        rd = rds[i] if i < len(rds) else {}
        rr = rrs[i] if i < len(rrs) else {}
        cve = te.get("cve_id", "")

        chain.append({
            "ts_id": ts.get("id", ""), "ts_type": ts.get("type", ""),
            "ts_name": ts.get("name", ""), "ts_capability": ts.get("capability", ""),
            "te_id": te.get("id", ""), "te_desc": te.get("description", "")[:100],
            "te_cve": cve, "te_mitre": te.get("mitre_technique", ""),
            "te_target": te.get("target_component", ""),
            "te_relevance": te.get("relevance", ""),
            "l_init": la.get("initiation_likelihood", ""),
            "l_impact": la.get("impact_likelihood", ""),
            "l_overall": la.get("overall_likelihood", ""),
            "l_predisposing": la.get("predisposing_conditions", [])[:2],
            "l_evidence": (la.get("evidence", "") or "")[:60],
            "i_type": ia.get("impact_type", ""),
            "i_severity": ia.get("severity", ""),
            "i_cia": ia.get("cia_impact", {}),
            "i_compliance": ia.get("compliance_impact", [])[:3],
            "i_compliance_count": len(ia.get("compliance_impact", [])),
            "i_business": ia.get("business_impact", ""),
            "r_level": rd.get("risk_level", ""),
            "r_score": rd.get("risk_score", 0),
            "resp_type": rr.get("response_type", ""),
            "resp_desc": (rr.get("description", "") or "")[:80],
            "resp_milestones": rr.get("milestones", [])[:2],
            "supply_chain": sc_map.get(cve, False) if cve else False,
        })

    # MITRE / scanner counts
    mitre_counts = Counter(c["te_mitre"] for c in chain if c["te_mitre"])
    scanner_counts = Counter(i.get("source", "") for i in poam)
    sc_total = sum(1 for i in poam if i.get("weakness_detail", {}).get("supply_chain"))

    # Supply chain packages
    sc_packages = build_sc_packages(poam)

    # Gate info
    fc = raw.get("gate", {}).get("findings_count", {})

    return {
        "phase": phase_name,
        "meta": {
            "assessment_id": raw.get("assessment_id", ""),
            "product": raw.get("product", ""),
            "mode": raw.get("mode", ""),
            "created_at": raw.get("created_at", ""),
            "duration_seconds": raw.get("duration_seconds", 0),
            "commit": commit,
            "run_id": run_id,
        },
        "decision": {
            "authorization": raw.get("authorization", {}).get("decision", "UNKNOWN"),
            "risk_level": raw.get("authorization", {}).get("risk_level", "unknown"),
            "reasoning": raw.get("authorization", {}).get("reasoning", ""),
            "valid_until": raw.get("authorization", {}).get("valid_until", ""),
        },
        "findings": {
            "total": raw.get("findings_count", 0),
            "critical": fc.get("critical", 0), "high": fc.get("high", 0),
            "medium": fc.get("medium", 0), "low": fc.get("low", 0),
        },
        "thresholds": raw.get("gate", {}).get("threshold_results", []),
        "sar": {
            "total": raw.get("sar", {}).get("total_controls", 0),
            "satisfied": raw.get("sar", {}).get("satisfied", 0),
            "other": raw.get("sar", {}).get("other_than_satisfied", 0),
            "not_assessed": raw.get("sar", {}).get("not_assessed", 0),
            "assessments": raw.get("sar", {}).get("control_assessments", []),
        },
        "sp800_30": {
            "scope": sp.get("scope", ""),
            "methodology": sp.get("methodology", ""),
            "risk_model": sp.get("risk_model", ""),
            "executive_summary": sp.get("executive_summary", ""),
            "assumptions": sp.get("assumptions", []),
            "cia_impact": sp.get("cia_impact_levels", {}),
            "recommendations": sp.get("recommendations", []),
            "reassessment_triggers": sp.get("reassessment_triggers", []),
            "next_review_date": sp.get("next_review_date", ""),
        },
        "threat_sources": ts_all,
        "risk_chain": chain,
        "sc_packages": sc_packages,
        "sc_packages_total": len(sc_packages),
        "supply_chain_total": sc_total,
        "supply_chain_pct": round(sc_total / len(poam) * 100, 1) if poam else 0,
        "supply_chain_packages": len(sc_packages),
        "supply_chain_with_fix": sum(1 for p in sc_packages if p.get("fix")),
        "supply_chain_without_fix": sum(1 for p in sc_packages if not p.get("fix")),
        "mitre_techniques": dict(mitre_counts),
        "scanner_counts": dict(scanner_counts),
    }


# ── Main ──

def main():
    args = parse_args()
    short_sha = args.commit[:7] if len(args.commit) >= 7 else args.commit
    now = datetime.now(timezone.utc).isoformat()

    print(f"[INFO] Risk Dashboard Gen: commit={short_sha} run={args.run_id}")
    print(f"[INFO] Results dir: {args.results_dir}")

    # Discover phases
    phases = discover_phases(args.results_dir)
    if not phases:
        print("[ERROR] No phase results found")
        sys.exit(1)

    # Process each phase
    manifest_phases = []
    phase_data = {}
    primary_decision = "UNKNOWN"

    for phase_name, raw in phases:
        trimmed = trim_phase(raw, phase_name, args.commit, args.run_id)
        phase_data[phase_name] = trimmed
        manifest_phases.append({
            "phase": phase_name,
            "findings": trimmed["findings"]["total"],
            "decision": trimmed["decision"]["authorization"],
        })
        # Use RELEASE decision as primary, fallback to last phase
        if phase_name == "RELEASE":
            primary_decision = trimmed["decision"]["authorization"]
        print(f"  {phase_name}: {trimmed['findings']['total']} findings, "
              f"{trimmed['decision']['authorization']}, "
              f"{len(trimmed['risk_chain'])} risk chain, "
              f"{len(trimmed.get('sc_packages', []))} SC packages")

    if primary_decision == "UNKNOWN" and phase_data:
        last = list(phase_data.values())[-1]
        primary_decision = last["decision"]["authorization"]

    # Build manifest
    manifest = {
        "phases": manifest_phases,
        "generated_at": now,
        "commit": args.commit,
        "run_id": args.run_id,
    }

    # Build projects.json
    release = phase_data.get("RELEASE", list(phase_data.values())[-1])
    projects = {
        "projects": [{
            "id": release["meta"]["product"],
            "name": release["meta"]["product"].replace("-", " ").title(),
            "description": f"JCCompany {release['meta']['product']} — PCI-DSS Scoped",
            "latest_commit": short_sha,
            "latest_date": now,
            "decision": primary_decision,
            "risk_level": release["decision"]["risk_level"],
            "findings": release["findings"],
            "scanners": list(release.get("scanner_counts", {}).keys()),
            "phases": len(manifest_phases),
            "framework": "NIST SP 800-30 / SP 800-37 RMF",
        }],
    }

    # Write outputs: latest/ + {commit}/
    for dest_dir in [
        os.path.join(args.output_dir, "data", "latest"),
        os.path.join(args.output_dir, "data", short_sha),
    ]:
        os.makedirs(dest_dir, exist_ok=True)

        # Phase JSONs
        for phase_name, data in phase_data.items():
            path = os.path.join(dest_dir, f"{phase_name.lower()}.json")
            with open(path, "w") as f:
                json.dump(data, f, separators=(",", ":"), default=str)

        # Manifest
        with open(os.path.join(dest_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, separators=(",", ":"), default=str)

    # projects.json at data/ root + inside latest/ and commit/
    for pj_dir in [
        os.path.join(args.output_dir, "data"),
        os.path.join(args.output_dir, "data", "latest"),
        os.path.join(args.output_dir, "data", short_sha),
    ]:
        os.makedirs(pj_dir, exist_ok=True)
        with open(os.path.join(pj_dir, "projects.json"), "w") as f:
            json.dump(projects, f, separators=(",", ":"), default=str)

    # Summary
    total_size = 0
    file_count = 0
    for root, _, files in os.walk(os.path.join(args.output_dir, "data")):
        for fn in files:
            fp = os.path.join(root, fn)
            total_size += os.path.getsize(fp)
            file_count += 1

    print(f"\n[OK] Generated {file_count} files ({total_size // 1024}KB total)")
    print(f"[OK] Output: {args.output_dir}/data/latest/ + {args.output_dir}/data/{short_sha}/")
    print(f"[INFO] Risk Dashboard gen complete")


if __name__ == "__main__":
    main()
