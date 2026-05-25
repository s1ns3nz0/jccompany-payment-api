#!/usr/bin/env python3
"""
VEX (Vulnerability Exploitability eXchange) Triage Script
==========================================================
NIST SP 800-204D S5.3 / SSDF RV.2 / DoD DevSecOps Guidebook

Workflow:
  1. Load Grype scan results (JSON)
  2. Load existing VEX document (CycloneDX VEX format)
  3. Match CVEs → apply VEX status (not_affected, affected, under_investigation)
  4. Generate updated VEX document
  5. Produce triage summary for pipeline + Loki push

Usage:
  python vex-triage.py \
    --grype-results ./grype-sbom-results/results.json \
    --grype-image-results ./grype-image-results/results.json \
    --vex ./vex.json \
    --output ./vex-output \
    --loki-url https://loki.miata.cloud \
    --commit abc123 \
    --product payment-api
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def load_grype(path):
    """Load Grype JSON results."""
    if not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    vulns = []
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        a = m.get("artifact", {})
        fix_versions = v.get("fix", {}).get("versions", [])
        vulns.append({
            "id": v.get("id", ""),
            "severity": v.get("severity", "Unknown"),
            "package": a.get("name", ""),
            "version": a.get("version", ""),
            "type": a.get("type", ""),
            "fix_versions": fix_versions,
            "cvss": next(
                (c.get("metrics", {}).get("baseScore", 0)
                 for c in v.get("cvss", [])), 0
            ),
            "description": v.get("description", "")[:200],
            "source": os.path.basename(path),
        })
    return vulns


def load_vex(path):
    """Load existing CycloneDX VEX document."""
    if not os.path.exists(path):
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "vulnerabilities": []
        }
    with open(path) as f:
        return json.load(f)


def build_vex_lookup(vex_doc):
    """Build lookup: (vuln_id, package) → vex_entry."""
    lookup = {}
    for v in vex_doc.get("vulnerabilities", []):
        vid = v.get("id", "")
        for affect in v.get("affects", []):
            ref = affect.get("ref", "")
            lookup[(vid, ref)] = v
        if not v.get("affects"):
            lookup[(vid, "*")] = v
    return lookup


def triage_vulns(vulns, vex_lookup):
    """Apply VEX status to vulnerabilities."""
    triaged = []
    for v in vulns:
        key = (v["id"], v["package"])
        key_wildcard = (v["id"], "*")

        vex_entry = vex_lookup.get(key) or vex_lookup.get(key_wildcard)

        if vex_entry:
            analysis = vex_entry.get("analysis", {})
            v["vex_status"] = analysis.get("state", "in_triage")
            v["vex_justification"] = analysis.get("justification", "")
            v["vex_response"] = analysis.get("response", [])
            v["vex_detail"] = analysis.get("detail", "")
        else:
            # Auto-triage rules
            if v["severity"] == "Low" and v["cvss"] < 2.0:
                v["vex_status"] = "not_affected"
                v["vex_justification"] = "vulnerable_code_not_in_execute_path"
                v["vex_detail"] = "Auto-triaged: Low severity with CVSS < 2.0"
            elif v["fix_versions"]:
                v["vex_status"] = "affected"
                v["vex_justification"] = ""
                v["vex_detail"] = f"Fix available: {', '.join(v['fix_versions'][:3])}"
            else:
                v["vex_status"] = "in_triage"
                v["vex_justification"] = ""
                v["vex_detail"] = "Awaiting manual triage"

        triaged.append(v)
    return triaged


def generate_vex_document(triaged, product, commit):
    """Generate CycloneDX VEX document."""
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": product,
                "version": commit[:8]
            },
            "tools": [{
                "vendor": "JCCompany",
                "name": "vex-triage",
                "version": "1.0.0"
            }]
        },
        "vulnerabilities": []
    }

    # Dedup by vuln ID
    seen = {}
    for v in triaged:
        vid = v["id"]
        if vid not in seen:
            seen[vid] = {
                "id": vid,
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"},
                "ratings": [{
                    "score": v["cvss"],
                    "severity": v["severity"].lower(),
                    "method": "CVSSv31"
                }],
                "analysis": {
                    "state": v["vex_status"],
                    "justification": v["vex_justification"],
                    "response": v.get("vex_response", []),
                    "detail": v["vex_detail"]
                },
                "affects": []
            }
        seen[vid]["affects"].append({
            "ref": v["package"],
            "versions": [{"version": v["version"], "status": v["vex_status"]}]
        })

    vex["vulnerabilities"] = list(seen.values())
    return vex


def generate_summary(triaged):
    """Generate triage summary."""
    total = len(triaged)
    status_counts = Counter(v["vex_status"] for v in triaged)
    severity_counts = Counter(v["severity"] for v in triaged)

    # Dedup by vuln ID for unique count
    unique_vulns = {}
    for v in triaged:
        if v["id"] not in unique_vulns:
            unique_vulns[v["id"]] = v
    unique_status = Counter(v["vex_status"] for v in unique_vulns.values())

    return {
        "total_findings": total,
        "unique_vulnerabilities": len(unique_vulns),
        "by_status": dict(status_counts),
        "by_severity": dict(severity_counts),
        "unique_by_status": dict(unique_status),
        "not_affected_count": status_counts.get("not_affected", 0),
        "affected_count": status_counts.get("affected", 0),
        "in_triage_count": status_counts.get("in_triage", 0),
        "actionable": status_counts.get("affected", 0),
        "suppressed": status_counts.get("not_affected", 0),
    }


def push_to_loki(loki_url, summary, product, commit):
    """Push VEX triage summary to Loki."""
    if not loki_url:
        return
    payload = {
        "streams": [{
            "stream": {
                "job": "vex-triage",
                "product": product,
                "type": "summary"
            },
            "values": [[
                str(int(time.time())) + "000000000",
                json.dumps({
                    **summary,
                    "commit": commit,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            ]]
        }]
    }
    try:
        req = urllib.request.Request(
            f"{loki_url}/loki/api/v1/push",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        resp = urllib.request.urlopen(req)  # nosemgrep: dynamic-urllib-use-detected
        print(f"[OK] Loki push: VEX summary (HTTP {resp.getcode()})")
    except Exception as e:
        print(f"[WARN] Loki push failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="VEX Triage for DevSecOps Pipeline")
    parser.add_argument("--grype-results", required=True, help="Grype SBOM results JSON")
    parser.add_argument("--grype-image-results", default="", help="Grype Image results JSON")
    parser.add_argument("--vex", default="vex.json", help="Existing VEX document")
    parser.add_argument("--output", default="./vex-output", help="Output directory")
    parser.add_argument("--loki-url", default="", help="Loki push URL")
    parser.add_argument("--commit", default="unknown", help="Git commit SHA")
    parser.add_argument("--product", default="payment-api", help="Product name")
    args = parser.parse_args()

    print("=" * 60)
    print("VEX Triage — Vulnerability Exploitability eXchange")
    print("=" * 60)

    # 1. Load scan results
    vulns = load_grype(args.grype_results)
    print(f"[INFO] SBOM findings: {len(vulns)}")

    if args.grype_image_results:
        img_vulns = load_grype(args.grype_image_results)
        print(f"[INFO] Image findings: {len(img_vulns)}")
        vulns.extend(img_vulns)

    print(f"[INFO] Total findings: {len(vulns)}")

    # 2. Load existing VEX
    vex_doc = load_vex(args.vex)
    vex_lookup = build_vex_lookup(vex_doc)
    print(f"[INFO] Existing VEX entries: {len(vex_lookup)}")

    # 3. Triage
    triaged = triage_vulns(vulns, vex_lookup)

    # 4. Generate outputs
    os.makedirs(args.output, exist_ok=True)

    # VEX document
    vex_out = generate_vex_document(triaged, args.product, args.commit)
    vex_path = os.path.join(args.output, "vex.json")
    with open(vex_path, "w") as f:
        json.dump(vex_out, f, indent=2)
    print(f"[OK] VEX document: {vex_path} ({len(vex_out['vulnerabilities'])} entries)")

    # Summary
    summary = generate_summary(triaged)
    summary_path = os.path.join(args.output, "vex-summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Triaged details
    details_path = os.path.join(args.output, "vex-details.json")
    with open(details_path, "w") as f:
        json.dump(triaged, f, indent=2)

    # 5. Print summary
    print()
    print(f"  Total findings:    {summary['total_findings']}")
    print(f"  Unique CVEs:       {summary['unique_vulnerabilities']}")
    print(f"  ✅ not_affected:   {summary['not_affected_count']}")
    print(f"  ⚠️  affected:      {summary['affected_count']}")
    print(f"  🔍 in_triage:      {summary['in_triage_count']}")
    print(f"  Actionable:        {summary['actionable']}")
    print(f"  Suppressed:        {summary['suppressed']}")
    print()

    # 6. Loki push
    if args.loki_url:
        push_to_loki(args.loki_url, summary, args.product, args.commit)

    print("[INFO] VEX triage complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
