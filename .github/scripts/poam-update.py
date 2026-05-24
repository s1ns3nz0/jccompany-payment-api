#!/usr/bin/env python3
"""
POA&M Registry Automatic Update Script
=======================================
NIST Controls: CA-5 (POA&M), CA-7 (Continuous Monitoring), PM-4 (POA&M Process)
Frameworks: DoD DevSecOps Guidebook v2.5, SSDF SP 800-218 RV.1.3, SP 800-204D

Workflow:
  1. Download current.json from S3 (existing registry)
  2. Collect findings from Risk Platform responses (RELEASE + DELIVER/DEPLOY)
  3. Match by fingerprint: NEW -> OPEN, still present -> update last_seen, gone -> CLOSED
  4. Compute SLA / overdue status
  5. Upload updated current.json + history snapshot to S3
  6. Push summary + open findings to Loki

Usage (in GitHub Actions):
  python poam-update.py \
    --results-dir ./risk-results \
    --s3-bucket jccompany-devsecops-evidence-106760547719 \
    --loki-url https://loki.miata.cloud \
    --commit abc1234 \
    --run-id 26320017044
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


# --- SLA Configuration (NIST RA-5, PCI-DSS 6.3.3, DoD cATO) ---
SLA_DAYS = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180,
}


def parse_args():
    p = argparse.ArgumentParser(description="POA&M Registry Update")
    p.add_argument("--results-dir", required=True, help="Directory with risk result JSONs")
    p.add_argument("--s3-bucket", required=True, help="S3 evidence bucket name")
    p.add_argument("--loki-url", default="", help="Loki push URL (skip if empty)")
    p.add_argument("--commit", default="unknown", help="Git commit SHA")
    p.add_argument("--run-id", default="0", help="GitHub Actions run ID")
    p.add_argument("--dry-run", action="store_true", help="Print results without uploading")
    return p.parse_args()


def load_json_safe(path):
    """Load JSON file, return None on error."""
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
        print(f"[WARN] Cannot load {path}: {e}")
        return None


def download_current_from_s3(bucket):
    """Download existing POA&M registry from S3. Returns empty registry if not found."""
    local_path = "/tmp/poam-current.json"
    s3_key = f"s3://{bucket}/poam/current.json"
    try:
        result = subprocess.run(
            ["aws", "s3", "cp", s3_key, local_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            data = load_json_safe(local_path)
            if data and "items" in data:
                print(f"[INFO] Loaded existing registry: {len(data['items'])} items")
                return data
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    print("[INFO] No existing registry found, starting fresh")
    return {
        "version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": None,
        "items": [],
        "history": {
            "total_runs": 0,
            "total_ever_opened": 0,
            "total_ever_closed": 0,
        },
    }


def core_fingerprint(fp):
    """
    Extract scanner|finding_id|package|version from fingerprint,
    stripping the path component to avoid duplicates across phases.
    e.g. 'grype|CVE-2024-12798|logback-core|1.4.14|/app/app.jar'
      -> 'grype|CVE-2024-12798|logback-core|1.4.14'
    """
    parts = fp.split("|")
    # Keep first 4 parts: scanner|finding_id|package|version
    return "|".join(parts[:4])


def collect_findings(results_dir):
    """
    Collect POA&M items from Risk Platform responses.
    Priority: RELEASE (superset) + DELIVER/DEPLOY (new findings only).
    Only processes responses with valid poam.items (skip errors/empty).
    Deduplicates by core fingerprint (scanner|id|package|version).
    """
    results_dir = Path(results_dir)
    all_findings = {}  # full fingerprint -> item
    seen_core = set()  # core fingerprints for dedup

    # Phase priority order: RELEASE first (superset), then others for new-only
    phase_files = [
        ("RELEASE", "risk-release-result.json"),
        ("DELIVER", "risk-deliver-response.json"),
        ("DEPLOY", "risk-deploy-response.json"),
        ("BUILD", "risk-build-result.json"),
        ("TEST", "risk-test-result.json"),
        ("DEVELOP", "risk-develop-result.json"),
    ]

    phases_loaded = []

    for phase_name, filename in phase_files:
        # Search recursively for the file
        matches = list(results_dir.rglob(filename))
        if not matches:
            print(f"[INFO] {phase_name}: file not found, skipping")
            continue

        data = load_json_safe(matches[0])
        if not data:
            print(f"[WARN] {phase_name}: failed to parse, skipping")
            continue

        # Skip error responses (422, etc.)
        if "detail" in data:
            print(f"[WARN] {phase_name}: error response, skipping")
            continue

        # Must have poam.items
        poam = data.get("poam", {})
        items = poam.get("items", [])
        if not items:
            print(f"[INFO] {phase_name}: no POA&M items")
            continue

        new_count = 0
        for item in items:
            fp = item.get("fingerprint", "")
            if not fp:
                continue
            cfp = core_fingerprint(fp)
            if cfp not in seen_core:
                seen_core.add(cfp)
                all_findings[fp] = item
                new_count += 1

        phases_loaded.append(phase_name)
        print(f"[INFO] {phase_name}: {len(items)} items, {new_count} new (total: {len(all_findings)})")

    return all_findings, phases_loaded


def match_and_update(existing_registry, new_findings, now, commit, run_id):
    """
    Match new findings against existing registry by core fingerprint.
    - New finding (not in existing) -> OPEN with SLA
    - Existing OPEN + still present -> update last_seen
    - Existing OPEN + not present in valid scan -> CLOSED
    - Existing CLOSED/RISK_ACCEPTED -> preserve (history)
    """
    existing_by_cfp = {}
    for item in existing_registry.get("items", []):
        fp = item.get("fingerprint", "")
        if fp:
            existing_by_cfp[core_fingerprint(fp)] = item

    # Build core fingerprint map for new findings
    new_by_cfp = {}
    for fp, item in new_findings.items():
        new_by_cfp[core_fingerprint(fp)] = item

    updated_items = []
    stats = {"new": 0, "persisted": 0, "closed": 0, "already_closed": 0}

    # 1. Process all new findings
    for cfp, new_item in new_by_cfp.items():
        if cfp in existing_by_cfp:
            # Existing item - update last_seen
            existing = existing_by_cfp.pop(cfp)

            if existing.get("status") in ("closed", "CLOSED"):
                # Was closed but reappeared -> reopen
                existing["status"] = "open"
                existing["lifecycle"]["closed_at"] = None
                stats["new"] += 1
            else:
                stats["persisted"] += 1

            # Update tracking fields
            existing.setdefault("lifecycle", {})
            existing["lifecycle"]["last_seen"] = now.isoformat()
            existing["lifecycle"]["last_seen_run"] = run_id
            existing["lifecycle"]["last_seen_commit"] = commit

            # Recompute days_open and overdue
            discovered = existing["lifecycle"].get("discovered_at", now.isoformat())
            try:
                disc_dt = datetime.fromisoformat(discovered)
                existing["lifecycle"]["days_open"] = (now - disc_dt).days
            except (ValueError, TypeError):
                existing["lifecycle"]["days_open"] = 0

            due = existing["lifecycle"].get("due_date", "")
            if due:
                try:
                    due_dt = datetime.fromisoformat(due) if "T" in due else datetime.strptime(due, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    existing["lifecycle"]["is_overdue"] = now > due_dt
                except (ValueError, TypeError):
                    existing["lifecycle"]["is_overdue"] = False

            updated_items.append(existing)
        else:
            # New finding - create POA&M entry
            severity = new_item.get("severity", "medium").lower()
            sla = SLA_DAYS.get(severity, 180)
            due_date = (now + timedelta(days=sla)).strftime("%Y-%m-%d")

            # Enrich lifecycle
            new_item.setdefault("lifecycle", {})
            new_item["lifecycle"]["discovered_at"] = now.isoformat()
            new_item["lifecycle"]["discovered_run"] = run_id
            new_item["lifecycle"]["discovered_commit"] = commit
            new_item["lifecycle"]["due_date"] = due_date
            new_item["lifecycle"]["sla_days"] = sla
            new_item["lifecycle"]["last_seen"] = now.isoformat()
            new_item["lifecycle"]["last_seen_run"] = run_id
            new_item["lifecycle"]["last_seen_commit"] = commit
            new_item["lifecycle"]["closed_at"] = None
            new_item["lifecycle"]["days_open"] = 0
            new_item["lifecycle"]["is_overdue"] = False

            new_item["status"] = "open"
            updated_items.append(new_item)
            stats["new"] += 1

    # 2. Remaining existing items not in new findings -> CLOSED
    for cfp, existing in existing_by_cfp.items():
        if existing.get("status") in ("closed", "CLOSED"):
            stats["already_closed"] += 1
            updated_items.append(existing)
        elif existing.get("status") in ("risk_accepted", "RISK_ACCEPTED"):
            # Preserve risk-accepted items as-is
            updated_items.append(existing)
        else:
            # OPEN but not found in new scan -> CLOSED
            existing["status"] = "closed"
            existing.setdefault("lifecycle", {})
            existing["lifecycle"]["closed_at"] = now.isoformat()
            existing["lifecycle"]["closed_run"] = run_id
            existing["lifecycle"]["closed_commit"] = commit

            # Compute final days_open
            discovered = existing["lifecycle"].get("discovered_at", now.isoformat())
            try:
                disc_dt = datetime.fromisoformat(discovered)
                existing["lifecycle"]["days_open"] = (now - disc_dt).days
            except (ValueError, TypeError):
                pass

            existing["lifecycle"]["is_overdue"] = False
            updated_items.append(existing)
            stats["closed"] += 1

    return updated_items, stats


def build_registry(items, existing_registry, now, commit, run_id, stats):
    """Build the updated registry document."""
    history = existing_registry.get("history", {})
    total_runs = history.get("total_runs", 0) + 1
    total_opened = history.get("total_ever_opened", 0) + stats["new"]
    total_closed = history.get("total_ever_closed", 0) + stats["closed"]

    return {
        "version": "1.0",
        "created_at": existing_registry.get("created_at", now.isoformat()),
        "updated_at": now.isoformat(),
        "commit": commit,
        "run_id": run_id,
        "items": items,
        "summary": build_summary(items, stats),
        "history": {
            "total_runs": total_runs,
            "total_ever_opened": total_opened,
            "total_ever_closed": total_closed,
        },
    }


def build_summary(items, stats):
    """Compute summary statistics for Loki push and dashboard."""
    open_items = [i for i in items if i.get("status") in ("open", "OPEN")]
    closed_items = [i for i in items if i.get("status") in ("closed", "CLOSED")]
    overdue_items = [i for i in open_items if i.get("lifecycle", {}).get("is_overdue")]

    # Severity breakdown (open only)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for item in open_items:
        sev = item.get("severity", "unknown").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["unknown"] += 1

    # Average days open (open items)
    days_list = [i.get("lifecycle", {}).get("days_open", 0) for i in open_items]
    avg_days = round(sum(days_list) / len(days_list), 1) if days_list else 0

    # SLA compliance (open items that are NOT overdue)
    sla_compliant = len(open_items) - len(overdue_items)
    sla_pct = round(sla_compliant / len(open_items) * 100, 1) if open_items else 100.0

    return {
        "total_open": len(open_items),
        "total_closed": len(closed_items),
        "overdue": len(overdue_items),
        "new_this_run": stats["new"],
        "closed_this_run": stats["closed"],
        "critical_open": sev_counts["critical"],
        "high_open": sev_counts["high"],
        "medium_open": sev_counts["medium"],
        "low_open": sev_counts["low"],
        "avg_days_open": avg_days,
        "sla_compliance_pct": sla_pct,
    }


def upload_to_s3(registry, bucket, commit, now, dry_run=False):
    """Upload current.json + history snapshot to S3."""
    current_path = "/tmp/poam-current-out.json"
    with open(current_path, "w") as f:
        json.dump(registry, f, indent=2, default=str)

    date_str = now.strftime("%Y-%m-%d")
    short_sha = commit[:7]

    uploads = [
        (current_path, f"s3://{bucket}/poam/current.json"),
        (current_path, f"s3://{bucket}/poam/history/{date_str}-{short_sha}.json"),
    ]

    for local, s3_path in uploads:
        if dry_run:
            print(f"[DRY-RUN] Would upload {local} -> {s3_path}")
        else:
            result = subprocess.run(
                ["aws", "s3", "cp", local, s3_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                print(f"[OK] Uploaded -> {s3_path}")
            else:
                print(f"[ERROR] S3 upload failed: {result.stderr.strip()}")

    return current_path


def push_to_loki(registry, loki_url, commit, run_id, dry_run=False):
    """Push summary + open findings to Loki."""
    if not loki_url:
        print("[INFO] Loki URL not set, skipping push")
        return

    push_url = f"{loki_url}/loki/api/v1/push"
    now_ns = str(int(datetime.now(timezone.utc).timestamp() * 1e9))

    streams = []

    # Stream 1: Summary
    summary = registry["summary"]
    summary_line = json.dumps({
        **summary,
        "commit": commit,
        "run_id": run_id,
    }, default=str)

    streams.append({
        "stream": {"job": "poam-registry", "type": "summary"},
        "values": [[now_ns, summary_line]],
    })

    # Stream 2: Individual OPEN findings
    open_items = [i for i in registry["items"] if i.get("status") in ("open", "OPEN")]
    for item in open_items:
        lc = item.get("lifecycle", {})
        sla_days = lc.get("sla_days", 90)
        days_open = lc.get("days_open", 0)
        sla_pct = round(days_open / sla_days * 100, 1) if sla_days > 0 else 0
        ticket = item.get("ticket", {})
        ra = item.get("risk_acceptance", {})
        delay = item.get("delay", {})

        finding_line = json.dumps({
            "poam_id": item.get("id", ""),
            "finding_id": item.get("finding_id", ""),
            "scanner": item.get("source", ""),
            "severity": item.get("severity", ""),
            "status": item.get("status", ""),
            "weakness": item.get("weakness", "")[:120],
            "package": item.get("weakness_detail", {}).get("package", ""),
            "cvss_score": item.get("weakness_detail", {}).get("cvss_score", 0),
            "supply_chain": item.get("weakness_detail", {}).get("supply_chain", False),
            "days_open": days_open,
            "sla_days": sla_days,
            "sla_pct": sla_pct,
            "due_date": lc.get("due_date", ""),
            "is_overdue": lc.get("is_overdue", False),
            "ticket_id": ticket.get("id", ""),
            "ticket_url": ticket.get("url", ""),
            "risk_accepted": bool(ra.get("accepted_by")),
            "accepted_by": ra.get("accepted_by", ""),
            "compensating_controls": ra.get("compensating_controls", ""),
            "delay_justification": delay.get("justification", ""),
            "remediation_plan": item.get("remediation", {}).get("plan", "")[:100],
            "vendor_dependency": item.get("remediation", {}).get("vendor_dependency", ""),
            "fingerprint": item.get("fingerprint", ""),
        }, default=str)

        sev = item.get("severity", "unknown").lower()
        streams.append({
            "stream": {
                "job": "poam-registry",
                "type": "finding",
                "severity": sev,
                "scanner": item.get("source", "unknown"),
            },
            "values": [[now_ns, finding_line]],
        })

    payload = json.dumps({"streams": streams}, default=str)

    if dry_run:
        print(f"[DRY-RUN] Would push {len(streams)} streams to Loki")
        return

    payload_path = "/tmp/poam-loki-payload.json"
    with open(payload_path, "w") as f:
        f.write(payload)

    result = subprocess.run(
        ["curl", "-s", "-w", "%{http_code}", "-o", "/dev/null",
         "-X", "POST", push_url,
         "-H", "Content-Type: application/json",
         "-d", f"@{payload_path}"],
        capture_output=True, text=True, timeout=30,
    )
    http_code = result.stdout.strip()
    if http_code in ("200", "204"):
        print(f"[OK] Loki push: {len(streams)} streams (HTTP {http_code})")
    else:
        print(f"[ERROR] Loki push failed: HTTP {http_code}")


def print_report(registry, stats):
    """Print human-readable POA&M report."""
    s = registry["summary"]
    print("\n" + "=" * 60)
    print("  POA&M Registry Update Report")
    print("=" * 60)
    print(f"  Open:     {s['total_open']}  (C={s['critical_open']} H={s['high_open']} M={s['medium_open']} L={s['low_open']})")
    print(f"  Closed:   {s['total_closed']}")
    print(f"  Overdue:  {s['overdue']}")
    print(f"  SLA:      {s['sla_compliance_pct']}%")
    print(f"  Avg days: {s['avg_days_open']}")
    print(f"  This run: +{stats['new']} new, -{stats['closed']} closed, {stats['persisted']} persisted")
    print("=" * 60)

    # Print overdue items
    open_items = [i for i in registry["items"] if i.get("status") in ("open", "OPEN")]
    overdue = [i for i in open_items if i.get("lifecycle", {}).get("is_overdue")]
    if overdue:
        print("\n  OVERDUE ITEMS:")
        for item in sorted(overdue, key=lambda x: x.get("severity", ""), reverse=True):
            print(f"    [{item.get('severity','?').upper()}] {item.get('finding_id','')} "
                  f"({item.get('source','')}) - {item.get('lifecycle',{}).get('days_open',0)}d overdue")
    print()


def main():
    args = parse_args()
    now = datetime.now(timezone.utc)

    print(f"[INFO] POA&M Update: commit={args.commit[:7]} run={args.run_id}")
    print(f"[INFO] Results dir: {args.results_dir}")

    # 1. Download existing registry
    existing = download_current_from_s3(args.s3_bucket)

    # 2. Collect findings from Risk Platform responses
    new_findings, phases = collect_findings(args.results_dir)
    if not new_findings:
        print("[WARN] No findings collected from any phase. Skipping update.")
        print("[WARN] This may indicate Risk Platform errors. Existing registry preserved.")
        sys.exit(0)

    print(f"[INFO] Phases loaded: {', '.join(phases)}")
    print(f"[INFO] Total unique findings: {len(new_findings)}")

    # 3. Match and update
    updated_items, stats = match_and_update(existing, new_findings, now, args.commit, args.run_id)

    # 4. Build registry
    registry = build_registry(updated_items, existing, now, args.commit, args.run_id, stats)

    # 5. Print report
    print_report(registry, stats)

    # 6. Upload to S3
    local_path = upload_to_s3(registry, args.s3_bucket, args.commit, now, args.dry_run)

    # 7. Push to Loki
    push_to_loki(registry, args.loki_url, args.commit, args.run_id, args.dry_run)

    # 8. Save local copy for artifact upload
    output_dir = Path(args.results_dir) / "poam-output"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "poam-current.json", "w") as f:
        json.dump(registry, f, indent=2, default=str)
    with open(output_dir / "poam-summary.json", "w") as f:
        json.dump(registry["summary"], f, indent=2)
    print(f"[INFO] Local output: {output_dir}")

    # Exit code based on overdue count
    overdue = registry["summary"]["overdue"]
    if overdue > 0:
        print(f"[WARN] {overdue} overdue items detected")
    print("[INFO] POA&M update complete")


if __name__ == "__main__":
    main()
