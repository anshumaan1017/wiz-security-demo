#!/usr/bin/env python3
"""
Analyzes wizcli image scan JSON output to produce a comprehensive
findings breakdown — designed to compare against Prisma Cloud's output.

Reads:    image-layers.json (from `wizcli docker scan --output ...,json,vulnerabilities`)
Writes:   findings_analysis.json + console table

This script is read-only on the input JSON. It produces analysis only.
"""
import json
import os
import sys
from collections import Counter, defaultdict


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]
EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🟢", "INFORMATIONAL": "⚪", "UNKNOWN": "⚫",
}


def safe_get(d, *keys, default=None):
    """Safely traverse nested dicts."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


def has_fix(vuln):
    """Check if vulnerability has a fix version."""
    fv = vuln.get("fixedVersion") or vuln.get("FixedVersion") or ""
    if not fv:
        return False
    fv = str(fv).strip().lower()
    if fv in ("", "n/a", "no fix", "none", "null"):
        return False
    return True


def get_exploit_signal(vuln):
    """Extract any exploit-related metadata Wiz might provide."""
    signals = {}
    # Check various possible field names for exploit data
    for field in ["hasExploit", "exploitable", "exploitability"]:
        val = vuln.get(field)
        if val is not None:
            signals[field] = val

    # CISA KEV
    for field in ["cisaKev", "cisaKnownExploited", "isKev", "knownExploited"]:
        val = vuln.get(field)
        if val:
            signals["cisaKev"] = bool(val)

    # EPSS score
    for field in ["epss", "epssScore", "epss_score"]:
        val = vuln.get(field)
        if val is not None:
            signals["epss"] = val

    # Exploit maturity
    for field in ["exploitMaturity", "exploit_maturity"]:
        val = vuln.get(field)
        if val:
            signals["exploitMaturity"] = val

    return signals


def main():
    json_path = sys.argv[1] if len(sys.argv) > 1 else "image-layers.json"

    if not os.path.exists(json_path):
        print(f"❌ {json_path} not found")
        sys.exit(1)

    with open(json_path) as f:
        data = json.load(f)

    print("=" * 80)
    print(f"FINDINGS BREAKDOWN ANALYSIS: {json_path}")
    print("=" * 80)

    # ============================================================
    # 1. Top-level structure
    # ============================================================
    print("\n📋 TOP-LEVEL STRUCTURE")
    print(f"  Top keys: {list(data.keys())}")

    # Look for policy / status info
    for key in ["status", "passed", "policyResults", "policies"]:
        if key in data:
            print(f"  {key}: {data[key]}")

    result = data.get("result") or data.get("Result") or {}
    print(f"  result keys: {list(result.keys())}")

    # ============================================================
    # 2. Collect all findings
    # ============================================================
    all_findings = []
    by_source = defaultdict(int)

    for source_key in ["osPackages", "libraries", "applications", "secrets"]:
        items = result.get(source_key, []) or []
        for pkg in items:
            vulns = pkg.get("vulnerabilities", []) or []
            for v in vulns:
                all_findings.append({
                    "source": source_key,
                    "package_name": pkg.get("name", "N/A"),
                    "package_version": pkg.get("version", "N/A"),
                    "package_type": pkg.get("type", "N/A"),
                    "vuln": v,
                    "layer_id": safe_get(pkg, "layerMetadata", "id") or "unknown",
                })
                by_source[source_key] += 1

    total = len(all_findings)
    print(f"\n📊 TOTAL FINDINGS: {total}")
    print(f"  By source:")
    for source, count in sorted(by_source.items(), key=lambda x: -x[1]):
        pct = (count / total * 100) if total else 0
        print(f"    {source:20s} {count:6d}  ({pct:5.1f}%)")

    # ============================================================
    # 3. Severity breakdown
    # ============================================================
    print("\n🎯 BY SEVERITY")
    severity_counts = Counter()
    severity_with_fix = Counter()
    severity_no_fix = Counter()

    for f in all_findings:
        sev = (f["vuln"].get("severity") or "UNKNOWN").upper()
        severity_counts[sev] += 1
        if has_fix(f["vuln"]):
            severity_with_fix[sev] += 1
        else:
            severity_no_fix[sev] += 1

    print(f"  {'Severity':<15} {'Total':>8} {'With Fix':>10} {'No Fix':>10} {'% No Fix':>10}")
    for sev in SEVERITY_ORDER:
        if severity_counts.get(sev, 0) == 0:
            continue
        total_s = severity_counts[sev]
        wf = severity_with_fix.get(sev, 0)
        nf = severity_no_fix.get(sev, 0)
        pct_nf = (nf / total_s * 100) if total_s else 0
        print(f"  {EMOJI[sev]} {sev:<12} {total_s:>8} {wf:>10} {nf:>10} {pct_nf:>9.1f}%")

    print(f"  {'-' * 60}")
    total_with_fix = sum(severity_with_fix.values())
    total_no_fix = sum(severity_no_fix.values())
    print(f"  {'TOTAL':<15} {total:>8} {total_with_fix:>10} {total_no_fix:>10}")
    if total:
        print(f"  → {total_no_fix} findings ({total_no_fix/total*100:.1f}%) have NO FIX available")
        print(f"  → {total_with_fix} findings ({total_with_fix/total*100:.1f}%) HAVE FIX available")

    # ============================================================
    # 4. CVE deduplication analysis
    # ============================================================
    print("\n🔁 CVE DUPLICATION (same CVE across multiple packages)")
    cve_counts = Counter()
    for f in all_findings:
        cve = f["vuln"].get("name") or f["vuln"].get("id") or "UNKNOWN"
        cve_counts[cve] += 1

    unique_cves = len(cve_counts)
    duplicates = total - unique_cves
    print(f"  Unique CVEs:           {unique_cves}")
    print(f"  Total finding entries: {total}")
    print(f"  Duplicate entries:     {duplicates} ({duplicates/total*100:.1f}% redundancy)")

    print(f"\n  Top 10 most-duplicated CVEs (across packages):")
    for cve, count in cve_counts.most_common(10):
        if count > 1:
            print(f"    {count:4d}x  {cve}")

    # ============================================================
    # 5. Exploit data analysis
    # ============================================================
    print("\n💣 EXPLOIT METADATA (what fields does Wiz provide?)")
    exploit_field_counts = Counter()
    sample_with_exploit = []

    for f in all_findings:
        signals = get_exploit_signal(f["vuln"])
        for field in signals:
            exploit_field_counts[field] += 1
        if signals and len(sample_with_exploit) < 3:
            sample_with_exploit.append({
                "cve": f["vuln"].get("name", "N/A"),
                "signals": signals,
            })

    if exploit_field_counts:
        print(f"  Exploit-related fields found:")
        for field, count in exploit_field_counts.most_common():
            print(f"    {field:30s} present on {count} findings")
        print(f"\n  Sample findings with exploit data:")
        for s in sample_with_exploit:
            print(f"    {s['cve']}: {s['signals']}")
    else:
        print(f"  ⚠️  NO exploit-related fields detected in any finding.")
        print(f"     Wiz CLI JSON output may not include KEV/EPSS data by default.")

    # ============================================================
    # 6. Sample finding structure (so we can see all fields)
    # ============================================================
    print("\n🔍 SAMPLE FINDING STRUCTURE (first finding's full vuln object)")
    if all_findings:
        first = all_findings[0]
        print(f"  Source: {first['source']}, Package: {first['package_name']}")
        print(f"  Vuln fields:")
        for k, v in first["vuln"].items():
            v_str = str(v)
            if len(v_str) > 80:
                v_str = v_str[:80] + "..."
            print(f"    {k}: {v_str}")

    # ============================================================
    # 7. Filter scenarios (preview what filters would do)
    # ============================================================
    print("\n🧪 FILTER SCENARIOS PREVIEW")

    def count_with_filter(filter_fn):
        return sum(1 for f in all_findings if filter_fn(f))

    scenarios = {
        "0. Original (no filter)":
            lambda f: True,
        "A. Has fix only":
            lambda f: has_fix(f["vuln"]),
        "B. Severity ≥ HIGH":
            lambda f: (f["vuln"].get("severity") or "").upper() in ("CRITICAL", "HIGH"),
        "C. Has fix + Severity ≥ MEDIUM":
            lambda f: has_fix(f["vuln"]) and (f["vuln"].get("severity") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM"),
        "D. Has fix + Severity ≥ HIGH":
            lambda f: has_fix(f["vuln"]) and (f["vuln"].get("severity") or "").upper() in ("CRITICAL", "HIGH"),
        "E. Has fix + Library/App only":
            lambda f: has_fix(f["vuln"]) and f["source"] in ("libraries", "applications"),
        "F. Aggressive (Prisma-like): Has fix + Sev≥MEDIUM + Lib/App":
            lambda f: has_fix(f["vuln"])
                      and (f["vuln"].get("severity") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM")
                      and f["source"] in ("libraries", "applications"),
    }

    print(f"  {'Scenario':<60} {'Findings':>10} {'Reduction':>10}")
    print(f"  {'-' * 82}")
    for name, fn in scenarios.items():
        c = count_with_filter(fn)
        reduction = ((total - c) / total * 100) if total else 0
        marker = "  " if name.startswith("0.") else ""
        print(f"  {marker}{name:<58} {c:>10} {reduction:>9.1f}%")

    # ============================================================
    # 8. Save analysis to JSON for tracking
    # ============================================================
    analysis = {
        "input_file": json_path,
        "total_findings": total,
        "by_source": dict(by_source),
        "by_severity": dict(severity_counts),
        "with_fix": total_with_fix,
        "no_fix": total_no_fix,
        "unique_cves": unique_cves,
        "duplicate_entries": duplicates,
        "exploit_fields_detected": dict(exploit_field_counts),
        "filter_scenarios": {
            name: count_with_filter(fn) for name, fn in scenarios.items()
        },
    }

    with open("findings_analysis.json", "w") as f:
        json.dump(analysis, f, indent=2)

    print(f"\n💾 Analysis saved to: findings_analysis.json")
    print("=" * 80)


if __name__ == "__main__":
    main()
