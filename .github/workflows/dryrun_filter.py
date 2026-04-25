#!/usr/bin/env python3
"""
DRY-RUN diagnostic for Wiz policy filter.

Reads image-layers.json and image.sarif, shows what filter_sarif_by_wiz_policy
would do — WITHOUT modifying any files. Pure read-only.

Use this to validate the filter logic against real data before deploying.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict


def parse_message_text(text):
    """Parse 'Key: value' lines from Wiz SARIF message text."""
    fields = {}
    if not text:
        return fields
    for line in text.split("\n"):
        m = re.match(r"^([A-Za-z ]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            fields.setdefault(key, val)
    return fields


def main():
    json_path = "image-layers.json"
    sarif_path = "image.sarif"

    if not os.path.exists(json_path):
        print(f"❌ {json_path} not found")
        sys.exit(1)
    if not os.path.exists(sarif_path):
        print(f"❌ {sarif_path} not found")
        sys.exit(1)

    with open(json_path) as f:
        json_data = json.load(f)
    with open(sarif_path) as f:
        sarif = json.load(f)

    print("=" * 80)
    print("WIZ POLICY FILTER — DRY RUN VALIDATION")
    print("=" * 80)

    # ============================================================
    # 1. Policy attribution from JSON
    # ============================================================
    print("\n📊 STEP 1: Wiz JSON policy attribution distribution")

    attribution = {}
    classification_counts = Counter()
    both_set = 0
    both_none = 0
    both_none_samples = []

    result = json_data.get("result") or {}
    total_in_json = 0

    for source_key in ["osPackages", "libraries", "applications"]:
        for pkg in result.get(source_key, []) or []:
            pkg_name = (pkg.get("name") or "").strip().lower()
            pkg_ver = (pkg.get("version") or "").strip()

            for vuln in pkg.get("vulnerabilities", []) or []:
                cve = (vuln.get("name") or "").strip()
                if not cve:
                    continue

                key = (cve, pkg_name, pkg_ver)
                total_in_json += 1

                failed = vuln.get("failedPolicyMatches")
                ignored = vuln.get("ignoredPolicyMatches")

                has_failed = bool(failed)
                has_ignored = bool(ignored)

                if has_failed and has_ignored:
                    both_set += 1
                    classification_counts["BOTH_SET"] += 1
                    attribution[key] = "failed"  # prioritize failed
                elif has_failed:
                    attribution[key] = "failed"
                    classification_counts["failed_only"] += 1
                elif has_ignored:
                    attribution[key] = "ignored"
                    classification_counts["ignored_only"] += 1
                else:
                    attribution[key] = "below_threshold"
                    classification_counts["both_none"] += 1
                    both_none += 1
                    if len(both_none_samples) < 5:
                        both_none_samples.append({
                            "cve": cve, "component": pkg_name,
                            "version": pkg_ver, "severity": vuln.get("severity")
                        })

    print(f"  Total findings in JSON: {total_in_json}")
    print(f"  Classifications:")
    for kind, count in classification_counts.most_common():
        pct = (count / total_in_json * 100) if total_in_json else 0
        print(f"    {kind:20s} {count:>6}  ({pct:5.1f}%)")

    if both_set:
        print(f"  ⚠️  {both_set} findings have BOTH failed AND ignored fields set (kept as failed)")
    if both_none:
        print(f"  ℹ️   {both_none} findings have NEITHER field set (would be dropped)")
        print(f"     Sample 'both none' findings:")
        for s in both_none_samples:
            print(f"       {s['cve']} | {s['component']} {s['version']} | {s['severity']}")

    # ============================================================
    # 2. SARIF results & matching
    # ============================================================
    print("\n🔗 STEP 2: SARIF-to-JSON match rate")

    sarif_results = sarif.get("runs", [{}])[0].get("results", []) or []
    total_in_sarif = len(sarif_results)
    print(f"  Total results in SARIF: {total_in_sarif}")

    # Try to match every SARIF result to JSON
    matched = 0
    unmatched_samples = []
    by_classification = Counter()
    sarif_classification_breakdown = defaultdict(list)

    for r in sarif_results:
        cve = (r.get("ruleId") or "").strip()
        msg_text = (r.get("message") or {}).get("text", "") or ""
        fields = parse_message_text(msg_text)
        comp_name = (fields.get("component") or "").strip().lower()
        comp_ver = (fields.get("version") or "").strip()

        key = (cve, comp_name, comp_ver)
        attr = attribution.get(key)

        if attr is not None:
            matched += 1
            by_classification[attr] += 1
            if len(sarif_classification_breakdown[attr]) < 3:
                sarif_classification_breakdown[attr].append({
                    "cve": cve, "component": comp_name, "version": comp_ver,
                    "level": r.get("level")
                })
        else:
            if len(unmatched_samples) < 5:
                unmatched_samples.append({
                    "cve": cve, "component": comp_name,
                    "version": comp_ver, "level": r.get("level"),
                    "msg_first_line": msg_text.split("\n")[0][:60]
                })

    unmatched = total_in_sarif - matched
    print(f"  Matched to JSON:    {matched:>6} ({matched/total_in_sarif*100:.1f}%)")
    print(f"  UNMATCHED:          {unmatched:>6} ({unmatched/total_in_sarif*100:.1f}%)")

    if unmatched_samples:
        print(f"\n  ⚠️  Sample unmatched SARIF results (would be dropped under new logic):")
        for s in unmatched_samples:
            print(f"     ruleId={s['cve']} | comp={s['component']!r} | ver={s['version']!r}")
            print(f"       level={s['level']} | msg='{s['msg_first_line']}'")

    # ============================================================
    # 3. What would the filter do?
    # ============================================================
    print("\n🎯 STEP 3: Filter outcome (DRY RUN — no files modified)")
    failed_count = by_classification.get("failed", 0)
    ignored_count = by_classification.get("ignored", 0)
    bt_count = by_classification.get("below_threshold", 0)

    print(f"  SARIF results that would be:")
    print(f"    KEPT (failed):           {failed_count:>5}")
    print(f"    DROPPED (ignored):       {ignored_count:>5}")
    print(f"    DROPPED (below_thresh):  {bt_count:>5}")
    print(f"    DROPPED (unmatched):     {unmatched:>5}")
    print(f"  ----------------------------------")
    print(f"  Final SARIF size:          {failed_count:>5} results")

    print(f"\n  Wiz console shows: 169 Failed (this is what we should match)")
    if failed_count == 169:
        print(f"  ✅ MATCH — filter would produce exactly 169 Open alerts in GitHub")
    else:
        print(f"  ⚠️  MISMATCH — filter would produce {failed_count} alerts, not 169")
        print(f"     Possible reasons:")
        print(f"       1. cap_results(max=1000) is truncating before filter runs")
        print(f"       2. Some failed findings have parsing issues in SARIF")
        print(f"       3. SARIF has duplicates not in JSON")

    # ============================================================
    # 4. Sample failed findings (so we know they look right)
    # ============================================================
    if "failed" in sarif_classification_breakdown:
        print(f"\n📋 SAMPLE 'FAILED' FINDINGS (would be kept as Open):")
        for s in sarif_classification_breakdown["failed"]:
            print(f"     {s['cve']} | {s['component']} {s['version']} | level={s['level']}")

    if "ignored" in sarif_classification_breakdown:
        print(f"\n📋 SAMPLE 'IGNORED' FINDINGS (would be dropped):")
        for s in sarif_classification_breakdown["ignored"]:
            print(f"     {s['cve']} | {s['component']} {s['version']} | level={s['level']}")

    # ============================================================
    # 5. Save full diagnostic to JSON
    # ============================================================
    diagnostic = {
        "json_total": total_in_json,
        "sarif_total": total_in_sarif,
        "json_classifications": dict(classification_counts),
        "sarif_match_breakdown": dict(by_classification),
        "sarif_unmatched": unmatched,
        "would_keep": failed_count,
        "would_drop": ignored_count + bt_count + unmatched,
        "expected_match": 169,
        "match_correct": failed_count == 169,
        "unmatched_samples": unmatched_samples,
        "both_none_samples": both_none_samples,
    }

    with open("filter_dryrun.json", "w") as f:
        json.dump(diagnostic, f, indent=2)

    print(f"\n💾 Full diagnostic saved to: filter_dryrun.json")
    print("=" * 80)


if __name__ == "__main__":
    main()
