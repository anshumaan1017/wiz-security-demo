#!/usr/bin/env python3
"""
Diagnostic script to dump the structure of image.sarif so we can see
exactly what GitHub Code Scanning is rejecting.

Run this AFTER wizsarif.py has already processed image.sarif.
It only reads the file — does not modify anything.
"""
import json
import os
import sys
from collections import Counter


def dump_sarif_diagnostics(path="image.sarif"):
    if not os.path.exists(path):
        print(f"❌ {path} not found")
        return

    with open(path) as f:
        sarif = json.load(f)

    print("=" * 80)
    print(f"SARIF DIAGNOSTIC DUMP: {path}")
    print("=" * 80)

    # Top-level
    print(f"\n📋 TOP-LEVEL")
    print(f"  $schema:  {sarif.get('$schema', '(missing)')}")
    print(f"  version:  {sarif.get('version', '(missing)')}")
    print(f"  runs:     {len(sarif.get('runs', []))}")

    for run_idx, run in enumerate(sarif.get("runs", [])):
        print(f"\n{'=' * 80}")
        print(f"RUN #{run_idx}")
        print(f"{'=' * 80}")

        # Tool info
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        print(f"\n🔧 TOOL.DRIVER")
        print(f"  name:             {driver.get('name', '(missing)')}")
        print(f"  version:          {driver.get('version', '(missing)')}")
        print(f"  semanticVersion:  {driver.get('semanticVersion', '(not set)')}")
        print(f"  informationUri:   {driver.get('informationUri', '(not set)')}")
        print(f"  organization:     {driver.get('organization', '(not set)')}")

        # originalUriBaseIds
        ubids = run.get("originalUriBaseIds")
        print(f"\n🗂️  originalUriBaseIds: {json.dumps(ubids) if ubids else '(not set)'}")

        # Rules
        rules = driver.get("rules", []) or []
        print(f"\n📐 RULES: {len(rules)} total")
        if rules:
            # Show first rule structure
            r0 = rules[0]
            print(f"  First rule structure:")
            print(f"    keys: {list(r0.keys())}")
            print(f"    id: {r0.get('id')}")
            print(f"    name: {r0.get('name', '(not set)')}")
            print(f"    shortDescription: {json.dumps(r0.get('shortDescription', {}))[:120]}")
            props = r0.get("properties", {})
            print(f"    properties keys: {list(props.keys())}")
            print(f"    properties.security-severity: {props.get('security-severity')}")
            print(f"    properties.tags: {props.get('tags')}")
            print(f"    defaultConfiguration: {r0.get('defaultConfiguration', '(not set)')}")

            # Check for rule issues
            issues = []
            rule_ids = []
            for i, r in enumerate(rules):
                rid = r.get("id")
                if not rid:
                    issues.append(f"  ⚠️  rules[{i}] has no id")
                else:
                    rule_ids.append(rid)
                if not r.get("shortDescription"):
                    issues.append(f"  ⚠️  rules[{i}] ({rid}) missing shortDescription")

            # Check for duplicate rule IDs
            id_counts = Counter(rule_ids)
            dupes = {k: v for k, v in id_counts.items() if v > 1}
            if dupes:
                issues.append(f"  ❌ DUPLICATE RULE IDs: {dict(list(dupes.items())[:5])}")

            if issues:
                print(f"\n  Rule issues found:")
                for issue in issues[:10]:
                    print(issue)
            else:
                print(f"  ✅ No rule-level issues detected")

        # Results
        results = run.get("results", []) or []
        print(f"\n📊 RESULTS: {len(results)} total")

        if results:
            # Count distribution
            level_counts = Counter(r.get("level", "(none)") for r in results)
            rule_id_counts = Counter(r.get("ruleId", "(none)") for r in results)
            print(f"\n  Level distribution: {dict(level_counts)}")
            print(f"  Top 5 rules by count: {dict(rule_id_counts.most_common(5))}")

            # Check max results per rule (GitHub limit: 1000)
            max_per_rule = max(rule_id_counts.values()) if rule_id_counts else 0
            over_limit = {k: v for k, v in rule_id_counts.items() if v > 1000}
            print(f"\n  Max results for any single rule: {max_per_rule}")
            if over_limit:
                print(f"  ❌ RULES OVER 1000-RESULT LIMIT: {over_limit}")
            else:
                print(f"  ✅ No rule exceeds 1000-result per-rule limit")

            # Sample first 3 results in detail
            print(f"\n  📝 SAMPLE RESULTS (first 3):")
            for i, r in enumerate(results[:3]):
                print(f"\n  ── Result #{i} ──")
                print(f"    keys: {list(r.keys())}")
                print(f"    ruleId: {r.get('ruleId')}")
                print(f"    ruleIndex: {r.get('ruleIndex')}")
                print(f"    level: {r.get('level')}")

                # Message
                msg = r.get("message", {})
                msg_text = msg.get("text", "")
                msg_md = msg.get("markdown", "")
                print(f"    message.text (first 120 chars): {msg_text[:120]!r}")
                print(f"    message.markdown exists: {bool(msg_md)}")
                print(f"    message.text length: {len(msg_text)}")

                # Locations — CRITICAL for GitHub
                locs = r.get("locations", []) or []
                print(f"    locations: {len(locs)} location(s)")
                for j, loc in enumerate(locs[:2]):
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    region = phys.get("region", {})
                    print(f"      location[{j}]:")
                    print(f"        artifactLocation.uri: {art.get('uri', '(MISSING)')!r}")
                    print(f"        artifactLocation.uriBaseId: {art.get('uriBaseId', '(not set)')!r}")
                    print(f"        region: {region}")

                # partialFingerprints — GitHub uses these for deduplication
                fp = r.get("partialFingerprints")
                print(f"    partialFingerprints: {fp if fp else '(not set — GitHub will auto-generate)'}")

                # properties
                props = r.get("properties", {})
                print(f"    properties keys: {list(props.keys()) if props else '(none)'}")

            # Check all results for common issues
            print(f"\n  🔍 SCANNING ALL {len(results)} RESULTS FOR ISSUES:")
            no_location = 0
            no_uri = 0
            no_region = 0
            dangling_rule = 0
            bad_index = 0
            rule_ids_set = {r.get("id") for r in rules if r.get("id")}
            uri_samples = Counter()

            for i, r in enumerate(results):
                locs = r.get("locations", []) or []
                if not locs:
                    no_location += 1
                    continue
                for loc in locs:
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    if not art.get("uri"):
                        no_uri += 1
                    else:
                        uri_samples[art.get("uri")] += 1
                    if not phys.get("region"):
                        no_region += 1

                rid = r.get("ruleId")
                if rid and rid not in rule_ids_set:
                    dangling_rule += 1

                ridx = r.get("ruleIndex")
                if ridx is not None and (ridx < 0 or ridx >= len(rules)):
                    bad_index += 1

            print(f"    Results with NO location:      {no_location}")
            print(f"    Results with NO uri:           {no_uri}")
            print(f"    Results with NO region:        {no_region}")
            print(f"    Results with dangling ruleId:  {dangling_rule}")
            print(f"    Results with bad ruleIndex:    {bad_index}")
            print(f"\n    Top 5 unique URIs:")
            for uri, count in uri_samples.most_common(5):
                print(f"      {count:4d}x  {uri[:100]}")
            print(f"\n    Total unique URIs: {len(uri_samples)}")

    # File stats
    size_bytes = os.path.getsize(path)
    print(f"\n{'=' * 80}")
    print(f"📦 FILE STATS")
    print(f"{'=' * 80}")
    print(f"  Size: {size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)")

    # Save first 2 results verbatim for deep inspection
    if sarif.get("runs") and sarif["runs"][0].get("results"):
        sample_path = "sarif_sample_results.json"
        with open(sample_path, "w") as f:
            json.dump({
                "tool_driver": sarif["runs"][0]["tool"]["driver"],
                "originalUriBaseIds": sarif["runs"][0].get("originalUriBaseIds"),
                "first_3_rules": sarif["runs"][0]["tool"]["driver"].get("rules", [])[:3],
                "first_3_results": sarif["runs"][0]["results"][:3],
            }, f, indent=2)
        print(f"\n  💾 Saved first 3 rules + results verbatim to: {sample_path}")
        print(f"     Please paste the contents of this file in your next message.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "image.sarif"
    dump_sarif_diagnostics(path)
