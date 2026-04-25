import os
import re
import json
import textwrap
import traceback
from tabulate import tabulate

# ANSI color codes for terminal output
ANSI = {
    "CRITICAL": "\033[1;37;41m",
    "HIGH":     "\033[1;31m",
    "MEDIUM":   "\033[1;33m",
    "LOW":      "\033[1;32m",
    "INFORMATIONAL": "\033[1;90m",
    "UNKNOWN":  "\033[0m",
    "RESET":    "\033[0m",
}

EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFORMATIONAL": "⚪",
    "UNKNOWN":  "⚫",
}

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
    "INFORMATIONAL": 4, "UNKNOWN": 5,
}

SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH":     "8.0",
    "MEDIUM":   "5.5",
    "LOW":      "3.0",
    "INFORMATIONAL": "0.5",
    "UNKNOWN":  "0.0",
}

LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFORMATIONAL": "note",
    "UNKNOWN":  "note",
}

SARIF_LEVEL_TO_SEVERITY = {
    "error":   "HIGH",
    "warning": "MEDIUM",
    "note":    "LOW",
    "none":    "INFORMATIONAL",
}

SARIF_FILES = [
    ("Source Dependencies (SCA)",          "dir.sarif"),
    ("Dockerfile Misconfigurations (IaC)", "dockerfile.sarif"),
    ("Container Image",                    "image.sarif"),
]


def parse_message_text(text):
    """Parse 'Key: value' lines from Wiz's SARIF message text."""
    fields = {}
    if not text:
        return fields
    for line in text.split("\n"):
        m = re.match(r"^([A-Za-z ]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            fields.setdefault(key, val)
    idx = text.find("Description:")
    if idx >= 0:
        fields["description"] = text[idx + len("Description:"):].strip()
    return fields


def wrap(text, width):
    if not text:
        return ""
    return "\n".join(textwrap.wrap(str(text), width=width)) or str(text)


def severity_from_cvss(score_str):
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFORMATIONAL"


def get_rule_map(sarif):
    rule_map = {}
    for run in sarif.get("runs", []):
        rules = (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        for rule in rules:
            rid = rule.get("id")
            if rid:
                rule_map[rid] = rule
    return rule_map


def get_severity_for_result(result, rule_map):
    msg_text = (result.get("message") or {}).get("text", "")
    fields = parse_message_text(msg_text)
    sev = fields.get("severity", "").upper()
    if sev and sev in SECURITY_SEVERITY:
        return sev, fields

    props = result.get("properties") or {}
    prop_sev = str(props.get("severity", "")).upper()
    if prop_sev and prop_sev in SECURITY_SEVERITY:
        return prop_sev, fields

    rid = result.get("ruleId")
    rule = rule_map.get(rid, {}) if rid else {}
    rule_props = rule.get("properties") or {}

    css = rule_props.get("security-severity")
    if css:
        mapped = severity_from_cvss(css)
        if mapped:
            return mapped, fields

    rp_sev = str(rule_props.get("severity", "")).upper()
    if rp_sev and rp_sev in SECURITY_SEVERITY:
        return rp_sev, fields

    problem = rule_props.get("problem") or {}
    problem_sev = str(problem.get("severity", "")).upper()
    if problem_sev and problem_sev in SECURITY_SEVERITY:
        return problem_sev, fields

    default_cfg = rule.get("defaultConfiguration") or {}
    level = (result.get("level") or default_cfg.get("level") or "").lower()
    if level in SARIF_LEVEL_TO_SEVERITY:
        return SARIF_LEVEL_TO_SEVERITY[level], fields

    return "UNKNOWN", fields


# ========================================================================
# FIX #1: Set a proper tool version so GitHub doesn't flag "unknown"
# ========================================================================
def ensure_tool_metadata(sarif):
    """Ensure tool.driver has name and version set — GitHub logs warnings otherwise."""
    for run in sarif.get("runs", []):
        tool = run.setdefault("tool", {})
        driver = tool.setdefault("driver", {})
        if not driver.get("name"):
            driver["name"] = "Wiz CLI"
        if not driver.get("version") or driver.get("version") == "unknown":
            driver["version"] = "1.0.0"
        if not driver.get("informationUri"):
            driver["informationUri"] = "https://www.wiz.io/"
    return sarif


# ========================================================================
# FIX #2: Rewrite titles into markdown only — keep text intact for parsing
# ========================================================================
def rewrite_alert_titles(sarif, scan_label):
    """
    Put custom title in message.markdown only. Leave message.text UNCHANGED
    so Wiz's 'Key: value' format is preserved for downstream parsing and
    GitHub doesn't flag inconsistent message structure.
    """
    rule_map = get_rule_map(sarif)

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "UNKNOWN")
            severity, fields = get_severity_for_result(result, rule_map)

            component = fields.get("component", "")
            version = fields.get("version", "")
            fixed = fields.get("fixed version", "")

            if scan_label in ("SCA", "Image"):
                parts = [f"[Wiz CLI Scan] {rule_id}"]
                if component and version:
                    ver_info = f"{component} {version}"
                    if fixed and fixed.lower() not in ("n/a", ""):
                        ver_info += f" → fix: {fixed}"
                    parts.append(ver_info)
                parts.append(f"{severity} vulnerability detected")
                new_title = " : ".join(parts)
            elif scan_label == "IaC":
                rule = rule_map.get(rule_id, {}) or {}
                rule_name = rule.get("name") or ""
                rule_short = (rule.get("shortDescription") or {}).get("text", "")
                desc = rule_short or rule_name or "Misconfiguration detected"
                new_title = f"[Wiz CLI Scan] {rule_name or rule_id} : {desc} : {severity}"
            else:
                new_title = f"[Wiz CLI Scan] {rule_id}"

            original_text = (result.get("message") or {}).get("text", "")
            original_md = (result.get("message") or {}).get("markdown", "") or original_text

            # CRITICAL: Keep text unchanged, only enhance markdown
            result["message"] = {
                "text": original_text if original_text else new_title,
                "markdown": f"### {new_title}\n\n{original_md}",
            }

    return sarif


# ========================================================================
# FIX #5: Normalize image SARIF locations. GitHub Code Scanning rejects
# SARIFs where artifactLocation.uri points to docker image references,
# AND where many results collapse to the same (uri, line) because
# GitHub's fingerprint generation produces duplicates.
#
# We solve this by:
#  1. Rewriting docker URIs → "Dockerfile" (repo-relative path)
#  2. Spreading startLine values so each (ruleId, component, version)
#     combination gets a unique synthetic line number
#
# IMPORTANT: We do NOT pre-compute partialFingerprints. GitHub calculates
# its own from (file content, line) and rejects SARIFs with mismatched
# pre-computed values. Let GitHub auto-generate them.
# ========================================================================
import hashlib


def _parse_msg_fields(text):
    """Extract component/version from Wiz's Key: value message format."""
    fields = {}
    if not text:
        return fields
    for line in text.split("\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().lower()] = v.strip()
    return fields


# ========================================================================
# FIX #6: Filter image SARIF based on Wiz policy attribution.
# 
# Wiz CLI's image scan JSON output (image-layers.json) tags each finding
# with policy attribution via two fields:
#   - failedPolicyMatches: non-empty → finding FAILED the policy (must fix)
#   - ignoredPolicyMatches: non-empty → finding was IGNORED by policy
#   - both None → finding is BELOW THRESHOLD (not relevant)
#
# We use this attribution to filter image.sarif so GitHub Security tab
# matches Wiz console's view exactly:
#   - Failed findings → Open alerts in GitHub (level: error)
#   - Ignored findings → Closed alerts in GitHub (with suppressions field)
#   - Below threshold findings → DROPPED (not in SARIF at all)
#
# Matching SARIF results to JSON findings is done by parsing
# (CVE name, component name, component version) from message.text since
# SARIF and JSON don't share IDs.
# ========================================================================

def build_policy_attribution_map(json_path):
    """
    Read image-layers.json and build a map of:
      (cve_name, component_name, component_version) -> "failed" / "ignored" / None
    
    Returns the map plus stats for reporting.
    """
    if not os.path.exists(json_path):
        print(f"  ⚠️  {json_path} not found — cannot apply Wiz policy filter")
        return None, None
    
    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ⚠️  Could not parse {json_path}: {e}")
        return None, None
    
    result = data.get("result") or {}
    attribution = {}
    stats = {"failed": 0, "ignored": 0, "below_threshold": 0, "total": 0}
    
    for source_key in ["osPackages", "libraries", "applications"]:
        for pkg in result.get(source_key, []) or []:
            pkg_name = (pkg.get("name") or "").strip().lower()
            pkg_ver = (pkg.get("version") or "").strip()
            
            for vuln in pkg.get("vulnerabilities", []) or []:
                cve = (vuln.get("name") or "").strip()
                if not cve:
                    continue
                
                key = (cve, pkg_name, pkg_ver)
                stats["total"] += 1
                
                failed = vuln.get("failedPolicyMatches")
                ignored = vuln.get("ignoredPolicyMatches")
                
                if failed:
                    attribution[key] = "failed"
                    stats["failed"] += 1
                elif ignored:
                    attribution[key] = "ignored"
                    stats["ignored"] += 1
                else:
                    attribution[key] = "below_threshold"
                    stats["below_threshold"] += 1
    
    return attribution, stats


# ========================================================================
# BEAUTIFICATION: Functions to enrich SARIF results with rich titles,
# remediation guidance, layer info, threat metadata, and references.
# ========================================================================

def build_vuln_metadata_map(json_path):
    """
    Build a map of (cve, comp_name, comp_ver) -> full vuln + package data.
    Used for beautifying SARIF results with rich metadata.
    """
    if not os.path.exists(json_path):
        return None, None
    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception:
        return None, None

    metadata = {}
    scan_report_url = data.get("reportUrl")

    result = data.get("result") or {}
    for source_key in ["osPackages", "libraries", "applications"]:
        for pkg in result.get(source_key, []) or []:
            pkg_name = (pkg.get("name") or "").strip().lower()
            pkg_ver = (pkg.get("version") or "").strip()
            for vuln in pkg.get("vulnerabilities", []) or []:
                cve = (vuln.get("name") or "").strip()
                if not cve:
                    continue
                key = (cve, pkg_name, pkg_ver)
                metadata[key] = {"vuln": vuln, "pkg": pkg}

    return metadata, scan_report_url


def _severity_emoji(sev):
    return {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
        "LOW": "🟢", "INFORMATIONAL": "⚪",
    }.get((sev or "").upper(), "⚫")


def _format_alert_title(vuln, pkg):
    """Build rich title: 'CVE-XXX: <comp> <ver> → <fixed_ver> [(modifier)]'"""
    cve = vuln.get("name") or "UNKNOWN-CVE"
    comp = pkg.get("name") or "unknown-component"
    ver = pkg.get("version") or ""
    fixed = vuln.get("fixedVersion")
    has_kev = bool(vuln.get("hasCisaKevExploit"))

    ver_short = ver[:50] + "…" if len(ver) > 50 else ver

    if fixed:
        core = f"{cve}: {comp} {ver_short} → {fixed}"
    else:
        core = f"{cve}: {comp} {ver_short} (no fix available)"

    if has_kev:
        return f"🚨 {core} (CISA KEV)"
    return core


def _truncate_description(desc, max_len=400):
    if not desc:
        return "_No description provided._"
    if len(desc) <= max_len:
        return desc
    truncated = desc[:max_len]
    last_period = truncated.rfind(". ")
    if last_period > max_len * 0.7:
        truncated = truncated[:last_period + 1]
    return truncated + " _[…truncated. See source for full description.]_"


def _format_remediation(vuln, pkg):
    comp = pkg.get("name") or "unknown"
    ver = pkg.get("version") or "unknown"
    fixed = vuln.get("fixedVersion")
    detection = (pkg.get("detectionMethod") or "").upper()

    if not fixed:
        return (
            f"**Component:** `{comp}`\n"
            f"**Current version:** `{ver}`\n"
            f"**Status:** ⚠️ No fix currently available from upstream\n\n"
            f"Mitigations to consider:\n"
            f"- Apply compensating controls (network restrictions, runtime monitoring)\n"
            f"- Track upstream for fix availability\n"
            f"- Consider replacing the dependency if no fix is forthcoming"
        )

    if "DEBIAN" in detection or "APT" in detection or detection == "PACKAGE":
        install_cmd = (
            f"```dockerfile\n"
            f"RUN apt-get update && apt-get install -y --only-upgrade {comp}\n"
            f"```"
        )
    elif "ALPINE" in detection or "APK" in detection:
        install_cmd = (
            f"```dockerfile\n"
            f"RUN apk add --no-cache {comp}={fixed}\n"
            f"```"
        )
    elif "NPM" in detection or "JAVASCRIPT" in detection:
        install_cmd = f"```bash\nnpm install {comp}@{fixed}\n```"
    elif "PYPI" in detection or "PYTHON" in detection:
        install_cmd = f"```bash\npip install --upgrade {comp}=={fixed}\n```"
    else:
        install_cmd = f"_Update `{comp}` to version `{fixed}` or later via your package manager._"

    return (
        f"**Component:** `{comp}`\n"
        f"**Current version:** `{ver}`\n"
        f"**Fixed in:** `{fixed}` or later\n\n"
        f"**How to fix:**\n\n{install_cmd}"
    )


def _format_layer_info(pkg):
    layer = pkg.get("layerMetadata") or {}
    if not layer:
        return None
    layer_id = layer.get("id") or "unknown"
    is_base = bool(layer.get("isBaseLayer"))
    instruction = (
        layer.get("details") or layer.get("createdBy")
        or layer.get("instruction") or ""
    )
    base_tag = " 📦 (Base image layer)" if is_base else ""
    if instruction and len(instruction) > 300:
        instruction = instruction[:300] + " ..."
    out = f"**Layer:**{base_tag}\n\n"
    if instruction:
        out += f"```\n{instruction}\n```\n\n"
    out += f"**Layer digest:** `{layer_id}`"
    return out


def _format_threat_metadata(vuln):
    rows = []
    if vuln.get("score") is not None:
        rows.append(("CVSS Score", f"{vuln['score']} ({(vuln.get('severity') or '').title()})"))
    if vuln.get("epssProbability") is not None:
        epss = vuln["epssProbability"]
        rows.append(("EPSS Probability", f"{epss * 100:.2f}%" if epss < 1 else f"{epss:.2f}%"))
    if vuln.get("epssPercentile") is not None:
        rows.append(("EPSS Percentile", f"{vuln['epssPercentile']:.1f}%"))
    has_exploit = vuln.get("hasExploit")
    if has_exploit is not None:
        rows.append(("Public Exploit", "🔥 Yes" if has_exploit else "No"))
    has_kev = vuln.get("hasCisaKevExploit")
    if has_kev is not None:
        rows.append(("CISA KEV Listed", "🚨 Yes" if has_kev else "No"))
    pub = vuln.get("publishDate")
    if pub:
        rows.append(("CVE Published", pub.split("T")[0]))
    fix_pub = vuln.get("fixPublishDate")
    if fix_pub:
        rows.append(("Fix Published", fix_pub.split("T")[0]))

    if not rows:
        return "_No threat metadata available._"
    md = "| Indicator | Value |\n|---|---|\n"
    for k, v in rows:
        md += f"| {k} | {v} |\n"
    return md


def _format_references(vuln, scan_report_url):
    refs = []
    if scan_report_url:
        refs.append(f"- 🔗 [View this scan in Wiz Console]({scan_report_url})")
    source = vuln.get("source")
    if source:
        refs.append(f"- 📋 [Source Advisory]({source})")
    cve = vuln.get("name", "")
    if cve.startswith("CVE-"):
        refs.append(f"- 🔍 [NVD Entry](https://nvd.nist.gov/vuln/detail/{cve})")
    if not refs:
        return "_No references available._"
    return "\n".join(refs)


def _format_alert_markdown(vuln, pkg, scan_report_url):
    """Build the full markdown body for the alert detail page."""
    sev = (vuln.get("severity") or "").upper()
    sev_em = _severity_emoji(sev)
    score = vuln.get("score")
    layer = pkg.get("layerMetadata") or {}
    is_base = bool(layer.get("isBaseLayer"))

    parts = [f"**Severity:** {sev_em} {sev.title()}"]
    if score is not None:
        parts[0] += f" (CVSS {score})"
    if vuln.get("fixedVersion"):
        parts.append("**Fix available:** Yes")
    else:
        parts.append("**Fix available:** No")
    if is_base:
        parts.append("**Base image layer:** Yes")

    header = " · ".join(parts)
    description = _truncate_description(vuln.get("description"))
    remediation = _format_remediation(vuln, pkg)
    layer_info = _format_layer_info(pkg)
    threat = _format_threat_metadata(vuln)
    refs = _format_references(vuln, scan_report_url)

    md = f"{header}\n\n"
    md += f"## Description\n\n{description}\n\n"
    md += f"## 🔧 Remediation\n\n{remediation}\n\n"
    if layer_info:
        md += f"## 📦 Introduced In\n\n{layer_info}\n\n"
    md += f"## Threat Metadata\n\n{threat}\n\n"
    md += f"## References\n\n{refs}\n"
    return md


def _build_rule_tags(vuln):
    tags = ["security", "vulnerability"]
    sev = (vuln.get("severity") or "").lower()
    if sev:
        tags.append(sev)
    if vuln.get("hasExploit"):
        tags.append("has-exploit")
    if vuln.get("hasCisaKevExploit"):
        tags.append("cisa-kev")
    if not vuln.get("fixedVersion"):
        tags.append("no-fix")
    return tags


def beautify_image_sarif(sarif, vuln_metadata_map, scan_report_url):
    """
    Apply rich beautification to image SARIF: titles, markdown bodies,
    rule tags, helpUri. Falls back gracefully when metadata is missing.
    """
    if not vuln_metadata_map:
        print(f"  ⚠️  No vuln metadata map — skipping beautification")
        return sarif

    # Build a CVE -> rule index for updating rule metadata
    rules_by_id = {}
    for run in sarif.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rid = rule.get("id")
            if rid:
                rules_by_id[rid] = rule

    beautified_count = 0
    skipped_count = 0
    rule_updates = {}  # rule_id -> {tags, helpUri, fullDescription}

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            cve = (result.get("ruleId") or "").strip()
            msg_text = (result.get("message") or {}).get("text", "") or ""
            fields = parse_message_text(msg_text)
            comp_name = (fields.get("component") or "").strip().lower()
            comp_ver = (fields.get("version") or "").strip()

            key = (cve, comp_name, comp_ver)
            meta = vuln_metadata_map.get(key)
            if not meta:
                skipped_count += 1
                continue

            vuln = meta["vuln"]
            pkg = meta["pkg"]

            # Build title and markdown
            title = _format_alert_title(vuln, pkg)
            markdown = _format_alert_markdown(vuln, pkg, scan_report_url)

            # Update result.message — text gets the title (used in alert lists),
            # markdown gets the rich body (used in alert detail page)
            result["message"] = {
                "text": title,
                "markdown": markdown,
            }

            # Track rule-level updates (do them after, to avoid duplicates)
            if cve and cve not in rule_updates:
                rule_updates[cve] = {
                    "tags": _build_rule_tags(vuln),
                    "helpUri": vuln.get("source") or "",
                    "shortDescription": title,
                    "fullDescription": _truncate_description(
                        vuln.get("description"), max_len=600
                    ),
                }

            beautified_count += 1

    # Apply rule-level updates
    for rid, updates in rule_updates.items():
        rule = rules_by_id.get(rid)
        if not rule:
            continue
        # Merge tags into existing tags
        props = rule.setdefault("properties", {})
        existing_tags = set(props.get("tags", []) or [])
        existing_tags.update(updates["tags"])
        props["tags"] = sorted(existing_tags)
        # Set helpUri only if we have one (and no existing one)
        if updates["helpUri"] and not rule.get("helpUri"):
            rule["helpUri"] = updates["helpUri"]
        # Update shortDescription with our rich title
        if updates["shortDescription"]:
            rule["shortDescription"] = {"text": updates["shortDescription"]}
        # Update fullDescription
        if updates["fullDescription"]:
            rule["fullDescription"] = {"text": updates["fullDescription"]}

    print(f"\n  ✨ BEAUTIFICATION APPLIED")
    print(f"     Beautified results:  {beautified_count}")
    print(f"     Beautified rules:    {len(rule_updates)}")
    if skipped_count:
        print(f"     Skipped (no JSON match): {skipped_count}")

    return sarif


def filter_sarif_by_wiz_policy(sarif, attribution_map, stats):
    """
    Filter SARIF results based on Wiz policy attribution.

    KEY INSIGHT: Wiz JSON output is binary — every finding is either:
      - in failedPolicyMatches (= "Failed" in console = action required)
      - in ignoredPolicyMatches (= "Below Threshold" or "Ignored" in console)

    The console's "Ignored" vs "Below Threshold" distinction does NOT
    appear in the JSON — both are lumped into ignoredPolicyMatches.

    So we keep ONLY findings with non-empty failedPolicyMatches.
    This matches the Wiz console's "Failed" count exactly.

    Findings with ignoredPolicyMatches → DROPPED (they will not appear
    in GitHub Security tab). They remain visible in the Wiz console.
    """
    if not attribution_map:
        print(f"  ⚠️  No attribution map — skipping policy filter")
        return sarif

    kept_failed = 0
    dropped_ignored = 0
    dropped_below_threshold = 0
    unmatched = 0

    for run in sarif.get("runs", []):
        original_results = run.get("results", []) or []
        new_results = []

        for result in original_results:
            cve = (result.get("ruleId") or "").strip()

            # Parse component+version from message.text
            msg_text = (result.get("message") or {}).get("text", "") or ""
            fields = parse_message_text(msg_text)
            comp_name = (fields.get("component") or "").strip().lower()
            comp_ver = (fields.get("version") or "").strip()

            key = (cve, comp_name, comp_ver)
            attr = attribution_map.get(key)

            if attr == "failed":
                # Keep as Open alert — matches Wiz console "Failed"
                new_results.append(result)
                kept_failed += 1
            elif attr == "ignored":
                # Drop — Wiz JSON conflates "Ignored" and "Below Threshold"
                # into this bucket; not actionable for GitHub Security tab
                dropped_ignored += 1
            elif attr == "below_threshold":
                # Drop — explicitly below policy threshold
                dropped_below_threshold += 1
            else:
                # Unmatched — SARIF result with no JSON counterpart.
                # Conservative: drop it to keep noise low. Customer can
                # always cross-reference Wiz console for full visibility.
                unmatched += 1

        run["results"] = new_results

    total_dropped = dropped_ignored + dropped_below_threshold + unmatched

    # Print attribution summary
    print(f"\n  🎯 WIZ POLICY FILTER APPLIED")
    print(f"     Wiz JSON had {stats['total']} total findings:")
    print(f"       Failed:          {stats['failed']:>5}  → KEPT (Open in GitHub)")
    print(f"       Ignored:         {stats['ignored']:>5}  → DROPPED")
    print(f"       Below Threshold: {stats['below_threshold']:>5}  → DROPPED")
    print(f"     SARIF results processed:")
    print(f"       Kept (Failed):     {kept_failed:>5}")
    print(f"       Dropped (Ignored): {dropped_ignored:>5}")
    print(f"       Dropped (BT):      {dropped_below_threshold:>5}")
    if unmatched:
        print(f"       Dropped (Unmatched):{unmatched:>5}  (typically EOL/secrets/non-CVE findings)")
    print(f"     → GitHub Security tab will show: {kept_failed} Open alerts")

    # Write to GitHub Step Summary
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write("\n## Wiz Image Scan — GitHub Security Tab Mapping\n\n")
            f.write(f"Filter applied based on Wiz policy `Zee-Container-Security`:\n\n")
            f.write(f"| State | Count | Mapped From |\n")
            f.write(f"|-------|------:|--------|\n")
            f.write(f"| 🔴 Open (action required) | **{kept_failed}** | Wiz `Failed` findings |\n")
            f.write(f"| ⚪ Dropped from SARIF | {total_dropped} | Wiz `Ignored` / Below Threshold (visible in Wiz console) |\n")
            f.write(f"\n**Total in GitHub Security tab:** {kept_failed} Open alerts\n")
            f.write(f"**Total findings detected by Wiz:** {stats['total']}\n")
            if stats['total']:
                reduction = (1 - kept_failed / stats['total']) * 100
                f.write(f"**Noise reduction:** {reduction:.1f}%\n")

    return sarif


def normalize_image_locations(sarif, target_path="Dockerfile", max_line=1000):
    """
    Rewrite artifactLocation.uri to a repo-relative path, give each result
    a unique startLine (based on ruleId+component+version hash), and add
    pre-computed partialFingerprints so GitHub's processor doesn't reject
    the SARIF during fingerprint generation.
    """
    for run in sarif.get("runs", []):
        run.setdefault("originalUriBaseIds", {})
        run["originalUriBaseIds"]["SRCROOT"] = {
            "uri": "file:///",
            "description": {"text": "Repository root"},
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")

            # Extract component+version from the message for uniqueness
            msg_text = (result.get("message") or {}).get("text", "")
            fields = _parse_msg_fields(msg_text)
            component = fields.get("component", "")
            version = fields.get("version", "")

            # Build a unique fingerprint key from (ruleId, component, version)
            fingerprint_key = f"{rule_id}|{component}|{version}"
            fp_hash = hashlib.sha256(fingerprint_key.encode()).hexdigest()

            # Synthetic startLine from hash — deterministic & unique-ish
            # Modulo max_line keeps it in a reasonable range for display
            synthetic_line = (int(fp_hash[:8], 16) % max_line) + 1

            locations = result.get("locations") or []
            if not locations:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_path,
                            "uriBaseId": "SRCROOT",
                        },
                        "region": {
                            "startLine": synthetic_line,
                            "endLine": synthetic_line,
                        },
                    }
                }]
            else:
                for loc in locations:
                    phys = loc.setdefault("physicalLocation", {})
                    art = phys.setdefault("artifactLocation", {})
                    original_uri = art.get("uri", "")

                    # Save original container image reference
                    if original_uri and (
                        original_uri.startswith("docker.io/")
                        or ":sha256:" in original_uri
                        or "@sha256:" in original_uri
                        or ("/" in original_uri and ":" in original_uri)
                    ):
                        props = result.setdefault("properties", {})
                        props["imageRef"] = original_uri

                    # Rewrite to repo-relative path
                    art["uri"] = target_path
                    art["uriBaseId"] = "SRCROOT"

                    # Use synthetic startLine for uniqueness
                    phys["region"] = {
                        "startLine": synthetic_line,
                        "endLine": synthetic_line,
                    }

            # Use synthetic startLine for uniqueness across results.
            # DO NOT pre-compute partialFingerprints — GitHub calculates
            # its own fingerprint from (file, line) and rejects SARIFs
            # with mismatched pre-computed fingerprints. See warning:
            # "Calculated fingerprint X:1 for file Dockerfile line 2,
            #  but found existing inconsistent fingerprint value Y"

    return sarif


def enrich_sarif_with_severity(sarif):
    rule_map = get_rule_map(sarif)
    rule_severity = {}

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rid = result.get("ruleId")
            sev, _ = get_severity_for_result(result, rule_map)
            if sev not in SECURITY_SEVERITY:
                sev = "UNKNOWN"
            if rid:
                rule_severity[rid] = sev
            result["level"] = LEVEL_MAP.get(sev, "warning")

    for run in sarif.get("runs", []):
        rules = (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        for rule in rules:
            rid = rule.get("id")
            sev = rule_severity.get(rid, "UNKNOWN")
            props = rule.setdefault("properties", {})
            props["security-severity"] = SECURITY_SEVERITY.get(sev, "0.0")
            tags = props.setdefault("tags", [])
            if "security" not in tags:
                tags.append("security")
            if sev.lower() not in tags:
                tags.append(sev.lower())
    return sarif


# ========================================================================
# FIX #3: Rewrite cap_results with strict rule-result consistency
# ========================================================================
def cap_results(sarif, max_results=1000):
    """
    Trim SARIF to max_results while maintaining strict ruleId/ruleIndex/rules
    consistency. This is what GitHub's backend validation enforces.

    Key invariants enforced:
    1. Every result.ruleId MUST have a matching rule in tool.driver.rules
    2. result.ruleIndex (if present) MUST point to the rule with matching id
    3. Orphan results (ruleId with no matching rule) are DROPPED entirely
    """
    severity_priority = {"error": 0, "warning": 1, "note": 2, "none": 3}

    for run in sarif.get("runs", []):
        tool_driver = run.setdefault("tool", {}).setdefault("driver", {})
        all_rules = tool_driver.get("rules", []) or []
        original_rule_ids = {r.get("id") for r in all_rules if r.get("id")}

        results = run.get("results", []) or []
        if not results:
            tool_driver["rules"] = []
            continue

        # Step 1: Drop orphan results whose ruleId doesn't exist in rules.
        # This is the key fix — GitHub rejects SARIFs with dangling ruleIds.
        valid_results = [
            r for r in results
            if r.get("ruleId") and r.get("ruleId") in original_rule_ids
        ]

        # Step 2: Sort by severity so highest-severity survives the cap
        valid_results.sort(key=lambda r: severity_priority.get(
            (r.get("level") or "warning").lower(), 9
        ))

        # Step 3: Apply the cap
        capped_results = valid_results[:max_results]

        # Step 4: Collect rule IDs actually used
        used_rule_ids = {r.get("ruleId") for r in capped_results}

        # Step 5: Filter rules to only those used, preserving order
        kept_rules = [r for r in all_rules if r.get("id") in used_rule_ids]

        # Step 6: Build authoritative id->index map from kept_rules
        rule_id_to_index = {r.get("id"): i for i, r in enumerate(kept_rules)}

        # Step 7: Fix every result's ruleIndex to match kept_rules exactly
        for result in capped_results:
            rid = result.get("ruleId")
            # We guaranteed rid is in rule_id_to_index by step 1 + step 4
            result["ruleIndex"] = rule_id_to_index[rid]

        # Step 8: Commit
        run["results"] = capped_results
        tool_driver["rules"] = kept_rules

    return sarif


# ========================================================================
# FIX #4: Final validation pass — catch any remaining schema issues
# ========================================================================
def validate_sarif(sarif, path):
    """Sanity check before writing. Prints warnings for any issues."""
    issues = []
    for run_idx, run in enumerate(sarif.get("runs", [])):
        rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
        rule_ids = {r.get("id") for r in rules if r.get("id")}
        rule_id_list = [r.get("id") for r in rules]

        results = run.get("results", []) or []
        for res_idx, r in enumerate(results):
            rid = r.get("ruleId")
            ridx = r.get("ruleIndex")

            if not rid:
                issues.append(f"  run[{run_idx}].results[{res_idx}]: missing ruleId")
                continue

            if rid not in rule_ids:
                issues.append(f"  run[{run_idx}].results[{res_idx}]: ruleId '{rid}' not in rules array")

            if ridx is not None:
                if ridx < 0 or ridx >= len(rules):
                    issues.append(f"  run[{run_idx}].results[{res_idx}]: ruleIndex {ridx} out of bounds")
                elif rule_id_list[ridx] != rid:
                    issues.append(f"  run[{run_idx}].results[{res_idx}]: ruleIndex {ridx} points to '{rule_id_list[ridx]}' but ruleId is '{rid}'")

    if issues:
        print(f"  ⚠️  Validation issues in {path}:")
        for issue in issues[:10]:
            print(issue)
        if len(issues) > 10:
            print(f"    ... and {len(issues) - 10} more issues")
    else:
        print(f"  ✅ {path} passed validation")
    return len(issues) == 0


def extract_rows(sarif):
    rule_map = get_rule_map(sarif)
    rows = []

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "N/A")
            severity, fields = get_severity_for_result(result, rule_map)

            rule = rule_map.get(rule_id, {})
            rule_short = (rule.get("shortDescription") or {}).get("text", "")
            rule_name = rule.get("name") or ""

            component = fields.get("component") or rule_name or "N/A"
            version = fields.get("version", "N/A")
            fixed = fields.get("fixed version", "N/A")

            msg_text = (result.get("message") or {}).get("text", "")
            desc = (fields.get("description", "") or rule_short or msg_text).split("\n")[0]

            locs = result.get("locations") or []
            file_path = "N/A"
            if locs:
                file_path = (
                    locs[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "N/A")
                )

            status = f"fixed in {fixed}" if fixed != "N/A" else "no fix"

            display_rule = rule_id
            if rule_name and len(rule_id) > 30 and "-" in rule_id:
                display_rule = rule_name

            rows.append({
                "rule": display_rule,
                "severity": severity,
                "component": component,
                "version": version,
                "status": status,
                "file": file_path,
                "description": desc,
            })

    rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))
    return rows


def print_report(title, rows):
    headers = ["RULE / CVE", "SEVERITY", "COMPONENT", "VERSION",
               "STATUS", "FILE", "DESCRIPTION"]
    display = [
        [
            wrap(r["rule"], 30),
            f"{ANSI.get(r['severity'], '')}{r['severity']}{ANSI['RESET']}",
            wrap(r["component"], 18),
            wrap(r["version"], 12),
            wrap(r["status"], 18),
            wrap(r["file"], 24),
            wrap(r["description"], 50),
        ]
        for r in rows
    ]

    bar = "=" * 100
    print(f"\n{bar}\n{title}  ({len(rows)} findings)\n{bar}")

    if rows:
        print(tabulate(display, headers=headers, tablefmt="grid"))
    else:
        print("No findings.")

    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    if counts:
        print("\nSummary: " + " | ".join(
            f"{ANSI.get(s, '')}{s}: {counts[s]}{ANSI['RESET']}"
            for s in SEVERITY_ORDER if counts.get(s)
        ))

    return counts


def write_summary(title, rows, counts):
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    headers = ["Rule / CVE", "Severity", "Component", "Version",
               "Status", "File", "Description"]
    md_rows = [
        [
            r["rule"],
            f"{EMOJI.get(r['severity'], '')} {r['severity']}",
            r["component"],
            r["version"],
            r["status"],
            r["file"],
            r["description"][:120],
        ]
        for r in rows
    ]

    with open(summary_path, "a") as f:
        f.write(f"\n## {title}\n\n")
        f.write(f"**Total findings shown:** {len(rows)}\n\n")
        if counts:
            f.write("**Breakdown:** " + " | ".join(
                f"{EMOJI[s]} {s}: {counts[s]}"
                for s in SEVERITY_ORDER if counts.get(s)
            ) + "\n\n")
        if rows:
            f.write(tabulate(md_rows, headers=headers, tablefmt="github"))
            f.write("\n")


def _extract_layer_info(obj):
    if not isinstance(obj, dict):
        return None, "", None, False

    meta = obj.get("layerMetadata")
    if not isinstance(meta, dict):
        return None, "", None, False

    layer_id = (
        meta.get("id") or meta.get("layerId") or meta.get("layerID")
        or meta.get("digest") or meta.get("layerDigest")
        or meta.get("sha") or meta.get("hash")
    )

    instruction = (
        meta.get("details") or meta.get("createdBy")
        or meta.get("instruction") or meta.get("command")
        or meta.get("cmd") or meta.get("layerInstruction") or ""
    )

    index = meta.get("index") or meta.get("layerIndex") or meta.get("order")
    is_base = bool(meta.get("isBaseLayer", False))

    return (
        str(layer_id) if layer_id else None,
        str(instruction) if instruction else "",
        index,
        is_base,
    )


def print_layer_report(json_path="image-layers.json"):
    if not os.path.exists(json_path):
        print(f"\n(Skipping per-layer report: {json_path} not found)")
        return

    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"\n(Could not parse {json_path}: {e})")
        return

    try:
        result = data.get("result") or {}
        all_findings = []
        for key in ("osPackages", "libraries", "applications"):
            all_findings.extend(result.get(key, []) or [])

        if not all_findings:
            print(f"(Layer report: no findings in result. Keys = {list(result.keys())})")
            return

        layers = {}
        for pkg in all_findings:
            layer_id, instruction, index, is_base = _extract_layer_info(pkg)
            if not layer_id:
                layer_id = "unknown"

            vulns = pkg.get("vulnerabilities", []) or []
            for v in vulns:
                key = (layer_id, instruction)
                layers.setdefault(key, {
                    "findings": [],
                    "index": index if index is not None else 999,
                    "is_base": is_base,
                })
                layers[key]["findings"].append({
                    "cve": v.get("name", "N/A"),
                    "severity": (v.get("severity") or "UNKNOWN").upper(),
                    "component": pkg.get("name", "N/A"),
                    "version": pkg.get("version", "N/A"),
                    "fixed": v.get("fixedVersion") or "no fix",
                })

        if not layers:
            print("(Layer report: no vulnerabilities found)")
            return

        def sort_key(item):
            (layer_id, _), payload = item
            return (payload["index"], str(layer_id))

        sorted_layers = sorted(layers.items(), key=sort_key)

        bar = "=" * 100
        print(f"\n{bar}\nPer-Layer Vulnerability Report  ({len(sorted_layers)} layers)\n{bar}")

        for idx, ((layer_id, instruction), payload) in enumerate(sorted_layers):
            findings = payload["findings"]
            is_base = payload.get("is_base", False)

            sev_counts = {}
            for f in findings:
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

            base_tag = " [BASE IMAGE]" if is_base else ""
            print(f"\nLayer #{idx + 1}{base_tag}")
            print(f"  Digest:      {layer_id}")
            if instruction:
                wrapped = textwrap.fill(
                    instruction, width=140,
                    initial_indent="  Instruction: ",
                    subsequent_indent="               ",
                )
                print(wrapped)

            sev_summary = " | ".join(
                f"{ANSI.get(s, '')}{s}: {sev_counts[s]}{ANSI['RESET']}"
                for s in SEVERITY_ORDER if sev_counts.get(s)
            )
            print(f"  Findings:    {len(findings)}  ({sev_summary})")

            findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
            seen = set()
            deduped = []
            for f in findings:
                k = (f["component"], f["cve"])
                if k not in seen:
                    seen.add(k)
                    deduped.append(f)
            top = deduped[:5]

            rows = [
                [
                    wrap(f["cve"], 16),
                    f"{ANSI.get(f['severity'], '')}{f['severity']}{ANSI['RESET']}",
                    wrap(f["component"], 24),
                    wrap(f["version"], 16),
                    wrap(f["fixed"], 16),
                ]
                for f in top
            ]
            print(tabulate(
                rows,
                headers=["CVE", "SEVERITY", "COMPONENT", "VERSION", "FIXED"],
                tablefmt="grid",
            ))
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more in this layer")

        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a") as f:
                f.write(f"\n## Per-Layer Vulnerability Report  ({len(sorted_layers)} layers)\n\n")
                for idx, ((layer_id, instruction), payload) in enumerate(sorted_layers):
                    findings = payload["findings"]
                    is_base = payload.get("is_base", False)

                    sev_counts = {}
                    for fd in findings:
                        sev_counts[fd["severity"]] = sev_counts.get(fd["severity"], 0) + 1

                    base_tag = " 🏛️ **BASE IMAGE**" if is_base else ""
                    f.write(f"### Layer #{idx + 1}{base_tag}\n\n")
                    f.write(f"**Digest:** `{layer_id}`\n\n")
                    if instruction:
                        f.write(f"**Instruction:** `{instruction}`\n\n")
                    f.write(f"**Findings:** {len(findings)} — " + " | ".join(
                        f"{EMOJI.get(s, '')} {s}: {sev_counts[s]}"
                        for s in SEVERITY_ORDER if sev_counts.get(s)
                    ) + "\n\n")

                    findings.sort(key=lambda fd: SEVERITY_ORDER.get(fd["severity"], 99))
                    seen = set()
                    deduped = []
                    for fd in findings:
                        k = (fd["component"], fd["cve"])
                        if k not in seen:
                            seen.add(k)
                            deduped.append(fd)
                    top = deduped[:5]

                    md_rows = [
                        [fd["cve"],
                         f"{EMOJI.get(fd['severity'], '')} {fd['severity']}",
                         fd["component"], fd["version"], fd["fixed"]]
                        for fd in top
                    ]
                    f.write(tabulate(
                        md_rows,
                        headers=["CVE", "Severity", "Component", "Version", "Fixed"],
                        tablefmt="github",
                    ))
                    f.write("\n\n")
                    if len(findings) > 5:
                        f.write(f"_... and {len(findings) - 5} more in this layer_\n\n")

    except Exception as e:
        print(f"\n(Per-layer report failed: {e})")
        print(traceback.format_exc())


def main():
    any_found = False
    for title, path in SARIF_FILES:
        if not os.path.exists(path):
            print(f"Skipping {title}: {path} not found")
            continue
        any_found = True

        try:
            with open(path) as f:
                sarif = json.load(f)

            # 1. Ensure tool metadata (fixes "version: unknown" warning)
            sarif = ensure_tool_metadata(sarif)

            # 2. Filter by Wiz policy attribution (image SARIF only)
            #    Reads image-layers.json to determine which findings are
            #    Failed / Ignored / Below Threshold per the Wiz policy
            vuln_metadata_map = None
            scan_report_url = None
            if "image" in path.lower():
                attribution_map, stats = build_policy_attribution_map("image-layers.json")
                if attribution_map is not None:
                    sarif = filter_sarif_by_wiz_policy(sarif, attribution_map, stats)
                # Also load full vuln metadata for beautification
                vuln_metadata_map, scan_report_url = build_vuln_metadata_map("image-layers.json")

            # 3. Normalize image locations (THE FIX for wiz-image failure)
            # GitHub rejects SARIFs whose artifactLocation.uri points to
            # docker image references instead of repo-relative paths.
            if "image" in path.lower():
                sarif = normalize_image_locations(sarif, target_path="Dockerfile")

            # 4. Enrich: add security-severity to each rule
            sarif = enrich_sarif_with_severity(sarif)

            # 5. Beautify (image SARIF) OR rewrite titles (other SARIFs)
            #    Image SARIF gets full beautification: rich titles + markdown
            #    body + tags + helpUri. SCA/IaC keep the simpler title format.
            scan_label = "SCA" if "dir" in path else (
                "IaC" if "dockerfile" in path else "Image"
            )
            if scan_label == "Image" and vuln_metadata_map:
                sarif = beautify_image_sarif(sarif, vuln_metadata_map, scan_report_url)
            else:
                sarif = rewrite_alert_titles(sarif, scan_label)

            # 6. Cap results with strict rule-result consistency
            if "image" in path.lower():
                sarif = cap_results(sarif, max_results=1000)
            else:
                sarif = cap_results(sarif, max_results=5000)

            # 7. Validate before writing
            validate_sarif(sarif, path)

            with open(path, "w") as f:
                json.dump(sarif, f, separators=(",", ":"))

            size_kb = os.path.getsize(path) / 1024
            result_count = sum(
                len(run.get("results", [])) for run in sarif.get("runs", [])
            )
            rule_count = sum(
                len(run.get("tool", {}).get("driver", {}).get("rules", []))
                for run in sarif.get("runs", [])
            )
            print(f"  Saved {path}: {size_kb:.1f} KB, {result_count} results, {rule_count} rules")

            rows = extract_rows(sarif)

            seen = set()
            deduped = []
            for r in rows:
                key = (r["component"], r["version"], r["rule"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(r)

            rows = deduped[:3]

            counts = print_report(title, rows)
            write_summary(title, rows, counts)
        except Exception as e:
            print(f"\n(Error processing {title}: {e})")
            print(traceback.format_exc())

    if not any_found:
        print("No SARIF files found. Did the scan steps run?")

    try:
        print_layer_report("image-layers.json")
    except Exception as e:
        print(f"\n(Per-layer report outer failure: {e})")


if __name__ == "__main__":
    main()
