#!/usr/bin/env python3
"""
Preview beautification — shows 3 sample alerts with rich titles and markdown
WITHOUT modifying any files. Pure read-only preview.

Picks 3 representative findings from image-layers.json:
  1. Most severe finding with CISA KEV (if any)
  2. A Critical finding with public exploit
  3. A regular Critical finding with fix available

Prints what each alert title and markdown body will look like in GitHub
Code Scanning. Use this to validate the format before deploying changes
to wizsarif.py.
"""
import json
import os
import sys
from datetime import datetime


# ============================================================
# Beautification helpers (must match what wizsarif.py will use)
# ============================================================

def severity_emoji(sev):
    """Return color emoji for severity badge."""
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFORMATIONAL": "⚪",
    }.get((sev or "").upper(), "⚫")


def format_alert_title(vuln, pkg):
    """
    Build a rich, scannable title for the alert.

    Patterns:
      - With fix:    "CVE-XXXX: <comp> <ver> → <fixed_ver>"
      - No fix:      "CVE-XXXX: <comp> <ver> (no fix available)"
      - With KEV:    "🚨 CVE-XXXX: <comp> <ver> → <fixed_ver> (CISA KEV)"
    """
    cve = vuln.get("name") or "UNKNOWN-CVE"
    comp = pkg.get("name") or "unknown-component"
    ver = pkg.get("version") or ""
    fixed = vuln.get("fixedVersion")
    has_kev = bool(vuln.get("hasCisaKevExploit"))

    # Truncate long versions for readability
    ver_short = ver[:50] + "…" if len(ver) > 50 else ver

    # Build the core
    if fixed:
        core = f"{cve}: {comp} {ver_short} → {fixed}"
    else:
        core = f"{cve}: {comp} {ver_short} (no fix available)"

    # Prefix with emoji ONLY for KEV (highest signal)
    if has_kev:
        return f"🚨 {core} (CISA KEV)"
    return core


def truncate_description(desc, max_len=400):
    """Truncate long descriptions cleanly at sentence boundary."""
    if not desc:
        return "_No description provided._"
    if len(desc) <= max_len:
        return desc
    # Try to cut at sentence boundary
    truncated = desc[:max_len]
    last_period = truncated.rfind(". ")
    if last_period > max_len * 0.7:  # only cut at sentence if it's near end
        truncated = truncated[:last_period + 1]
    return truncated + " _[…truncated. See source for full description.]_"


def format_remediation(vuln, pkg):
    """Build remediation guidance based on package type."""
    comp = pkg.get("name") or "unknown"
    ver = pkg.get("version") or "unknown"
    fixed = vuln.get("fixedVersion")
    pkg_type = (pkg.get("type") or "").upper()
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

    # Fix available — provide install command based on package source
    install_cmd = ""
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
        install_cmd = (
            f"```bash\n"
            f"npm install {comp}@{fixed}\n"
            f"```"
        )
    elif "PYPI" in detection or "PYTHON" in detection:
        install_cmd = (
            f"```bash\n"
            f"pip install --upgrade {comp}=={fixed}\n"
            f"```"
        )
    else:
        install_cmd = f"_Update `{comp}` to version `{fixed}` or later via your package manager._"

    return (
        f"**Component:** `{comp}`\n"
        f"**Current version:** `{ver}`\n"
        f"**Fixed in:** `{fixed}` or later\n\n"
        f"**How to fix:**\n\n"
        f"{install_cmd}"
    )


def format_layer_info(pkg):
    """Show which Dockerfile layer introduced the issue."""
    layer = pkg.get("layerMetadata") or {}
    if not layer:
        return None

    layer_id = layer.get("id") or "unknown"
    is_base = bool(layer.get("isBaseLayer"))
    instruction = (
        layer.get("details") or layer.get("createdBy") or layer.get("instruction") or ""
    )

    base_tag = " 📦 (Base image layer)" if is_base else ""

    # Truncate very long instructions
    if instruction and len(instruction) > 300:
        instruction = instruction[:300] + " ..."

    out = f"**Layer:**{base_tag}\n\n"
    if instruction:
        out += f"```\n{instruction}\n```\n\n"
    out += f"**Layer digest:** `{layer_id}`"
    return out


def format_threat_metadata(vuln):
    """Build the threat metadata table."""
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


def format_references(vuln, scan_report_url):
    """Build references section."""
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


def format_alert_markdown(vuln, pkg, scan_report_url):
    """Build the full markdown body for the alert detail page."""
    sev = (vuln.get("severity") or "").upper()
    sev_em = severity_emoji(sev)
    score = vuln.get("score")
    layer = pkg.get("layerMetadata") or {}
    is_base = bool(layer.get("isBaseLayer"))

    # Build header summary line
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

    # Build sections
    description = truncate_description(vuln.get("description"))
    remediation = format_remediation(vuln, pkg)
    layer_info = format_layer_info(pkg)
    threat = format_threat_metadata(vuln)
    refs = format_references(vuln, scan_report_url)

    md = f"{header}\n\n"
    md += f"## Description\n\n{description}\n\n"
    md += f"## 🔧 Remediation\n\n{remediation}\n\n"
    if layer_info:
        md += f"## 📦 Introduced In\n\n{layer_info}\n\n"
    md += f"## Threat Metadata\n\n{threat}\n\n"
    md += f"## References\n\n{refs}\n"

    return md


def build_rule_tags(vuln):
    """Build the tags list that will appear on the rule."""
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


# ============================================================
# Main preview logic
# ============================================================

def main():
    json_path = "image-layers.json"
    if not os.path.exists(json_path):
        print(f"❌ {json_path} not found")
        sys.exit(1)

    with open(json_path) as f:
        data = json.load(f)

    scan_report_url = data.get("reportUrl")
    print("=" * 80)
    print("BEAUTIFICATION PREVIEW — Sample alerts as they will appear in GitHub")
    print("=" * 80)
    print(f"\nScan reportUrl: {scan_report_url or '(not present in JSON)'}")

    # Find 3 representative samples among Failed findings
    result = data.get("result") or {}
    kev_sample = None
    exploit_sample = None
    regular_sample = None

    for source_key in ["osPackages", "libraries", "applications"]:
        for pkg in result.get(source_key, []) or []:
            for vuln in pkg.get("vulnerabilities", []) or []:
                # Only sample from Failed findings (the ones that will show up)
                if not vuln.get("failedPolicyMatches"):
                    continue

                if vuln.get("hasCisaKevExploit") and kev_sample is None:
                    kev_sample = (pkg, vuln)
                elif vuln.get("hasExploit") and exploit_sample is None:
                    exploit_sample = (pkg, vuln)
                elif vuln.get("fixedVersion") and regular_sample is None:
                    regular_sample = (pkg, vuln)

                if kev_sample and exploit_sample and regular_sample:
                    break

    samples = []
    if kev_sample:
        samples.append(("CISA KEV finding", kev_sample))
    if exploit_sample and exploit_sample != kev_sample:
        samples.append(("Has-exploit finding", exploit_sample))
    if regular_sample:
        samples.append(("Regular Critical finding", regular_sample))

    if not samples:
        print("\n⚠️  No 'Failed' findings found in JSON — cannot preview.")
        sys.exit(0)

    # Print each sample
    for label, (pkg, vuln) in samples:
        print("\n" + "=" * 80)
        print(f"SAMPLE: {label}")
        print("=" * 80)

        title = format_alert_title(vuln, pkg)
        md = format_alert_markdown(vuln, pkg, scan_report_url)
        tags = build_rule_tags(vuln)

        print(f"\n📌 ALERT TITLE (shown in alert lists):\n")
        print(f"   {title}")

        print(f"\n🏷️  RULE TAGS (filterable in GitHub Security tab):\n")
        print(f"   {' · '.join(tags)}")

        print(f"\n🔗 helpUri (shown as 'More info' link):\n")
        print(f"   {vuln.get('source', '(none)')}")

        print(f"\n📄 MARKDOWN BODY (rendered on alert detail page):")
        print(f"   ┌{'─' * 76}┐")
        for line in md.split("\n"):
            # Wrap long lines for terminal readability
            while len(line) > 74:
                print(f"   │ {line[:74]} │")
                line = line[74:]
            print(f"   │ {line:<74} │")
        print(f"   └{'─' * 76}┘")

    # Write the markdown to a file too so user can preview in editor
    with open("preview_sample_alerts.md", "w") as f:
        f.write("# Beautification Preview — Sample Alert Bodies\n\n")
        f.write(f"_Generated from `{json_path}` — preview only, no SARIF modified._\n\n")
        f.write(f"**Scan report URL:** {scan_report_url or '(not present)'}\n\n")
        f.write("---\n\n")
        for label, (pkg, vuln) in samples:
            title = format_alert_title(vuln, pkg)
            md = format_alert_markdown(vuln, pkg, scan_report_url)
            tags = build_rule_tags(vuln)
            f.write(f"## {label}\n\n")
            f.write(f"### Title\n\n`{title}`\n\n")
            f.write(f"### Tags\n\n`{' · '.join(tags)}`\n\n")
            f.write(f"### Body\n\n")
            f.write(md)
            f.write("\n---\n\n")

    print("\n" + "=" * 80)
    print("💾 Markdown preview saved to: preview_sample_alerts.md")
    print("   Download as artifact for richer rendering in your local editor.")
    print("=" * 80)


if __name__ == "__main__":
    main()
