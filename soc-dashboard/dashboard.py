#!/usr/bin/env python3
"""Local SOC dashboard.

Merges Wazuh alert exports (JSON array or JSONL) with scanner findings CSV
exports into a single self-contained HTML report. Python standard library only.

Usage:
    python dashboard.py --alerts FILE --findings FILE --out report.html [--title TEXT]
    python dashboard.py --demo
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_DIR = BASE_DIR / "sample"

# Wazuh rule levels >= this value are counted as "high-severity alerts".
ALERT_HIGH_THRESHOLD = 10

CANON_FIELDS = [
    "Application Name",
    "Application ID",
    "Custom Severity Name",
    "CVE ID",
    "CWE ID",
    "Flaw Name",
    "First Found Date",
    "Filename/Class",
    "Finding Status",
    "Fixed Date",
    "Team Name",
    "Days to Resolve",
    "Scan Type",
    "Description",
    "Scanner Link",
    "Finding UID",
    "Issue ID",
    "Sandbox Name",
]

# Accept canonical names plus common variants. Keys are normalized
# (lowercased, non-alphanumeric characters removed) header names.
FIELD_ALIASES = {
    "applicationname": "Application Name",
    "application": "Application Name",
    "applicationnameid": "Application Name",
    "appname": "Application Name",
    "applicationid": "Application ID",
    "appid": "Application ID",
    "customseverityname": "Custom Severity Name",
    "customseverity": "Custom Severity Name",
    "severity": "Custom Severity Name",
    "severityname": "Custom Severity Name",
    "cveid": "CVE ID",
    "cve": "CVE ID",
    "cweid": "CWE ID",
    "cwe": "CWE ID",
    "flawname": "Flaw Name",
    "vulnerabilitytitle": "Flaw Name",
    "title": "Flaw Name",
    "firstfounddate": "First Found Date",
    "founddate": "First Found Date",
    "filenameclass": "Filename/Class",
    "filename": "Filename/Class",
    "filepath": "Filename/Class",
    "sourcefile": "Filename/Class",
    "findingstatus": "Finding Status",
    "status": "Finding Status",
    "resolutionstatus": "Finding Status",
    "fixeddate": "Fixed Date",
    "resolutiondate": "Fixed Date",
    "teamname": "Team Name",
    "team": "Team Name",
    "businessunit": "Team Name",
    "daystoresolve": "Days to Resolve",
    "scantype": "Scan Type",
    "analysistype": "Scan Type",
    "description": "Description",
    "scannerlink": "Scanner Link",
    "findinguid": "Finding UID",
    "issueid": "Issue ID",
    "sandboxname": "Sandbox Name",
}


def canon_key(text):
    """Normalize a header/field name to lowercase alphanumerics."""
    return "".join(ch.lower() for ch in str(text) if ch.isalnum())


def clean(value):
    """Return a trimmed string; never None."""
    if value is None:
        return ""
    return str(value).strip()


def esc(value):
    """HTML-escape user-supplied data."""
    return html.escape(clean(value), quote=True)


def to_int(value, default=0):
    """Best-effort integer parse (handles '12', '12.0', 'level 12')."""
    s = clean(value)
    if not s:
        return default
    digits = ""
    for ch in s:
        if ch.isdigit() or (ch == "-" and not digits):
            digits += ch
        elif digits:
            break
    try:
        return int(digits)
    except (ValueError, TypeError):
        return default


# --------------------------------------------------------------------------
# Input loading
# --------------------------------------------------------------------------

def _pick(obj, keys, default=""):
    """Return first present/non-empty value for a list of dot-path keys."""
    for key in keys:
        cur = obj
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None and str(cur).strip() != "":
            return cur
    return default


def normalize_alert(raw):
    """Normalize one Wazuh alert dict. Returns None when unusable."""
    if not isinstance(raw, dict):
        return None
    description = clean(_pick(raw, ["rule.description", "rule.title", "description", "rule"]))
    level = to_int(_pick(raw, ["rule.level", "level", "severity"]), 0)
    if not description and level == 0:
        return None
    agent_raw = _pick(raw, ["agent.name", "agent", "agent_name", "hostname"], "")
    if isinstance(agent_raw, dict):
        agent_raw = _pick(agent_raw, ["name", "id", "host"], "")
    return {
        "timestamp": clean(_pick(raw, ["timestamp", "@timestamp", "time", "date"])),
        "level": level,
        "description": description or "(unspecified rule)",
        "agent": clean(agent_raw) or "(unknown agent)",
        "srcip": clean(_pick(raw, ["srcip", "src_ip", "source_ip", "srcip"])),
        "location": clean(_pick(raw, ["location", "full_log", "log"])),
    }


def load_alerts(path):
    """Load a JSON array, a wrapped JSON object, or JSONL from *path*.

    Returns (alerts, skipped_count).
    """
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    raw_items = []
    stripped = text.strip()
    if stripped:
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                raw_items = parsed
            elif isinstance(parsed, dict):
                for key in ("alerts", "results", "hits", "data"):
                    if isinstance(parsed.get(key), list):
                        raw_items = parsed[key]
                        break
                else:
                    raw_items = [parsed]
            else:
                raw_items = []
        except (ValueError, json.JSONDecodeError):
            for line in stripped.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_items.append(json.loads(line))
                except (ValueError, json.JSONDecodeError):
                    raw_items.append(None)

    alerts = []
    skipped = 0
    for item in raw_items:
        norm = normalize_alert(item)
        if norm is None:
            skipped += 1
        else:
            alerts.append(norm)
    return alerts, skipped


def normalize_finding(row):
    """Normalize a csv.DictReader row into the canonical vocabulary."""
    normalized = {field: "" for field in CANON_FIELDS}
    for raw_header, value in row.items():
        if raw_header is None:
            continue
        canonical = FIELD_ALIASES.get(canon_key(raw_header))
        val = clean(value)
        if canonical and (not normalized[canonical] or val):
            if not normalized[canonical]:
                normalized[canonical] = val
    normalized["Application Name"] = normalized["Application Name"] or "(unknown application)"
    cwe = normalized["CWE ID"]
    if cwe and not cwe.lower().startswith("cwe-") and cwe.isdigit():
        normalized["CWE ID"] = "CWE-" + cwe
    return normalized


def load_findings(path):
    """Load a scanner findings CSV. Returns (findings, skipped_count)."""
    findings = []
    skipped = 0
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return [], 0
        for row in reader:
            if row is None or not any(clean(v) for v in row.values()):
                skipped += 1
                continue
            findings.append(normalize_finding(row))
    return findings, skipped


# --------------------------------------------------------------------------
# Classification / statistics
# --------------------------------------------------------------------------

CRITICAL_WORDS = ("critical", "very high", "veryhigh", "5")


def severity_label(value):
    """Map a raw severity value (name or 0-5) to a display bucket."""
    s = clean(value).lower()
    if not s:
        return "Unknown"
    if "critical" in s:
        return "Critical"
    if "very high" in s or "veryhigh" in s or s == "5":
        return "Very High"
    if s == "4" or "high" in s:
        return "High"
    if s == "3" or "medium" in s:
        return "Medium"
    if s == "2" or "low" in s:
        return "Low"
    if s == "1" or "very low" in s or "verylow" in s:
        return "Very Low"
    if s == "0" or "information" in s:
        return "Informational"
    return "Unknown"


def is_critical_finding(finding):
    return severity_label(finding.get("Custom Severity Name", "")) in ("Critical", "Very High")


def alert_bucket(level):
    if level <= 3:
        return "Low (0-3)"
    if level <= 6:
        return "Medium (4-6)"
    if level <= 9:
        return "High (7-9)"
    return "Critical (10+)"


def compute_stats(alerts, findings, alerts_skipped, findings_skipped, alerts_path, findings_path):
    alert_levels = Counter(alert_bucket(a["level"]) for a in alerts)
    finding_sevs = Counter(severity_label(f.get("Custom Severity Name", "")) for f in findings)
    top_rules = Counter(a["description"] for a in alerts)
    top_apps = Counter(f["Application Name"] for f in findings)
    top_cwes = Counter(f["CWE ID"] for f in findings if f["CWE ID"])

    recent_alerts = sorted(alerts, key=lambda a: a["timestamp"], reverse=True)[:10]
    recent_findings = sorted(
        findings, key=lambda f: f["First Found Date"], reverse=True
    )[:10]

    return {
        "total_alerts": len(alerts),
        "high_alerts": sum(1 for a in alerts if a["level"] >= ALERT_HIGH_THRESHOLD),
        "total_findings": len(findings),
        "critical_findings": sum(1 for f in findings if is_critical_finding(f)),
        "alert_levels": alert_levels,
        "finding_sevs": finding_sevs,
        "top_rules": top_rules,
        "top_apps": top_apps,
        "top_cwes": top_cwes,
        "recent_alerts": recent_alerts,
        "recent_findings": recent_findings,
        "alerts_skipped": alerts_skipped,
        "findings_skipped": findings_skipped,
        "alerts_path": os.path.basename(str(alerts_path)),
        "findings_path": os.path.basename(str(findings_path)),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# --------------------------------------------------------------------------
# HTML rendering
# --------------------------------------------------------------------------

CSS = """
:root {
  --bg: #0b0f16;
  --panel: #141b26;
  --panel-2: #1b2432;
  --border: #2a3646;
  --text: #d7e0ec;
  --muted: #8b9bb0;
  --accent: #4cc2ff;
  --critical: #f85149;
  --high: #ff7b72;
  --medium: #d29922;
  --low: #3fb950;
  --info: #58a6ff;
  --unknown: #788696;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 14px; line-height: 1.5;
}
.wrap { max-width: 1240px; margin: 0 auto; padding: 32px 24px 64px; }
header h1 { margin: 0 0 4px; font-size: 26px; letter-spacing: .3px; }
header .sub { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
h2 { font-size: 17px; margin: 0 0 14px; border-left: 3px solid var(--accent); padding-left: 10px; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .6px; }
.card .value { font-size: 32px; font-weight: 700; margin-top: 6px; }
.card.c-alerts .value { color: var(--info); }
.card.c-high .value { color: var(--high); }
.card.c-findings .value { color: var(--accent); }
.card.c-critical .value { color: var(--critical); }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 28px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
.bar-row { display: grid; grid-template-columns: 120px 1fr 44px; align-items: center; gap: 10px; margin: 8px 0; }
.bar-label { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-track { background: var(--panel-2); border-radius: 4px; height: 16px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; min-width: 2px; }
.bar-value { text-align: right; font-variant-numeric: tabular-nums; font-size: 12px; }
.sev-critical, .sev-10 { background: var(--critical); }
.sev-high, .sev-4 { background: var(--high); }
.sev-7 { background: #ffa657; }
.sev-medium, .sev-3 { background: var(--medium); }
.sev-low, .sev-2 { background: var(--low); }
.sev-0 { background: var(--info); }
.sev-unknown { background: var(--unknown); }
.rank-list { list-style: none; margin: 0; padding: 0; }
.rank-list li { display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-bottom: 1px solid var(--border); }
.rank-list li:last-child { border-bottom: none; }
.rank-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rank-count { color: var(--accent); font-variant-numeric: tabular-nums; font-weight: 600; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; background: var(--panel-2); position: sticky; top: 0; }
tbody tr:nth-child(even) { background: rgba(255,255,255,.02); }
.scroll { max-height: 360px; overflow: auto; border: 1px solid var(--border); border-radius: 6px; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; background: var(--panel-2); }
.pill.critical { color: var(--critical); }
.pill.high { color: var(--high); }
.pill.medium { color: var(--medium); }
.pill.low { color: var(--low); }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.note { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--medium); border-radius: 8px; padding: 16px 18px; color: var(--muted); font-size: 12.5px; }
.note strong { color: var(--text); }
.note p { margin: 6px 0; }
footer { margin-top: 24px; color: var(--muted); font-size: 11px; text-align: center; }
@media (max-width: 900px) { .cards { grid-template-columns: repeat(2, 1fr); } .grid2 { grid-template-columns: 1fr; } }
"""

JS = """
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.pill').forEach(function (p) {
    if (p.dataset.toggle === '1') {
      p.style.cursor = 'pointer';
      p.addEventListener('click', function () {
        var row = p.closest('tr');
        var detail = row ? row.nextElementSibling : null;
        if (detail && detail.classList.contains('detail-row')) {
          detail.style.display = (detail.style.display === 'none') ? '' : 'none';
        }
      });
    }
  });
});
"""


def card(label, value, css):
    return (
        '<div class="card %s"><div class="label">%s</div>'
        '<div class="value">%s</div></div>' % (css, esc(label), esc(value))
    )


def bar_section(pairs):
    """pairs: list of (label, count, css_class)."""
    if not pairs:
        return '<p style="color:var(--muted)">No data available.</p>'
    maximum = max(count for _, count, _ in pairs) or 1
    out = []
    for label, count, css in pairs:
        width = round(count * 100.0 / maximum, 2)
        out.append(
            '<div class="bar-row"><div class="bar-label" title="%s">%s</div>'
            '<div class="bar-track"><div class="bar-fill %s" style="width:%s%%"></div></div>'
            '<div class="bar-value">%d</div></div>'
            % (esc(label), esc(label), css, width, count)
        )
    return "".join(out)


ALERT_BUCKET_CSS = {
    "Low (0-3)": "sev-0",
    "Medium (4-6)": "sev-medium",
    "High (7-9)": "sev-7",
    "Critical (10+)": "sev-critical",
}
FINDING_SEV_CSS = {
    "Critical": "sev-critical",
    "Very High": "sev-high",
    "High": "sev-high",
    "Medium": "sev-medium",
    "Low": "sev-low",
    "Very Low": "sev-2",
    "Informational": "sev-0",
    "Unknown": "sev-unknown",
}


def rank_section(counter, limit=8):
    if not counter:
        return '<p style="color:var(--muted)">No data available.</p>'
    out = ['<ul class="rank-list">']
    for name, count in counter.most_common(limit):
        out.append(
            '<li><span class="rank-name" title="%s">%s</span>'
            '<span class="rank-count">%d</span></li>' % (esc(name), esc(name), count)
        )
    out.append("</ul>")
    return "".join(out)


def sev_pill(label):
    key = label.lower().replace(" ", "-")
    return '<span class="pill %s">%s</span>' % (key, esc(label))


def alerts_table(alerts):
    if not alerts:
        return '<p style="color:var(--muted)">No recent alerts.</p>'
    out = [
        '<div class="scroll"><table><thead><tr>'
        '<th>Timestamp</th><th>Level</th><th>Rule</th>'
        '<th>Agent</th><th>Source IP</th><th>Location</th>'
        '</tr></thead><tbody>'
    ]
    for a in alerts:
        out.append(
            "<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td class=\"mono\">%s</td><td>%s</td></tr>"
            % (
                esc(a["timestamp"]) or "-",
                esc(a["level"]),
                esc(a["description"]),
                esc(a["agent"]),
                esc(a["srcip"]) or "-",
                esc(a["location"]) or "-",
            )
        )
    out.append("</tbody></table></div>")
    return "".join(out)


def findings_table(findings):
    if not findings:
        return '<p style="color:var(--muted)">No recent findings.</p>'
    out = [
        '<div class="scroll"><table><thead><tr>'
        '<th>Application</th><th>Severity</th><th>CWE</th><th>Flaw Name</th>'
        '<th>First Found</th><th>Status</th><th>Filename/Class</th>'
        '</tr></thead><tbody>'
    ]
    for f in findings:
        label = severity_label(f.get("Custom Severity Name", ""))
        out.append(
            "<tr><td>%s</td><td>%s</td><td class=\"mono\">%s</td><td>%s</td>"
            "<td class=\"mono\">%s</td><td>%s</td><td class=\"mono\">%s</td></tr>"
            % (
                esc(f["Application Name"]),
                sev_pill(label),
                esc(f["CWE ID"]) or "-",
                esc(f["Flaw Name"]) or "-",
                esc(f["First Found Date"]) or "-",
                esc(f["Finding Status"]) or "-",
                esc(f["Filename/Class"]) or "-",
            )
        )
    out.append("</tbody></table></div>")
    return "".join(out)


def render_html(stats, title):
    alert_pairs = [
        (label, stats["alert_levels"].get(label, 0), ALERT_BUCKET_CSS.get(label, "sev-unknown"))
        for label in ["Low (0-3)", "Medium (4-6)", "High (7-9)", "Critical (10+)"]
    ]
    finding_pairs = [
        (label, stats["finding_sevs"].get(label, 0), FINDING_SEV_CSS.get(label, "sev-unknown"))
        for label in ["Critical", "Very High", "High", "Medium", "Low", "Very Low", "Informational", "Unknown"]
        if stats["finding_sevs"].get(label, 0) > 0
    ]

    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<title>%s</title>" % esc(title))
    parts.append("<style>%s</style>" % CSS)
    parts.append("</head><body><div class=\"wrap\">")
    parts.append(
        '<header><h1>%s</h1><div class="sub">SOC merged dashboard '
        '&middot; generated %s</div></header>' % (esc(title), esc(stats["generated"]))
    )

    parts.append("<h2>Executive Summary</h2>")
    parts.append('<div class="cards">')
    parts.append(card("Total Alerts", stats["total_alerts"], "c-alerts"))
    parts.append(card("High-Severity Alerts", stats["high_alerts"], "c-high"))
    parts.append(card("Total Findings", stats["total_findings"], "c-findings"))
    parts.append(card("Critical Findings", stats["critical_findings"], "c-critical"))
    parts.append("</div>")

    parts.append('<div class="grid2">')
    parts.append('<section class="panel"><h2>Severity Distribution - Wazuh Alerts</h2>%s</section>' % bar_section(alert_pairs))
    parts.append('<section class="panel"><h2>Severity Distribution - Scanner Findings</h2>%s</section>' % bar_section(finding_pairs))
    parts.append("</div>")

    parts.append('<div class="grid2">')
    parts.append('<section class="panel"><h2>Top Triggered Rules</h2>%s</section>' % rank_section(stats["top_rules"]))
    parts.append('<section class="panel"><h2>Top Affected Applications</h2>%s</section>' % rank_section(stats["top_apps"]))
    parts.append("</div>")

    parts.append('<section class="panel" style="margin-bottom:28px"><h2>Top CWEs</h2>%s</section>' % rank_section(stats["top_cwes"]))

    parts.append('<section class="panel" style="margin-bottom:28px"><h2>Recent Alerts</h2>%s</section>' % alerts_table(stats["recent_alerts"]))
    parts.append('<section class="panel" style="margin-bottom:28px"><h2>Recent Findings</h2>%s</section>' % findings_table(stats["recent_findings"]))

    parts.append('<section class="note"><h2 style="border:none;padding:0;margin-bottom:8px">Data Provenance and Disclaimer</h2>')
    parts.append(
        "<p><strong>Sources.</strong> Wazuh alerts: %s (%d valid, %d skipped/malformed). "
        "scanner findings: %s (%d valid, %d skipped/malformed).</p>"
        % (
            esc(stats["alerts_path"]), stats["total_alerts"], stats["alerts_skipped"],
            esc(stats["findings_path"]), stats["total_findings"], stats["findings_skipped"],
        )
    )
    parts.append(
        "<p><strong>Generation.</strong> Produced locally on %s by dashboard.py using only "
        "the Python standard library. This is a single self-contained HTML file with inline "
        "CSS/JS and no external or CDN assets.</p>" % esc(stats["generated"])
    )
    parts.append(
        "<p><strong>Interpretation.</strong> This report is an unofficial aggregation for SOC "
        "triage and is not an official Scanner product. Severities, levels, and counts reflect "
        "the supplied exports at the time of generation and are evidence for review, not a verdict. "
        'A Wazuh level of %d or higher is counted as a high-severity alert. "Critical findings" '
        "means Very High or Critical severity. Verify all items against the source systems before "
        "taking action.</p>" % ALERT_HIGH_THRESHOLD
    )
    parts.append("</section>")

    parts.append('<footer>Local SOC dashboard &middot; %s</footer>' % esc(stats["generated"]))
    parts.append("</div><script>%s</script></body></html>" % JS)
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Demo data
# --------------------------------------------------------------------------

DEMO_RULES = [
    (15, "SSH authentication failure", "sshd"),
    (12, "Multiple web attacks detected", "web-01"),
    (10, "Suspicious process spawned", "win-wks-14"),
    (7, "File integrity monitoring alert", "web-01"),
    (5, "Windows event log cleared", "win-wks-07"),
    (3, "New firewall rule added", "fw-edge"),
    (13, "Rootkit behavior detected", "db-prod-02"),
    (9, "VirusTotal malicious hash match", "win-wks-14"),
]

DEMO_APPS = [
    "Payments API", "Customer Portal", "Identity Service", "Reporting Engine", "Mobile Backend"
]
DEMO_SEVERITIES = ["Very High", "High", "Medium", "Low", "Informational"]
DEMO_CWES = ["CWE-79", "CWE-89", "CWE-22", "CWE-287", "CWE-416", "CWE-200"]
DEMO_FLAWS = [
    "Cross-site Scripting", "SQL Injection", "Path Traversal",
    "Improper Authentication", "Use After Free", "Information Exposure",
]


def generate_demo():
    """Write synthetic sample inputs under sample/ and return their paths."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    alerts = []
    base_day = datetime(2026, 11, 10, 8, 0, 0)
    for i in range(24):
        level, desc, agent = DEMO_RULES[i % len(DEMO_RULES)]
        ts = base_day.replace(hour=8 + (i % 10)) .strftime("%Y-%m-%dT%H:%M:%S+00:00")
        alerts.append({
            "timestamp": ts,
            "rule": {"level": level, "description": desc},
            "agent": {"name": agent},
            "srcip": "203.0.113.%d" % (10 + i),
            "location": "%s:/var/log/auth.log" % agent,
        })
    # Two malformed rows to demonstrate graceful handling.
    alerts.append({"rule": {}, "agent": {}})
    alerts.append("this is not an alert object")
    (SAMPLE_DIR / "alerts.json").write_text(
        json.dumps(alerts, indent=2), encoding="utf-8"
    )

    # Deliberately use common variants in the header to prove normalization:
    # Application, Severity, CWE instead of the canonical names.
    header = [
        "Application", "Application ID", "Severity", "CVE ID", "CWE ID".replace("CWE ID", "CWE"),
        "Flaw Name", "First Found Date", "Filename/Class", "Finding Status",
        "Fixed Date", "Team Name", "Days to Resolve", "Scan Type", "Description",
    ]
    rows = []
    for i in range(30):
        sev = DEMO_SEVERITIES[i % len(DEMO_SEVERITIES)]
        app = DEMO_APPS[i % len(DEMO_APPS)]
        cwe = DEMO_CWES[i % len(DEMO_CWES)]
        flaw = DEMO_FLAWS[DEMO_CWES.index(cwe)]
        found = (base_day.replace(day=10 + (i % 7))).strftime("%Y-%m-%d %H:%M:%S")
        rows.append([
            app, str(1000 + i), sev,
            "CVE-2026-%04d" % (1000 + i), cwe, flaw, found,
            "src/main/Service%d.java:%d" % (i, 40 + i),
            "OPEN" if i % 5 else "CLOSED",
            "" if i % 5 else "2026-11-15 09:00:00",
            "AppSec Team %d" % (i % 3 + 1),
            "" if i % 5 else "5",
            "STATIC",
            "Sample finding %d for demonstration purposes." % i,
        ])
    path = SAMPLE_DIR / "findings.csv"
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)

    return SAMPLE_DIR / "alerts.json", path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build(alerts_path, findings_path, out_path, title):
    alerts, a_skip = load_alerts(alerts_path)
    findings, f_skip = load_findings(findings_path)
    stats = compute_stats(alerts, findings, a_skip, f_skip, alerts_path, findings_path)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(stats, title), encoding="utf-8")
    return stats, out_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a self-contained SOC HTML dashboard."
    )
    parser.add_argument("--alerts", help="Wazuh alerts JSON array or JSONL file")
    parser.add_argument("--findings", help="scanner findings CSV file")
    parser.add_argument("--out", help="Output HTML file path")
    parser.add_argument("--title", default="SOC Dashboard", help="Report title")
    parser.add_argument(
        "--demo", action="store_true",
        help="Generate synthetic sample data under sample/ and build a demo report",
    )
    args = parser.parse_args(argv)

    if args.demo:
        alerts_path, findings_path = generate_demo()
        out_path = Path(args.out) if args.out else SAMPLE_DIR / "report.html"
        print("Demo inputs generated: %s , %s" % (alerts_path, findings_path))
    else:
        if not (args.alerts and args.findings and args.out):
            parser.error("--alerts, --findings and --out are required unless --demo is used")
        alerts_path, findings_path, out_path = args.alerts, args.findings, args.out

    stats, out_path = build(alerts_path, findings_path, out_path, args.title)
    print("Wrote %s (%d bytes)" % (out_path, out_path.stat().st_size))
    print(
        "Alerts: %d valid (%d skipped) | Findings: %d valid (%d skipped) | "
        "High alerts: %d | Critical findings: %d"
        % (
            stats["total_alerts"], stats["alerts_skipped"],
            stats["total_findings"], stats["findings_skipped"],
            stats["high_alerts"], stats["critical_findings"],
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
