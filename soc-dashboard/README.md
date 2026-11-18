# SOC Dashboard

A local, single-file HTML dashboard that merges Wazuh alert exports with
scanner findings CSV exports. Python standard library only - no pip installs,
no CDN, no external assets. The report is fully self-contained (inline CSS/JS)
and uses a professional dark aesthetic.

## Requirements

- Python 3.x (tested on Python 3.14.9, Windows 11 / git-bash)
- No external packages. See `requirements.txt`.

## Usage

Build a report from your own exports:

```bash
python dashboard.py --alerts ALERTS.json --findings FINDINGS.csv --out report.html
```

With an optional custom title:

```bash
python dashboard.py --alerts ALERTS.json --findings FINDINGS.csv --out report.html --title "Nightly SOC Review"
```

Generate synthetic sample data under `sample/` and build a demo report:

```bash
python dashboard.py --demo
```

The demo writes `sample/alerts.json`, `sample/findings.csv`, and
`sample/report.html`.

Rebuild the report from the generated samples (explicit paths):

```bash
python dashboard.py --alerts sample/alerts.json --findings sample/findings.csv --out sample/report.html
```

Run `python dashboard.py --help` for the full argument list.

## Input formats

### Wazuh alerts (`--alerts`)

A JSON array, a JSON object with an `alerts`/`results`/`hits`/`data` list, or
JSON Lines (one JSON object per line). Recognized fields (all optional):

- `rule.level`, `rule.description` (also `rule.title`, `description`)
- `agent.name` (also `agent`, `agent_name`, `hostname`)
- `timestamp` (also `@timestamp`, `time`, `date`)
- `srcip` (also `src_ip`, `source_ip`)
- `location`

A row with neither a rule description nor a level is skipped and counted as
malformed.

### scanner findings (`--findings`)

A CSV export with a header row. The canonical Scanner vocabulary is accepted:

`Application Name`, `Application ID`, `Custom Severity Name`, `CVE ID`,
`CWE ID`, `Flaw Name`, `First Found Date`, `Filename/Class`,
`Finding Status`, `Fixed Date`, `Team Name`, `Days to Resolve`, `Scan Type`.

Common variants are normalized automatically, including:

- `Severity` or `Custom Severity` -> `Custom Severity Name`
- `CWE` -> `CWE ID` (numeric values become `CWE-<n>`)
- `Application` -> `Application Name`
- `Status` -> `Finding Status`, `Team` -> `Team Name`
- `CVE` -> `CVE ID`, `Filename` / `File Path` -> `Filename/Class`

Blank or all-empty rows are skipped gracefully and reported in the
provenance note.

## Report sections

- Summary cards: total alerts, high-severity alerts, total findings, critical findings
- Severity Distribution bars for Wazuh alerts (by rule level) and scanner findings (by severity)
- Top Triggered Rules
- Top Affected Applications
- Top CWEs
- Recent Alerts table
- Recent Findings table
- Data Provenance and Disclaimer note

A Wazuh rule level of 10 or higher counts as a high-severity alert; a finding
with severity "Very High" or "Critical" counts as critical. These thresholds
are constants at the top of `dashboard.py`.

## Disclaimer

This is an unofficial aggregation tool for SOC triage, not an official
Scanner product. Counts and severities reflect the supplied exports at
generation time and are evidence for review, not a verdict. Verify findings
against the source systems before acting.
