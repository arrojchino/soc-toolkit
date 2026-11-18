# SOC / Veracode projects

Built from the knowledge base of the delriscotechnologies and ancient-cthulhu GitHub accounts.
All tools are local, stdlib-only Python 3.14, read-only, and emit no emojis.

## 1. soc-dashboard
Merge Wazuh alerts (JSON/JSONL) with Veracode findings CSV into one self-contained HTML report.
- Run: `python dashboard.py --demo`
- Run: `python dashboard.py --alerts sample/alerts.json --findings sample/veracode_findings.csv --out sample/report.html`
- Artifact: `sample/report.html` (15,980 bytes, 12/12 sections verified)

## 2. repo-search
SQLite FTS5 search over the 55-repo knowledge base, with fallback substring scoring.
- Run: `python repo_search.py index`
- Run: `python repo_search.py search phishfry`
- Run: `python repo_search.py show redline`
- Artifact: `index.db` (117 documents indexed)

## 3. toolkit
Read-only local SOC CLI: analyze-eml, connections, firewall-rules, normalize-findings, verify-trace.
- Run: `python toolkit.py --help`
- Run: `python toolkit.py analyze-eml sample/sample.eml`
- Run: `python toolkit.py normalize-findings sample/findings.csv --out sample/normalized.csv`
- Run: `python toolkit.py verify-trace sample/trace.json`

## 4. rea-forensics
Consume REA plugin analysis JSON, hash each artifact with SHA-256, emit a forensic HTML report and evidence manifest.
- Run: `python pipeline.py --demo`
- Run: `python pipeline.py --analysis FILE --artifacts DIR --out report.html --manifest manifest.csv`
- Artifacts: `report.html` (7,379 bytes), `manifest.csv` (294 bytes)
- Handoff: export REA JSON from Hermes next session, then feed it to this pipeline.
