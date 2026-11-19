# Local Security Toolkit

Index of the local-first security tools: finding ledger, SOC checks, knowledge
search, evidence handling and dashboards.

Live: https://arrojchino.github.io/soc-toolkit/

## Tools

- **Signal** — local-first finding ledger with stable fingerprints, verification
  states, hashed evidence, HTML report and SARIF output.
- **Sentinel** — one read-only CLI for 69 focused security checks grouped by
  team, with a JSON envelope and CI exit-code gate.
- **Atlas** — dependency-free search over the 55-repo security knowledge base,
  with SQLite FTS5 ranking and a Python fallback.
- **Ward** — read-only local SOC utilities: EML triage, connections, firewall
  rules, scanner findings normalization and tool-trace consistency.
- **Trace** — evidence reports from a REA JSON analysis, with a hashed custody
  ledger and a self-contained HTML report.
- **Burn** — a minimal appsec dashboard with session timer, severity counts,
  triage flow and a findings table.
- **Balling** — a Three.js sculpture generated from an ASCII silhouette.

All tools are stdlib-first, local-only and read-only. They organize evidence and
make claims checkable; they do not scan, exploit or contact a network.
