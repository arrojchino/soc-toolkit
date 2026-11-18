# repo_search.py

A local, dependency-free search CLI over the 55-repo GitHub knowledge base
(`delriscotechnologies` and `ancient-cthulhu`). Uses only the Python standard
library. Data is read from:

- `C:/Users/Garza/github-repos-knowledge/INDEX.md`
- `C:/Users/Garza/github-repos-knowledge/meta.json`
- `C:/Users/Garza/github-repos-knowledge/summaries/*.md`
- `C:/Users/Garza/github-repos-knowledge/raw/*.md`

Set `REPO_SEARCH_KB` to use a different knowledge-base root. If the summary
files are missing, the installed skill's `references/*.md` are used instead.

## Requirements

Python 3.8+ (tested with 3.14.9). SQLite FTS5 is used when available; if the
SQLite build lacks FTS5, the tool automatically falls back to Python substring
scoring. Search is case-insensitive and supports multi-word queries.

## Build the index

```bash
cd C:/Users/Garza/soc-projects/repo-search
python repo_search.py index
```

Creates `index.db` next to the script. Re-running rebuilds it from scratch.

## Search

Ranked results show the repo, account, absolute source path, and a snippet with
matched terms wrapped in `[brackets]`.

```bash
python repo_search.py search phishfry
python repo_search.py search ruletrace
python repo_search.py search "active directory" --limit 5
```

A word containing punctuation is tokenized as a phrase: `ruletrace` matches
text containing `ruletrace` (the FTS tokenizer splits on the dot). Multiple
words are OR-ed and ranked by relevance, so documents matching more terms rank
higher.

## Show a repo

Prints the repo metadata, its raw README, and the matching section(s) from the
summary files.

```bash
python repo_search.py show redline
python repo_search.py show delriscotechnologies/phishfry
python repo_search.py show phishfry
```

## List the inventory

```bash
python repo_search.py list
python repo_search.py list --account delriscotechnologies
python repo_search.py list --account ancient-cthulhu
```

Output: owner, repo, language, stars, and description from `meta.json`.

## Cross-cutting themes

```bash
python repo_search.py themes
```

Prints every `## Cross-cutting themes` section found in the summary files.

## Implementation notes

- The `documents` table stores path, repo, account, source, title, and full text
  for every indexed source (INDEX.md, one row per meta.json repo, each summary,
  each raw README).
- `documents_fts` is an FTS5 external-content index over those rows with the
  `unicode61` tokenizer; `bm25()` ranking and `snippet()` highlighting are used.
- A `meta` table records schema version, backend, document count, KB root, and
  index timestamp so search can degrade gracefully when FTS5 is unavailable.
