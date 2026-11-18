#!/usr/bin/env python3
"""Local search CLI over the 55-repo GitHub knowledge base (stdlib only).

Data sources (default: C:/Users/Garza/github-repos-knowledge):
  INDEX.md, meta.json, summaries/*.md, raw/*.md
Override the knowledge-base root with the REPO_SEARCH_KB environment variable.

Commands:
  index                  build/update index.db (SQLite FTS5, with fallback)
  search QUERY           ranked results with highlighted snippets
  show REPO_NAME         relevant raw README + summary sections for a repo
  list [--account ...]   inventory from meta.json
  themes                 cross-cutting themes from all summary files
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = PROJECT_DIR / "index.db"
KB_ROOT = Path(os.environ.get("REPO_SEARCH_KB", "C:/Users/Garza/github-repos-knowledge"))
SKILL_REF = Path(
    "C:/Users/Garza/AppData/Local/hermes/skills/research/"
    "github-repos-knowledge/references"
)
SCHEMA_VERSION = "1"
HIGHLIGHT_OPEN = "["
HIGHLIGHT_CLOSE = "]"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def summary_files() -> list[Path]:
    """Summaries from the knowledge base, falling back to the installed skill."""
    files = sorted((KB_ROOT / "summaries").glob("*.md"))
    if not files and SKILL_REF.is_dir():
        files = sorted(SKILL_REF.glob("*.md"))
    return files


def account_for_summary(stem: str) -> str:
    s = stem.lower()
    if s.startswith("delrisco"):
        return "delriscotechnologies"
    if s.startswith("veracode"):
        return "ancient-cthulhu"
    return "mixed"


def collect_documents() -> list[dict]:
    """Return one document row per source file / meta entry."""
    docs: list[dict] = []

    index_md = KB_ROOT / "INDEX.md"
    if index_md.is_file():
        docs.append(
            {
                "path": str(index_md),
                "repo": "INDEX",
                "account": "all",
                "source": "index",
                "title": "Knowledge base inventory (INDEX.md)",
                "text": read_text(index_md),
            }
        )

    meta_path = KB_ROOT / "meta.json"
    meta_rows = []
    if meta_path.is_file():
        import json

        meta_rows = json.loads(read_text(meta_path))
        for rec in meta_rows:
            desc = rec.get("description") or "no description"
            text = (
                f"{rec.get('full_name', '')} - {desc}\n"
                f"Language: {rec.get('language') or 'n/a'}; "
                f"Stars: {rec.get('stars', 0)}; Fork: {rec.get('fork', False)}; "
                f"Default branch: {rec.get('default_branch', '')}; "
                f"Readme: {rec.get('readme', '')}; "
                f"Size KB: {rec.get('size_kb', '')}; "
                f"Updated: {rec.get('updated_at', '')}"
            )
            docs.append(
                {
                    "path": str(meta_path),
                    "repo": rec.get("name", ""),
                    "account": rec.get("owner", ""),
                    "source": "meta",
                    "title": rec.get("full_name", ""),
                    "text": text,
                }
            )

    for path in summary_files():
        text = read_text(path)
        docs.append(
            {
                "path": str(path),
                "repo": path.stem,
                "account": account_for_summary(path.stem),
                "source": "summary",
                "title": f"Summary: {path.stem}",
                "text": text,
            }
        )

    raw_dir = KB_ROOT / "raw"
    if raw_dir.is_dir():
        for path in sorted(raw_dir.glob("*.md")):
            stem = path.stem
            if "__" in stem:
                account, repo = stem.split("__", 1)
            else:
                account, repo = "unknown", stem
            docs.append(
                {
                    "path": str(path),
                    "repo": repo,
                    "account": account,
                    "source": "raw",
                    "title": f"{account}/{repo}",
                    "text": read_text(path),
                }
            )

    return docs


def connect() -> sqlite3.Connection:
    if not DB_PATH.is_file():
        raise SystemExit(
            f"No index at {DB_PATH}. Run: python repo_search.py index"
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_meta(conn: sqlite3.Connection) -> dict:
    try:
        return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}
    except sqlite3.Error:
        return {}


def fts_available(conn: sqlite3.Connection) -> bool:
    if db_meta(conn).get("fts_available") == "0":
        return False
    try:
        conn.execute("SELECT rowid FROM documents_fts LIMIT 0").fetchall()
        return True
    except sqlite3.Error:
        return False


# --------------------------------------------------------------------------
# index
# --------------------------------------------------------------------------
def cmd_index(_args: argparse.Namespace) -> None:
    docs = collect_documents()
    if not docs:
        raise SystemExit(f"No source documents found under {KB_ROOT}")

    # Rebuild from scratch; remove stray WAL/SHM files too.
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            (PROJECT_DIR / ("index.db" + suffix)).unlink()
        except FileNotFoundError:
            pass

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """CREATE TABLE documents (
                   id INTEGER PRIMARY KEY,
                   path TEXT NOT NULL,
                   repo TEXT,
                   account TEXT,
                   source TEXT,
                   title TEXT,
                   text TEXT NOT NULL
               )"""
        )
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.executemany(
            "INSERT INTO documents(path, repo, account, source, title, text) "
            "VALUES (:path, :repo, :account, :source, :title, :text)",
            docs,
        )

        fts_ok = True
        try:
            conn.execute(
                """CREATE VIRTUAL TABLE documents_fts USING fts5(
                       path, repo, account, title, text,
                       content='documents', content_rowid='id',
                       tokenize='unicode61 remove_diacritics 2'
                   )"""
            )
            conn.executemany(
                "INSERT INTO documents_fts(rowid, path, repo, account, title, text) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (i + 1, d["path"], d["repo"], d["account"], d["title"], d["text"])
                    for i, d in enumerate(docs)
                ],
            )
        except sqlite3.Error as exc:  # FTS5 missing/broken -> Python fallback
            fts_ok = False
            print(f"warning: FTS5 unavailable ({exc}); using substring fallback")

        import datetime

        conn.executemany(
            "INSERT INTO meta(key, value) VALUES (?, ?)",
            [
                ("schema_version", SCHEMA_VERSION),
                ("fts_available", "1" if fts_ok else "0"),
                ("doc_count", str(len(docs))),
                ("kb_root", str(KB_ROOT)),
                ("indexed_at", datetime.datetime.now().isoformat(timespec="seconds")),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    print(f"Indexed {len(docs)} documents into {DB_PATH}")
    print(f"  sources: {KB_ROOT}")
    print(f"  backend: {'SQLite FTS5 (unicode61)' if fts_ok else 'Python substring fallback'}")


# --------------------------------------------------------------------------
# search
# --------------------------------------------------------------------------
def build_fts_query(query: str) -> str:
    """Turn user text into an OR query; punctuation inside a word becomes a phrase.

    'veracode.yml' -> '"veracode yml"' (the unicode61 tokenizer splits the dot)
    'phishfry eml' -> 'phishfry OR eml'
    """
    phrases = []
    for word in query.split():
        parts = re.findall(r"\w+", word, flags=re.UNICODE)
        if not parts:
            continue
        phrases.append(parts[0] if len(parts) == 1 else '"' + " ".join(parts) + '"')
    return " OR ".join(phrases)


def query_words(query: str) -> list[str]:
    return [w.lower() for w in re.findall(r"\w+", query, flags=re.UNICODE)]


def make_snippet(text: str, words: list[str], width: int = 220) -> str:
    """Fallback highlighter: window around the first hit, then bracket matches."""
    low = text.lower()
    hits = [low.find(w) for w in words if low.find(w) >= 0]
    start = max(0, min(hits) - width // 3) if hits else 0
    snippet = text[start : start + width].replace("\n", " ")
    if hits:
        pattern = "(" + "|".join(re.escape(w) for w in sorted(set(words), key=len, reverse=True)) + ")"
        snippet = re.sub(pattern, lambda m: HIGHLIGHT_OPEN + m.group(0) + HIGHLIGHT_CLOSE,
                         snippet, flags=re.IGNORECASE)
    prefix = "..." if start else ""
    suffix = "..." if start + width < len(text) else ""
    return prefix + snippet + suffix


def print_result(number: int, row: dict, score: float, words: list[str]) -> None:
    repo = row["repo"] or "-"
    account = row["account"] or "-"
    print(f"[{number}] {account}/{repo}   score={score:.3f}" if account != repo else f"[{number}] {repo}   score={score:.3f}")
    print(f"    source: {row['path']}  ({row['source']})")
    print(f"    {row['snippet']}")
    print()


def cmd_search(args: argparse.Namespace) -> None:
    query = " ".join(args.query).strip()
    if not query:
        raise SystemExit("search requires a non-empty query")
    conn = connect()
    try:
        backend = "fts5" if fts_available(conn) else "fallback"
        rows: list[dict] = []
        if backend == "fts5":
            fts_query = build_fts_query(query)
            if fts_query:
                sql = """
                    SELECT d.path, d.repo, d.account, d.source, d.title,
                           snippet(documents_fts, 4, ?, ?, ' ... ', 20) AS snippet,
                           bm25(documents_fts, 1.0, 4.0, 1.0, 2.0, 1.0) AS score
                    FROM documents_fts
                    JOIN documents d ON d.id = documents_fts.rowid
                    WHERE documents_fts MATCH ?
                    ORDER BY score
                    LIMIT ?
                """
                try:
                    for r in conn.execute(sql, (HIGHLIGHT_OPEN, HIGHLIGHT_CLOSE, fts_query, args.limit)):
                        rows.append(dict(r))
                except sqlite3.Error as exc:
                    print(f"warning: FTS query failed ({exc}); using fallback", file=sys.stderr)
                    backend = "fallback"
        if backend == "fallback":
            words = query_words(query)
            for r in conn.execute("SELECT * FROM documents"):
                row = dict(r)
                text = row["text"].lower()
                count = sum(text.count(w) for w in words)
                if count == 0:
                    continue
                row["snippet"] = make_snippet(row["text"], words)
                row["score"] = -float(count)
                rows.append(row)
            rows.sort(key=lambda r: (r["score"], r["path"]))
            rows = rows[: args.limit]

        print(f'{len(rows)} result(s) for "{query}"  [backend: {backend}]')
        print("matched terms shown in [brackets]\n")
        for i, row in enumerate(rows, 1):
            print_result(i, row, row["score"], query_words(query))
    finally:
        conn.close()


# --------------------------------------------------------------------------
# show
# --------------------------------------------------------------------------
SECTION_RE = re.compile(
    r"^##\s+(?:\d+\.\s+)?(?:([\w.\-]+)/)?([\w.\-]+)\s*$", re.MULTILINE
)


def extract_section(text: str, heading_re: re.Pattern) -> str | None:
    m = heading_re.search(text)
    if not m:
        return None
    start = m.start()
    nxt = re.search(r"^##\s+", text[m.end() :], re.MULTILINE)
    end = m.end() + nxt.start() if nxt else len(text)
    return text[start:end].strip("\n")


def load_meta() -> list[dict]:
    import json

    path = KB_ROOT / "meta.json"
    return json.loads(read_text(path)) if path.is_file() else []


def repo_heading_re(repo: str, account: str | None) -> re.Pattern:
    name_pat = re.escape(repo)
    if account:
        pattern = rf"^##\s+(?:\d+\.\s+)?{re.escape(account)}/{name_pat}\s*$"
    else:
        pattern = rf"^##\s+(?:\d+\.\s+)?(?:[\w.\-]+/)?{name_pat}\s*$"
    return re.compile(pattern, re.MULTILINE | re.IGNORECASE)


def cmd_show(args: argparse.Namespace) -> None:
    wanted = args.repo.strip()
    meta = load_meta()
    matches = [
        rec
        for rec in meta
        if wanted.lower() in (rec.get("name", "").lower(), rec.get("full_name", "").lower())
    ]
    if not matches:
        matches = [rec for rec in meta if wanted.lower() == rec.get("name", "").lower()]
    if not matches:
        raise SystemExit(f"Unknown repo: {wanted!r} (see: python repo_search.py list)")
    rec = matches[0]
    repo = rec.get("name", wanted)
    account = rec.get("owner", "")
    full_name = rec.get("full_name", f"{account}/{repo}")

    print("=" * 72)
    print(f"REPO: {full_name}")
    print(f"Description: {rec.get('description') or 'no description'}")
    print(f"Language: {rec.get('language') or 'n/a'} | Stars: {rec.get('stars', 0)} "
          f"| Fork: {rec.get('fork', False)} | Branch: {rec.get('default_branch', '')}")
    print("=" * 72)

    raw_dir = KB_ROOT / "raw"
    raw_path = None
    if raw_dir.is_dir():
        for path in raw_dir.glob("*.md"):
            if path.stem.lower() == f"{account}__{repo}".lower():
                raw_path = path
                break
        if raw_path is None:
            for path in raw_dir.glob("*.md"):
                if path.stem.lower().endswith("__" + repo.lower()):
                    raw_path = path
                    break

    if raw_path:
        text = read_text(raw_path)
        lines = text.splitlines()
        body = "\n".join(lines[:300])
        note = "" if len(lines) <= 300 else f"\n... [truncated; full file has {len(lines)} lines: {raw_path}]"
        print(f"\n--- RAW README: {raw_path} ---\n")
        print(body + note)
    else:
        print("\n--- RAW README: none (no README in knowledge base) ---")

    heading_re = repo_heading_re(repo, account)
    found_summary = False
    for path in summary_files():
        section = extract_section(read_text(path), heading_re)
        if section:
            found_summary = True
            print(f"\n--- SUMMARY SECTION: {path} ---\n")
            print(section)
    if not found_summary:
        # try without owner in case summary used a bare repo name
        for path in summary_files():
            section = extract_section(read_text(path), repo_heading_re(repo, None))
            if section:
                found_summary = True
                print(f"\n--- SUMMARY SECTION: {path} ---\n")
                print(section)
                break
    if not found_summary:
        print("\n--- SUMMARY SECTION: none found ---")


# --------------------------------------------------------------------------
# list
# --------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> None:
    meta = load_meta()
    if args.account:
        meta = [r for r in meta if r.get("owner") == args.account]
    print(f"{len(meta)} repos" + (f" for account {args.account}" if args.account else ""))
    print("-" * 100)
    for rec in sorted(meta, key=lambda r: (r.get("owner", ""), r.get("name", "").lower())):
        desc = (rec.get("description") or "no description").replace("\n", " ")
        if len(desc) > 64:
            desc = desc[:61] + "..."
        print(
            f"{rec.get('owner', ''):<22} {rec.get('name', ''):<48} "
            f"{(rec.get('language') or 'n/a'):<12} {rec.get('stars', 0):>3}*  {desc}"
        )


# --------------------------------------------------------------------------
# themes
# --------------------------------------------------------------------------
THEME_HEADING = re.compile(r"^##\s+Cross-cutting themes\s*$", re.MULTILINE | re.IGNORECASE)


def cmd_themes(_args: argparse.Namespace) -> None:
    files = summary_files()
    count = 0
    for path in files:
        text = read_text(path)
        section = extract_section(text, THEME_HEADING)
        if not section:
            continue
        count += 1
        print("=" * 72)
        print(f"SOURCE: {path}")
        print("=" * 72)
        print(section)
        print()
    if count == 0:
        print("No 'Cross-cutting themes' sections found in summary files.")
    else:
        print(f"{count} cross-cutting-theme section(s) from {len(files)} summary file(s).")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo_search.py",
        description="Local search CLI over the 55-repo knowledge base",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_index = sub.add_parser("index", help="build/update index.db")
    p_index.set_defaults(func=cmd_index)

    p_search = sub.add_parser("search", help="ranked full-text search")
    p_search.add_argument("query", nargs="+", help="query words (multi-word supported)")
    p_search.add_argument("--limit", type=int, default=10, help="max results (default 10)")
    p_search.set_defaults(func=cmd_search)

    p_show = sub.add_parser("show", help="show a repo's README and summary sections")
    p_show.add_argument("repo", help="repo name, e.g. redline or delriscotechnologies/redline")
    p_show.set_defaults(func=cmd_show)

    p_list = sub.add_parser("list", help="inventory repos from meta.json")
    p_list.add_argument(
        "--account",
        choices=["delriscotechnologies", "ancient-cthulhu"],
        help="filter by account",
    )
    p_list.set_defaults(func=cmd_list)

    p_themes = sub.add_parser("themes", help="print cross-cutting themes")
    p_themes.set_defaults(func=cmd_themes)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
