#!/usr/bin/env python3
"""Query the Facet Pi feedback database for Catseye improvement.

Usage:
    python3 scripts/feedback.py [command] [db_path]

Commands:
    summary       Counts by detection type (default)
    scans         Recent scan results (last 50)
    fp            User-flagged false positives
    missed        Issues Catseye didn't catch
    new           New findings manually reported by users
    json          Export all feedback as JSON
    json <type>   Export feedback filtered by type as JSON

Database path defaults to $HOME/.facet-pi/feedback.db
"""

import sqlite3
import json
import sys
import os


def get_db():
    db = os.environ.get("FACET_DB", os.path.expandvars("$HOME/.facet-pi/feedback.db"))
    if not os.path.exists(db):
        print(f"No feedback database at {db}")
        sys.exit(1)
    return db


def summary(db):
    conn = sqlite3.connect(db)
    cur = conn.execute(
        "SELECT detection_type, COUNT(*) as count "
        "FROM feedback GROUP BY detection_type ORDER BY count DESC"
    )
    for row in cur:
        print(f"{row[0]:20s} {row[1]}")
    conn.close()


def scans(db):
    conn = sqlite3.connect(db)
    cur = conn.execute(
        "SELECT id, tool_name, file_path, issue_description, user_notes "
        'FROM feedback WHERE detection_type = "scan_result" '
        "ORDER BY id DESC LIMIT 50"
    )
    print(f"{'ID':>4}  {'Tool':<12}  {'File':<41}  {'Description':<61}  Notes")
    print("-" * 160)
    for r in cur:
        print(
            f"{r[0]:>4}  {(r[1] or ''):<12}  {(r[2] or '')[:40]:<41}  "
            f"{(r[3] or '')[:60]:<61}  {r[4] or ''}"
        )
    conn.close()


def by_type(db, detection_type):
    conn = sqlite3.connect(db)
    cur = conn.execute(
        "SELECT id, tool_name, file_path, issue_description, user_notes "
        "FROM feedback WHERE detection_type = ? ORDER BY id DESC",
        (detection_type,),
    )
    for r in cur:
        print(f"#{r[0]} [{r[1]}] {r[2]}")
        print(f"  {r[3]}")
        print(f"  Notes: {r[4]}")
        print()
    conn.close()


def export_json(db, detection_type=None):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    if detection_type:
        cur = conn.execute(
            "SELECT * FROM feedback WHERE detection_type = ? ORDER BY id DESC",
            (detection_type,),
        )
    else:
        cur = conn.execute("SELECT * FROM feedback ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    print(json.dumps(rows, indent=2))
    conn.close()


COMMANDS = {
    "summary": lambda db: summary(db),
    "scans": lambda db: scans(db),
    "fp": lambda db: by_type(db, "false_positive"),
    "missed": lambda db: by_type(db, "missed_issue"),
    "new": lambda db: by_type(db, "new_finding"),
    "json": lambda db: export_json(db),
}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "summary"
    db_override = None

    # Check for extra args: json <type> or db path as last arg
    args = sys.argv[1:]
    json_type = None
    if args and args[-1].endswith(".db"):
        db_override = args.pop()

    if not args:
        cmd = "summary"
    else:
        cmd = args[0]

    if cmd == "json" and len(args) > 1:
        json_type = args[1]

    db = db_override or get_db()

    if cmd == "json":
        export_json(db, json_type)
    elif cmd in COMMANDS:
        COMMANDS[cmd](db)
    else:
        print(f"Unknown command: {cmd}")
        print("Available: summary, scans, fp, missed, new, json [type]")
        sys.exit(1)


if __name__ == "__main__":
    main()
