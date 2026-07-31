"""Result Store — SQLite-backed audit history with before/after diff.

Stores every audit run with timestamp, app name, scores, and full results.
Enables trend tracking, before/after comparison, and regression detection.

Usage:
    from agentic_redteam.result_store import ResultStore

    store = ResultStore()
    store.save_run("payment-agent", results_dict)

    history = store.get_history("payment-agent", limit=10)
    diff = store.compare_last_two("payment-agent")
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path.home() / ".swishos" / "audit_history.db"


class ResultStore:
    """SQLite-backed store for audit run results."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                run_at TEXT NOT NULL,
                total_tests INTEGER DEFAULT 0,
                total_passed INTEGER DEFAULT 0,
                pass_rate REAL DEFAULT 0.0,
                grade TEXT DEFAULT '',
                owasp_score INTEGER DEFAULT 0,
                categories_json TEXT DEFAULT '{}',
                failures_json TEXT DEFAULT '[]',
                full_results_json TEXT DEFAULT '{}',
                elapsed_seconds REAL DEFAULT 0.0
            );

            CREATE INDEX IF NOT EXISTS idx_runs_app ON audit_runs(app_name);
            CREATE INDEX IF NOT EXISTS idx_runs_time ON audit_runs(run_at);
        """)
        self._conn.commit()

    def save_run(self, app_name: str, target_url: str, results: dict[str, Any]) -> int:
        """Save an audit run. Returns the run ID."""
        owasp = results.get("owasp_score", {})
        summary = results.get("summary", {})

        cur = self._conn.execute("""
            INSERT INTO audit_runs
                (app_name, target_url, run_at, total_tests, total_passed,
                 pass_rate, grade, owasp_score, categories_json,
                 failures_json, full_results_json, elapsed_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            app_name,
            target_url,
            datetime.now(timezone.utc).isoformat(),
            owasp.get("total_tests", 0),
            owasp.get("total_passed", 0),
            owasp.get("pass_rate", 0.0),
            owasp.get("grade", ""),
            owasp.get("composite", 0),
            json.dumps(summary),
            json.dumps(results.get("failures", [])),
            json.dumps(results),
            results.get("elapsed_seconds", 0.0),
        ))
        self._conn.commit()
        return cur.lastrowid

    def get_history(self, app_name: str, limit: int = 20) -> list[dict[str, Any]]:
        """Get audit history for an app, most recent first."""
        rows = self._conn.execute("""
            SELECT id, app_name, target_url, run_at, total_tests, total_passed,
                   pass_rate, grade, owasp_score, elapsed_seconds
            FROM audit_runs
            WHERE app_name = ?
            ORDER BY run_at DESC
            LIMIT ?
        """, (app_name, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        """Get full details of a specific run."""
        row = self._conn.execute("""
            SELECT * FROM audit_runs WHERE id = ?
        """, (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["categories"] = json.loads(d.pop("categories_json"))
        d["failures"] = json.loads(d.pop("failures_json"))
        d["full_results"] = json.loads(d.pop("full_results_json"))
        return d

    def get_latest(self, app_name: str) -> dict[str, Any] | None:
        """Get the most recent run for an app."""
        row = self._conn.execute("""
            SELECT * FROM audit_runs WHERE app_name = ? ORDER BY run_at DESC LIMIT 1
        """, (app_name,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["categories"] = json.loads(d.pop("categories_json"))
        d["failures"] = json.loads(d.pop("failures_json"))
        d["full_results"] = json.loads(d.pop("full_results_json"))
        return d

    def compare_last_two(self, app_name: str) -> dict[str, Any] | None:
        """Compare the two most recent runs — the before/after diff."""
        rows = self._conn.execute("""
            SELECT id, run_at, total_tests, total_passed, pass_rate, grade,
                   owasp_score, categories_json, failures_json
            FROM audit_runs
            WHERE app_name = ?
            ORDER BY run_at DESC
            LIMIT 2
        """, (app_name,)).fetchall()

        if len(rows) < 2:
            return None

        current = dict(rows[0])
        previous = dict(rows[1])

        current_cats = json.loads(current["categories_json"])
        previous_cats = json.loads(previous["categories_json"])
        current_failures = json.loads(current["failures_json"])
        previous_failures = json.loads(previous["failures_json"])

        # Compute diffs
        pass_rate_delta = current["pass_rate"] - previous["pass_rate"]
        score_delta = current["owasp_score"] - previous["owasp_score"]

        # Find fixed and new failures
        prev_descs = {f.get("description", "") for f in previous_failures}
        curr_descs = {f.get("description", "") for f in current_failures}
        fixed = prev_descs - curr_descs
        new_failures = curr_descs - prev_descs

        # Per-category changes
        category_changes = {}
        all_cats = set(list(current_cats.keys()) + list(previous_cats.keys()))
        for cat in all_cats:
            prev_rate = previous_cats.get(cat, {}).get("pass_rate", 0)
            curr_rate = current_cats.get(cat, {}).get("pass_rate", 0)
            if curr_rate != prev_rate:
                category_changes[cat] = {
                    "before": prev_rate,
                    "after": curr_rate,
                    "delta": curr_rate - prev_rate,
                }

        return {
            "app_name": app_name,
            "current_run": {"id": current["id"], "date": current["run_at"], "grade": current["grade"], "pass_rate": current["pass_rate"], "score": current["owasp_score"]},
            "previous_run": {"id": previous["id"], "date": previous["run_at"], "grade": previous["grade"], "pass_rate": previous["pass_rate"], "score": previous["owasp_score"]},
            "pass_rate_delta": round(pass_rate_delta, 1),
            "score_delta": score_delta,
            "fixed_count": len(fixed),
            "new_failure_count": len(new_failures),
            "fixed": list(fixed),
            "new_failures": list(new_failures),
            "category_changes": category_changes,
            "improved": pass_rate_delta > 0,
            "regressed": pass_rate_delta < 0,
        }

    def get_trend(self, app_name: str, limit: int = 12) -> list[dict[str, Any]]:
        """Get pass_rate trend over time (for charting)."""
        rows = self._conn.execute("""
            SELECT run_at, pass_rate, grade, owasp_score
            FROM audit_runs
            WHERE app_name = ?
            ORDER BY run_at DESC
            LIMIT ?
        """, (app_name, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def list_apps(self) -> list[dict[str, Any]]:
        """List all apps that have been audited with their latest stats."""
        rows = self._conn.execute("""
            SELECT app_name,
                   COUNT(*) as total_runs,
                   MAX(run_at) as last_run,
                   MAX(pass_rate) as best_rate,
                   (SELECT pass_rate FROM audit_runs a2
                    WHERE a2.app_name = audit_runs.app_name
                    ORDER BY run_at DESC LIMIT 1) as latest_rate,
                   (SELECT grade FROM audit_runs a3
                    WHERE a3.app_name = audit_runs.app_name
                    ORDER BY run_at DESC LIMIT 1) as latest_grade
            FROM audit_runs
            GROUP BY app_name
            ORDER BY last_run DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
