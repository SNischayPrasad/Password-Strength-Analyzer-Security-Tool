"""
Optional analytics storage (SQLite) - SAFE METADATA ONLY.

There is deliberately NO password column anywhere in this schema - not
plaintext, not encrypted, not hashed:

  * Plaintext or reversible (encrypted) passwords would turn this tool into a
    credential database that attackers would love to steal.
  * Even a hash of an arbitrary submitted password is risky: people often type
    their REAL passwords into strength checkers. A fast hash of a common or
    human-chosen password can be guessed offline, and a stored hash could also
    be used to tell whether the same password was checked twice. The dashboard
    does not need it, so we do not collect it (data minimization).

What IS stored: score, classification, length, unique-character ratio,
number of weaknesses, timestamp - and, per analysis, the generic type/
severity/title of each weakness (never the matched characters).
"""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id            TEXT PRIMARY KEY,
    score                  INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    classification         TEXT    NOT NULL,
    password_length        INTEGER NOT NULL,
    unique_character_ratio REAL    NOT NULL,
    weakness_count         INTEGER NOT NULL,
    created_at             TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
    finding_type  TEXT NOT NULL,
    severity      TEXT NOT NULL,
    description   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
"""

CLASSIFICATIONS = ("VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG")
LENGTH_BUCKETS = (("1-7", 1, 7), ("8-11", 8, 11), ("12-15", 12, 15),
                  ("16-19", 16, 19), ("20+", 20, 10_000))


def build_safe_record(result: dict) -> dict:
    """
    Extract ONLY allow-listed, non-sensitive fields from an analysis result.

    Using an explicit allow-list (instead of "store the result minus the
    password") means a future change to the analyzer output can never leak
    new data into storage by accident.
    """
    metrics = result["metrics"]
    weaknesses = [f for f in result["findings"] if f["severity"] != "info"]
    return {
        "analysis_id": uuid.uuid4().hex,
        "score": int(result["score"]),
        "classification": str(result["classification"]),
        "password_length": int(metrics["length"]),
        "unique_character_ratio": float(metrics["unique_character_ratio"]),
        "weakness_count": len(weaknesses),
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "findings": [
            # `title` is a fixed generic label such as "Keyboard pattern".
            {"finding_type": f["type"], "severity": f["severity"], "description": f["title"]}
            for f in weaknesses
        ],
    }


class AnalyticsRepository:
    """Tiny data-access layer around the SQLite analytics database."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ---- writes ---------------------------------------------------------

    def record_analysis(self, result: dict) -> str:
        """Store safe metadata for one analysis and return its analysis_id."""
        record = build_safe_record(result)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO analyses (analysis_id, score, classification, password_length, "
                "unique_character_ratio, weakness_count, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (record["analysis_id"], record["score"], record["classification"],
                 record["password_length"], record["unique_character_ratio"],
                 record["weakness_count"], record["created_at"]),
            )
            conn.executemany(
                "INSERT INTO findings (analysis_id, finding_type, severity, description) "
                "VALUES (?, ?, ?, ?)",
                [(record["analysis_id"], f["finding_type"], f["severity"], f["description"])
                 for f in record["findings"]],
            )
        return record["analysis_id"]

    def reset(self) -> None:
        """Delete all analytics rows (used by the demo seeding script and tests)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM analyses")

    # ---- reads ----------------------------------------------------------

    def get_dashboard_stats(self) -> dict:
        with self._connect() as conn:
            total, avg = conn.execute(
                "SELECT COUNT(*), AVG(score) FROM analyses").fetchone()
            by_class = {c: 0 for c in CLASSIFICATIONS}
            for row in conn.execute(
                    "SELECT classification, COUNT(*) AS n FROM analyses GROUP BY classification"):
                by_class[row["classification"]] = row["n"]

            score_buckets = {f"{i}-{i + 9 if i < 90 else 100}": 0 for i in range(0, 100, 10)}
            for row in conn.execute(
                    "SELECT MIN(score / 10, 9) AS bucket, COUNT(*) AS n FROM analyses GROUP BY bucket"):
                start = row["bucket"] * 10
                score_buckets[f"{start}-{start + 9 if start < 90 else 100}"] = row["n"]

            length_dist = {label: 0 for label, _, _ in LENGTH_BUCKETS}
            for label, low, high in LENGTH_BUCKETS:
                length_dist[label] = conn.execute(
                    "SELECT COUNT(*) FROM analyses WHERE password_length BETWEEN ? AND ?",
                    (low, high)).fetchone()[0]

            pattern_count_dist = {"0": 0, "1": 0, "2": 0, "3": 0, "4+": 0}
            for row in conn.execute(
                    "SELECT MIN(weakness_count, 4) AS k, COUNT(*) AS n FROM analyses GROUP BY k"):
                pattern_count_dist["4+" if row["k"] >= 4 else str(row["k"])] = row["n"]

        return {
            "total_analyses": total,
            "average_score": round(avg, 1) if avg is not None else 0,
            "classification_counts": by_class,
            "score_distribution": score_buckets,
            "length_distribution": length_dist,
            "weaknesses_per_analysis": pattern_count_dist,
            "weakness_types": self.get_weakness_stats()["weakness_types"],
        }

    def get_weakness_stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            rows = conn.execute(
                "SELECT finding_type, COUNT(*) AS n, COUNT(DISTINCT analysis_id) AS analyses "
                "FROM findings GROUP BY finding_type ORDER BY n DESC").fetchall()
        return {
            "total_analyses": total,
            "weakness_types": [
                {
                    "type": row["finding_type"],
                    "count": row["n"],
                    "percent_of_analyses": round(100 * row["analyses"] / total, 1) if total else 0,
                }
                for row in rows
            ],
        }

    def column_names(self, table: str) -> list[str]:
        """Used by privacy tests to prove there is no password column."""
        if table not in {"analyses", "findings"}:
            raise ValueError("unknown table")
        with self._connect() as conn:
            return [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]
