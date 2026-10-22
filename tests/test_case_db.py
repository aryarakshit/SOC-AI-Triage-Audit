"""Unit tests for HomeSOC SQLite Case Database integrity and schema."""
import json
import sqlite3
import pytest
from pathlib import Path

from core.case_db_builder import init_database, seed_database, get_default_cases

EXPECTED_CATEGORIES = {
    "powershell_execution": 20,
    "lolbin_abuse": 20,
    "credential_access": 15,
    "linux_privilege_escalation": 20,
    "network_dns_c2": 15,
    "adversarial_log_injection": 10
}

VALID_VERDICTS = {"TP_MALICIOUS", "BP_BENIGN_ADMIN", "FP_NOISE"}


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "test_homesoc.db"
    seed_database(db_file)
    return db_file


def test_database_seeding_count(test_db: Path):
    """Verify exactly 100 cases are seeded in ground_truth_cases table."""
    conn = sqlite3.connect(str(test_db))
    count = conn.execute("SELECT COUNT(*) FROM ground_truth_cases").fetchone()[0]
    conn.close()
    assert count == 100


def test_category_distributions(test_db: Path):
    """Verify each of the 6 threat categories has the exact configured case count."""
    conn = sqlite3.connect(str(test_db))
    rows = conn.execute("SELECT category, COUNT(*) FROM ground_truth_cases GROUP BY category").fetchall()
    conn.close()

    counts = dict(rows)
    for cat, expected_count in EXPECTED_CATEGORIES.items():
        assert counts.get(cat) == expected_count, f"Category {cat} count mismatch: {counts.get(cat)} != {expected_count}"


def test_telemetry_json_schema(test_db: Path):
    """Verify all raw telemetry JSON payloads parse and contain required SIEM fields."""
    conn = sqlite3.connect(str(test_db))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT case_id, raw_telemetry_json, analyst_verdict, rule_level FROM ground_truth_cases").fetchall()
    conn.close()

    for r in rows:
        telemetry = json.loads(r["raw_telemetry_json"])
        assert "commandLine" in telemetry, f"Case {r['case_id']} missing commandLine"
        assert "image" in telemetry, f"Case {r['case_id']} missing image"
        assert "parentImage" in telemetry, f"Case {r['case_id']} missing parentImage"
        assert "user" in telemetry, f"Case {r['case_id']} missing user"
        assert "srcip" in telemetry, f"Case {r['case_id']} missing srcip"
        assert r["analyst_verdict"] in VALID_VERDICTS
        assert 1 <= r["rule_level"] <= 15


def test_database_tables_exist(test_db: Path):
    """Verify both ground_truth_cases and ai_triage_results exist."""
    conn = sqlite3.connect(str(test_db))
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    conn.close()

    assert "ground_truth_cases" in tables
    assert "ai_triage_results" in tables
