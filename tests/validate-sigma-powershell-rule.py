#!/usr/bin/env python3
"""Validate the Lesson 9 Sigma rule against controlled process events."""

import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = (
    REPOSITORY_ROOT
    / "detections"
    / "sigma"
    / "proc_creation_win_powershell_lab_validation.yml"
)
FIXTURE_CASES = (
    (
        REPOSITORY_ROOT / "tests" / "fixtures" / "sigma" / "powershell_marker_match.json",
        True,
        "expected match",
    ),
    (
        REPOSITORY_ROOT
        / "tests"
        / "fixtures"
        / "sigma"
        / "powershell_marker_nonmatch.json",
        False,
        "expected nonmatch",
    ),
)
EVENT_FIELDS = ("Image", "CommandLine", "ParentImage", "User")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_sigma(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ("sigma", *arguments),
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def compile_sqlite_query() -> str:
    validation = run_sigma("check", str(RULE_PATH))
    if validation.returncode != 0:
        fail(f"Sigma validation failed:\n{validation.stdout}{validation.stderr}")

    conversion = run_sigma("convert", "-t", "sqlite", str(RULE_PATH))
    if conversion.returncode != 0:
        fail(f"Sigma SQLite conversion failed:\n{conversion.stdout}{conversion.stderr}")

    query = conversion.stdout.strip()
    if not query.startswith("SELECT ") or "<TABLE_NAME>" not in query:
        fail(f"Sigma returned an unexpected SQLite query: {query!r}")

    return query.replace("<TABLE_NAME>", "events")


def load_event(path: Path) -> dict:
    if not path.is_file():
        fail(f"Required fixture is missing: {path.relative_to(REPOSITORY_ROOT)}")

    with path.open(encoding="utf-8") as fixture_file:
        event = json.load(fixture_file)

    missing_fields = [field for field in EVENT_FIELDS if field not in event]
    if missing_fields:
        fail(f"{path.name} is missing fields: {', '.join(missing_fields)}")

    return event


def query_matches_event(query: str, event: dict) -> bool:
    with sqlite3.connect(":memory:") as connection:
        connection.execute(
            "CREATE TABLE events "
            "(Image TEXT, CommandLine TEXT, ParentImage TEXT, User TEXT)"
        )
        connection.execute(
            "INSERT INTO events (Image, CommandLine, ParentImage, User) "
            "VALUES (?, ?, ?, ?)",
            tuple(event[field] for field in EVENT_FIELDS),
        )
        return connection.execute(query).fetchone() is not None


def main() -> None:
    if shutil.which("sigma") is None:
        fail("Sigma CLI is not installed or is not available on PATH")
    if not RULE_PATH.is_file():
        fail(f"Sigma rule is missing: {RULE_PATH.relative_to(REPOSITORY_ROOT)}")

    query = compile_sqlite_query()
    print("PASS: Sigma rule validation and SQLite conversion")

    for fixture_path, expected_match, case_name in FIXTURE_CASES:
        event = load_event(fixture_path)
        actual_match = query_matches_event(query, event)
        if actual_match != expected_match:
            fail(
                f"{case_name} failed for {fixture_path.name}: "
                f"expected match={expected_match}, actual match={actual_match}"
            )
        print(f"PASS: {case_name} ({fixture_path.name})")


if __name__ == "__main__":
    main()
