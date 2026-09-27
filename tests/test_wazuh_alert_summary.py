#!/usr/bin/env python3
"""Behavior tests for the Wazuh alert-summary CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "automation" / "wazuh_alert_summary.py"
CURATED_ALERT_PATHS = (
    REPOSITORY_ROOT
    / "docs"
    / "evidence"
    / "lesson-11-wazuh-rule-92041-registry-process-alert.json",
    REPOSITORY_ROOT
    / "docs"
    / "evidence"
    / "lesson-11-wazuh-rule-92213-powershell-temp-file-alert.json",
)


def raw_alert() -> dict:
    return {
        "_source": {
            "timestamp": "2026-09-24T04:57:20.178+0000",
            "agent": {"id": "001", "name": "SOC-WIN11"},
            "rule": {
                "id": "92041",
                "level": 10,
                "description": "Value added to registry key has Base64-like pattern",
                "mitre": {"id": ["T1027", "T1112"]},
            },
            "data": {
                "win": {
                    "system": {"eventID": "1", "eventRecordID": "101505"},
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\reg.exe",
                        "user": "SOC-WIN11\\socadmin",
                        "commandLine": "reg add HKCU\\Software\\Example /f",
                    },
                }
            },
        }
    }


def raw_alert_with_rule(rule_id: str) -> dict:
    alert = raw_alert()
    alert["_source"]["rule"]["id"] = rule_id
    return alert


class WazuhAlertSummaryCliTests(unittest.TestCase):
    def run_cli(self, *paths: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(SCRIPT_PATH), *(str(path) for path in paths)),
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_displays_single_raw_wazuh_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            alert_path = Path(temp_directory) / "alert.json"
            alert_path.write_text(json.dumps(raw_alert()), encoding="utf-8")

            result = self.run_cli(alert_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Loaded 1 alert from 1 file", result.stdout)
        self.assertIn("[1/1] Rule 92041 — Level 10", result.stdout)
        self.assertIn("Time:        2026-09-24 04:57:20 UTC", result.stdout)
        self.assertIn("Agent:       SOC-WIN11 (001)", result.stdout)
        self.assertIn(
            "Description: Value added to registry key has Base64-like pattern",
            result.stdout,
        )
        self.assertIn("MITRE:       T1027, T1112", result.stdout)
        self.assertIn("Event:       Sysmon Event ID 1, Record 101505", result.stdout)
        self.assertIn("Image:       C:\\Windows\\System32\\reg.exe", result.stdout)
        self.assertIn("User:        SOC-WIN11\\socadmin", result.stdout)
        self.assertIn("Command:     reg add HKCU\\Software\\Example /f", result.stdout)

    def test_combines_single_alert_and_list_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            temp_path = Path(temp_directory)
            single_path = temp_path / "single.json"
            list_path = temp_path / "list.json"
            single_path.write_text(
                json.dumps(raw_alert_with_rule("92041")), encoding="utf-8"
            )
            list_path.write_text(
                json.dumps(
                    [raw_alert_with_rule("92213"), raw_alert_with_rule("92302")]
                ),
                encoding="utf-8",
            )

            result = self.run_cli(single_path, list_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Loaded 3 alerts from 2 files", result.stdout)
        self.assertIn("[1/3] Rule 92041", result.stdout)
        self.assertIn("[2/3] Rule 92213", result.stdout)
        self.assertIn("[3/3] Rule 92302", result.stdout)

    def test_reports_invalid_file_and_continues_with_valid_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            temp_path = Path(temp_directory)
            invalid_path = temp_path / "invalid.json"
            valid_path = temp_path / "valid.json"
            invalid_path.write_text("{not valid json", encoding="utf-8")
            valid_path.write_text(json.dumps(raw_alert()), encoding="utf-8")

            result = self.run_cli(invalid_path, valid_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("[1/1] Rule 92041", result.stdout)
        self.assertIn("Processed: 1 alert", result.stdout)
        self.assertIn("Files read: 1", result.stdout)
        self.assertIn("Errors: 1", result.stdout)
        self.assertIn(f"ERROR: {invalid_path}:", result.stderr)

    def test_displays_not_available_for_missing_optional_fields(self) -> None:
        alert = raw_alert()
        del alert["_source"]["rule"]["mitre"]
        alert["_source"]["data"]["win"]["eventdata"] = {}
        del alert["_source"]["data"]["win"]["system"]["eventRecordID"]

        with tempfile.TemporaryDirectory() as temp_directory:
            alert_path = Path(temp_directory) / "partial.json"
            alert_path.write_text(json.dumps(alert), encoding="utf-8")

            result = self.run_cli(alert_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MITRE:       Not available", result.stdout)
        self.assertIn("Event:       Sysmon Event ID 1, Record Not available", result.stdout)
        self.assertIn("Image:       Not available", result.stdout)
        self.assertIn("User:        Not available", result.stdout)
        self.assertIn("Command:     Not available", result.stdout)

    def test_rejects_alert_object_without_wazuh_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            invalid_path = Path(temp_directory) / "not-wazuh.json"
            valid_path = Path(temp_directory) / "valid.json"
            invalid_path.write_text(json.dumps({"message": "not a Wazuh alert"}))
            valid_path.write_text(json.dumps(raw_alert()), encoding="utf-8")

            result = self.run_cli(invalid_path, valid_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("[1/1] Rule 92041", result.stdout)
        self.assertIn("Errors: 1", result.stdout)
        self.assertIn(
            "must contain a Wazuh _source object or curated evidence sections",
            result.stderr,
        )

    def test_displays_target_filename_for_file_creation_alert(self) -> None:
        alert = raw_alert_with_rule("92213")
        event_data = alert["_source"]["data"]["win"]["eventdata"]
        event_data["targetFilename"] = "C:\\Temp\\policy-test.ps1"
        del event_data["commandLine"]

        with tempfile.TemporaryDirectory() as temp_directory:
            alert_path = Path(temp_directory) / "file-alert.json"
            alert_path.write_text(json.dumps(alert), encoding="utf-8")

            result = self.run_cli(alert_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Target:      C:\\Temp\\policy-test.ps1", result.stdout)
        self.assertIn("Command:     Not available", result.stdout)

    def test_displays_curated_lesson_11_evidence_files(self) -> None:
        result = self.run_cli(*CURATED_ALERT_PATHS)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Loaded 2 alerts from 2 files", result.stdout)
        self.assertIn("[1/2] Rule 92041 — Level 10", result.stdout)
        self.assertIn("[2/2] Rule 92213 — Level 15", result.stdout)
        self.assertIn("Event:       Sysmon Event ID 1, Record 101505", result.stdout)
        self.assertIn("Event:       Sysmon Event ID 11, Record 101531", result.stdout)


if __name__ == "__main__":
    unittest.main()
