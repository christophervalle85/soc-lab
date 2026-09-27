#!/usr/bin/env python3
"""Display important fields from Wazuh JSON alerts."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


NOT_AVAILABLE = "Not available"


def display_value(value: object) -> str:
    if value is None or value == "" or value == []:
        return NOT_AVAILABLE
    return str(value)


def format_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value:
        return NOT_AVAILABLE
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_mitre_ids(rule: dict) -> str:
    mitre_ids = rule.get("mitre", {}).get("id")
    if isinstance(mitre_ids, list):
        return ", ".join(str(technique_id) for technique_id in mitre_ids)
    return display_value(mitre_ids)


def render_alert(alert: dict, position: int, total: int) -> str:
    source = alert["_source"]
    rule = source.get("rule", {})
    agent = source.get("agent", {})
    windows = source.get("data", {}).get("win", {})
    system = windows.get("system", {})
    event_data = windows.get("eventdata", {})

    return "\n".join(
        (
            f"[{position}/{total}] Rule {display_value(rule.get('id'))} "
            f"— Level {display_value(rule.get('level'))}",
            f"Time:        {format_timestamp(source.get('timestamp'))}",
            f"Agent:       {display_value(agent.get('name'))} "
            f"({display_value(agent.get('id'))})",
            f"Description: {display_value(rule.get('description'))}",
            f"MITRE:       {format_mitre_ids(rule)}",
            "Event:       "
            f"Sysmon Event ID {display_value(system.get('eventID'))}, "
            f"Record {display_value(system.get('eventRecordID'))}",
            f"Image:       {display_value(event_data.get('image'))}",
            f"User:        {display_value(event_data.get('user'))}",
            f"Command:     {display_value(event_data.get('commandLine'))}",
            f"Target:      {display_value(event_data.get('targetFilename'))}",
            "-" * 60,
        )
    )


def normalize_alert_shape(alert: dict) -> dict:
    if isinstance(alert.get("_source"), dict):
        return alert

    wazuh_alert = alert.get("wazuh_alert")
    sysmon_event = alert.get("sysmon_event")
    agent = alert.get("agent")
    if not all(isinstance(section, dict) for section in (wazuh_alert, sysmon_event, agent)):
        raise ValueError(
            "alert must contain a Wazuh _source object or curated evidence sections"
        )

    event_data = {
        "image": sysmon_event.get("image"),
        "user": sysmon_event.get("user"),
        "commandLine": sysmon_event.get("command_line"),
        "targetFilename": sysmon_event.get("target_filename"),
    }
    return {
        "_source": {
            "timestamp": wazuh_alert.get("timestamp_utc"),
            "agent": agent,
            "rule": {
                "id": wazuh_alert.get("rule_id"),
                "level": wazuh_alert.get("level"),
                "description": wazuh_alert.get("description"),
                "mitre": {"id": wazuh_alert.get("mitre")},
            },
            "data": {
                "win": {
                    "system": {
                        "eventID": sysmon_event.get("event_id"),
                        "eventRecordID": sysmon_event.get("event_record_id"),
                    },
                    "eventdata": event_data,
                }
            },
        }
    }


def load_alerts(path: Path) -> list[dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(document, list):
        if not all(isinstance(alert, dict) for alert in document):
            raise ValueError("top-level list must contain only alert objects")
        alerts = document
    elif isinstance(document, dict):
        alerts = [document]
    else:
        raise ValueError("top-level JSON value must be an alert object or list")

    return [normalize_alert_shape(alert) for alert in alerts]


def pluralized(count: int, singular: str) -> str:
    return singular if count == 1 else f"{singular}s"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize Wazuh JSON alerts in the terminal."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Wazuh JSON file")
    arguments = parser.parse_args()

    alerts: list[dict] = []
    files_read = 0
    error_count = 0
    for path in arguments.paths:
        try:
            alerts.extend(load_alerts(path))
        except (OSError, json.JSONDecodeError, ValueError) as error:
            print(f"ERROR: {path}: {error}", file=sys.stderr)
            error_count += 1
        else:
            files_read += 1

    alert_count = len(alerts)
    print(
        f"Loaded {alert_count} {pluralized(alert_count, 'alert')} "
        f"from {files_read} {pluralized(files_read, 'file')}"
    )
    print()
    for position, alert in enumerate(alerts, start=1):
        print(render_alert(alert, position, alert_count))
    print(f"Processed: {alert_count} {pluralized(alert_count, 'alert')}")
    print(f"Files read: {files_read}")
    print(f"Errors: {error_count}")
    return 1 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
