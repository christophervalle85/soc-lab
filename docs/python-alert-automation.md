# Python Wazuh Alert Summarization

## Purpose

`automation/wazuh_alert_summary.py` is a read-only command-line utility for
reviewing multiple Wazuh JSON alerts without navigating every nested field
manually. It leaves the source files unchanged and prints a concise terminal
summary for each alert.

The first version intentionally does not create Markdown reports or redact
local input. Evidence selected for publication must still be reviewed and
sanitized separately before it is committed to Git.

## Supported input

Pass one or more JSON file paths. Each file may contain either:

- One raw Wazuh alert object with a top-level `_source` object
- A top-level list of raw Wazuh alert objects
- A curated project evidence object containing `agent`, `wazuh_alert`, and
  `sysmon_event` sections

The bundled sample preserves the relevant structure of the Lesson 11 Wazuh
alerts while using controlled lab values.

```bash
python3 automation/wazuh_alert_summary.py \
  sample-data/wazuh-alerts-example.json
```

Multiple files can be supplied in the same command:

```bash
python3 automation/wazuh_alert_summary.py alert-one.json alert-two.json
```

The two curated Lesson 11 evidence files can be reviewed together:

```bash
python3 automation/wazuh_alert_summary.py \
  docs/evidence/lesson-11-wazuh-rule-92041-registry-process-alert.json \
  docs/evidence/lesson-11-wazuh-rule-92213-powershell-temp-file-alert.json
```

## Terminal output

The utility prints the number of alerts and files loaded, followed by one
numbered block per alert. When present in the source event, the block includes:

- UTC timestamp
- Wazuh rule ID, level, and description
- Agent name and ID
- MITRE ATT&CK technique IDs
- Sysmon event ID and record ID
- Process image, user, and command line
- Target filename

Missing optional fields are shown as `Not available` rather than causing the
entire run to fail.

## Error behavior

An unreadable file, invalid JSON document, unsupported top-level JSON value, or
alert that matches neither supported structure is reported to standard error.
Other valid files are still processed. The final summary reports the number of
processed alerts, successfully read files, and errors.

The program returns exit code `1` when any input file fails, allowing another
script to detect an incomplete batch. A fully successful run returns `0`.

## Validation

The behavior tests use Python's standard-library `unittest` framework:

```bash
python3 -m unittest tests/test_wazuh_alert_summary.py -v
```

They cover a single raw alert, combined object/list inputs, the repository's
curated Lesson 11 evidence, missing optional fields, file-creation targets,
malformed JSON, and structurally invalid alert objects. No third-party Python
packages are required.

## Limitations

- Version one recognizes raw Wazuh alerts represented by `_source` and the
  curated evidence structure used by this repository. Other export envelopes
  may require an additional adapter.
- The event-specific fields currently target Windows/Sysmon alert data under
  `data.win`; common Wazuh rule and agent fields still remain visible when
  optional Windows fields are absent.
- The output assists triage but does not determine whether an alert is
  malicious, benign, or a false positive.
- Terminal output is not automatically safe for publication merely because it
  is concise. Public evidence still requires a separate review.
