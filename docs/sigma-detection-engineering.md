# Sigma Detection Engineering and Validation

## Objective

Lesson 9 expresses the verified Lesson 8 PowerShell marker detection in Sigma,
a portable rule format that separates detection logic from a specific SIEM's
native rule language. The goal is to preserve the same bounded behavior as the
Wazuh XML rule, validate the Sigma structure with official tooling, translate
it for a supported search platform, and test both matching and nonmatching
events repeatably.

The exercise demonstrates portability; it does not classify all PowerShell
activity as malicious or replace the deployed Wazuh rule.

## Rule Design

The portable rule is
[`proc_creation_win_powershell_lab_validation.yml`](../detections/sigma/proc_creation_win_powershell_lab_validation.yml).
It uses a Windows process-creation log source and requires both of the
following conditions:

1. `Image` ends with `\powershell.exe`.
2. `CommandLine` contains the exact marker
   `SOC-LAB-LESSON8-T1059-001`.

The rule has UUID `388f6589-290c-48be-89e3-ecf2f7aca571`, experimental
status, low severity, and MITRE ATT&CK tags for Execution and `T1059.001`
(PowerShell). Its generic `Image`, `CommandLine`, `ParentImage`, and `User`
fields describe the required telemetry without embedding Wazuh's native field
paths in the rule.

## Native Wazuh Rule Versus Sigma Rule

The Lesson 8 XML and Lesson 9 YAML express the same controlled detection idea
for different purposes:

| Artifact | Purpose |
|---|---|
| Wazuh XML rule `100100` | Native rule installed on `soc-wazuh`; generated the verified live alert |
| Sigma YAML rule | Portable detection definition that can be translated by supported backends |

Sigma does not collect events or produce alerts by itself. A Sigma backend
converts the generic rule into a query for a target platform. Field mappings
provided by a processing pipeline determine how generic Sigma fields appear in
that target's schema.

## Official Tool Validation

The rule was checked on the Mac with Sigma CLI `3.1.0` and pySigma `1.4.0`:

```bash
sigma check detections/sigma/proc_creation_win_powershell_lab_validation.yml
```

Result:

```text
Found 0 errors, 0 condition errors and 0 issues.
```

This verifies that the current Sigma tooling can parse the rule, evaluate its
condition, and apply its built-in validation checks. It does not by itself
prove that the detection matches the intended event, so behavioral fixture
tests are also required.

## OpenSearch Translation

The stable OpenSearch backend `2.0.3` and the `ecs_windows` processing pipeline
translated the rule into OpenSearch Lucene syntax:

```bash
sigma convert --disable-pipeline-check \
  -t opensearch_lucene \
  -p ecs_windows \
  detections/sigma/proc_creation_win_powershell_lab_validation.yml
```

Generated query:

```text
process.executable.caseless:*\powershell.exe AND process.command_line:*SOC\-LAB\-LESSON8\-T1059\-001*
```

The installed OpenSearch backend exposes the target identifier
`opensearch_lucene`, while the installed ECS pipeline metadata still lists the
older backend identifier `opensearch`. The `--disable-pipeline-check` option
bypasses only that identifier compatibility check. Sigma parsing and rule
validation were performed separately and remained enabled.

The translated query uses Elastic Common Schema fields. It demonstrates
backend conversion, but it is not a drop-in Wazuh query: Wazuh alert documents
store the corresponding Sysmon data under fields such as
`data.win.eventdata.image` and `data.win.eventdata.commandLine`. A deployment
target therefore still requires field-mapping review and platform-specific
testing.

## Repeatable Behavior Tests

The validation script
[`validate-sigma-powershell-rule.py`](../tests/validate-sigma-powershell-rule.py)
uses the official Sigma SQLite backend to compile the YAML rule into an
executable query. It loads each sanitized JSON fixture into a temporary,
in-memory SQLite table and evaluates the generated query against the event.
This tests the compiled Sigma logic instead of recreating the selection in a
separate custom matcher.

Fixtures:

- [`powershell_marker_match.json`](../tests/fixtures/sigma/powershell_marker_match.json)
  represents the verified Lesson 8 marker command.
- [`powershell_marker_nonmatch.json`](../tests/fixtures/sigma/powershell_marker_nonmatch.json)
  represents the verified control command with a different marker.

Run the complete validation from the repository root:

```bash
python3 tests/validate-sigma-powershell-rule.py
```

Verified result:

```text
PASS: Sigma rule validation and SQLite conversion
PASS: expected match (powershell_marker_match.json)
PASS: expected nonmatch (powershell_marker_nonmatch.json)
```

The positive test would fail if either required selection stopped matching.
The negative test would fail if the rule became broad enough to match the
control marker.

## Interpretation and Limitations

This validation establishes that the rule is structurally valid, convertible,
and behaves correctly for the two documented fixtures. It does not establish
production readiness or complete coverage of malicious PowerShell behavior.

The rule intentionally detects only the controlled marker. It does not cover
`pwsh.exe`, encoded commands, obfuscation, download activity, suspicious child
processes, or other PowerShell tradecraft. Those behaviors require separate
rules, broader representative datasets, and additional false-positive testing.

## Skills Demonstrated

- Translating a verified native Wazuh detection into portable Sigma YAML
- Separating detection logic, log source, metadata, and conditions
- Validating Sigma syntax and metadata with official tooling
- Converting a Sigma rule through SQLite and OpenSearch backends
- Designing deterministic expected-match and expected-nonmatch fixtures
- Identifying field-mapping and backend-portability limitations
