# Custom Wazuh Rule Development and Validation

## Objective

Lesson 8 converts a verified detection gap into a bounded native Wazuh rule.
Lesson 7 established that Sysmon recorded a controlled PowerShell command on
`SOC-WIN11`, while the existing Wazuh rules did not generate a visible alert
for that specific marker. The goal was to create one repeatable detection,
verify the complete positive path, and confirm that a similar nonmatching event
did not trigger the custom rule.

This is a controlled lab validation. It does not classify routine PowerShell
use as malicious and is not presented as a production-ready PowerShell threat
detection.

## Detection Design

The repository rule is
[`lesson-08-powershell-marker.xml`](../detections/wazuh/lesson-08-powershell-marker.xml).
It uses custom rule ID `100100` at level `5` and requires all of the following:

1. A Windows Sysmon process-creation event in the `sysmon_event1` group.
2. A process image ending in `powershell.exe`, matched case-insensitively.
3. The exact controlled marker `SOC-LAB-LESSON8-T1059-001` in the command line.

The rule maps the observed command-interpreter behavior to MITRE ATT&CK
`T1059.001` (PowerShell). The unique marker keeps the exercise deterministic
and prevents the lab rule from alerting on every ordinary PowerShell process.

## Deployment Validation

The rule was installed on `soc-wazuh` at
`/var/ossec/etc/rules/lesson-08-powershell-marker.xml`. Validation established
that:

- Rule ID `100100` was not already in use by another local rule.
- `wazuh-analysisd -t` accepted the installed configuration with exit code `0`.
- The installed file uses owner/group `wazuh:wazuh` and mode `-rw-rw----`,
  matching `local_rules.xml`.
- The Wazuh manager was restarted and independently confirmed active at
  2026-09-15 18:57:55 UTC.
- Agent `001` (`SOC-WIN11`) was Active during validation.

These checks separate configuration correctness from behavioral correctness. A
rule can parse successfully without matching the intended event, so positive
and negative tests were still required.

## Expected-Match Test

The controlled command launched Windows PowerShell from `cmd.exe` with the
exact detection marker:

```cmd
powershell.exe -NoProfile -NonInteractive -Command "Write-Output 'SOC-LAB-LESSON8-T1059-001'"
```

The resulting evidence shows:

- Agent: `001` (`SOC-WIN11`)
- Sysmon event: Event ID `1`, record `65220`
- Wazuh alert time: 2026-09-15 14:24:49.697 dashboard time
- Rule: `100100`, level `5`
- ATT&CK mapping: `T1059.001`
- Result: **PASS — the custom rule generated the expected alert**

The complete three-page alert export is retained as
[`lesson-08-wazuh-rule-100100-t1059-001-positive-match.pdf`](evidence/lesson-08-wazuh-rule-100100-t1059-001-positive-match.pdf).

## Expected-Nonmatch Test

The control command used the same PowerShell executable and parent process but
replaced the required marker with `SOC-LAB-LESSON8-CONTROL-001`:

```cmd
powershell.exe -NoProfile -NonInteractive -Command "Write-Output 'SOC-LAB-LESSON8-CONTROL-001'"
```

Local Sysmon Event ID `1`, record `65365`, created at 2026-09-15 15:05:01
local time, proves that the control process executed and endpoint telemetry was
available. A Wazuh Threat Hunting query for agent `001` and rule `100100` over
a rolling 30-minute window captured at 15:25 returned no results. That window
included the 15:05 control event and excluded the earlier 14:24 positive alert.

- Result: **PASS — the control event was recorded by Sysmon but did not trigger
  rule `100100`**

Supporting evidence:

- [`lesson-08-sysmon-control-event-id-1.png`](../screenshots/lesson-08-sysmon-control-event-id-1.png)
- [`lesson-08-wazuh-rule-100100-negative-control-no-alert.png`](../screenshots/lesson-08-wazuh-rule-100100-negative-control-no-alert.png)

## Interpretation and Limitations

The two tests demonstrate a complete, bounded detection-engineering workflow:
identify a telemetry-versus-alerting gap, write a native rule, validate the
configuration, prove an expected match, and prove one expected nonmatch.

The rule is deliberately narrow. Its exact marker makes accidental matches
unlikely in this lab, but it also means the rule does not detect arbitrary
malicious PowerShell behavior. It does not currently cover `pwsh.exe`, encoded
commands, suspicious download patterns, obfuscation, or other behavioral
indicators. Those require separate detection logic and broader testing before
production use.

The negative result is bounded to the documented control event and search
window. It supports the conclusion that this control did not match rule
`100100`; it is not a claim that the rule has zero false positives under every
possible condition.

## Skills Demonstrated

- Translating an observed coverage gap into a native Wazuh rule
- Correlating endpoint Sysmon telemetry with SIEM alerts
- Validating rule syntax, installation, permissions, and manager activation
- Designing expected-match and expected-nonmatch tests
- Mapping a detection to MITRE ATT&CK with evidence-based limitations
- Preserving sanitized, reviewable validation evidence
