# Wazuh Detection Tuning and False-Positive Validation

## Objective

This validation addresses a verified false positive from built-in Wazuh rule
`92213`. The rule assigned level `15` and MITRE ATT&CK `T1105` to a benign
PowerShell script-policy test file created under a user's temporary directory.
The goal was to reduce the alert severity only for the well-defined benign
pattern while retaining the original detection for other script files.

## Baseline Finding

Lesson 11 correlated the original rule `92213` alert with a PowerShell
evidence query. Sysmon Event ID `11` showed that PowerShell created:

```text
C:\Users\socadmin\AppData\Local\Temp\__PSScriptPolicyTest_udiwgrly.l3d.ps1
```

The event proved that a `.ps1` file was created in a user Temp directory. It
did not prove ingress tool transfer or malicious execution.

The built-in rule at
`/var/ossec/ruleset/rules/0830-sysmon_id_11.xml` matches files under
`AppData\Local\Temp` with executable or script extensions, including `.ps1`.
It does not constrain the creating image or recognize PowerShell's
`__PSScriptPolicyTest_*.ps1` filename family. The built-in rule was not edited.

## Tuning Decision

Custom child rule `100110` requires all of the following:

1. Built-in rule `92213` matched first.
2. The creating image is the Windows PowerShell executable under
   `Windows\System32\WindowsPowerShell\v1.0`.
3. The target is a user Temp file matching
   `__PSScriptPolicyTest_*.ps1`.

The child rule downgrades that exact combination to level `3`. It does not
silence the event, so analysts retain a searchable audit record. It has no
MITRE ATT&CK mapping because the matched pattern is documented here as a known
benign operating-system and PowerShell behavior rather than validated
adversary activity.

The repository source is
[`lesson-13-powershell-policy-test-tuning.xml`](../detections/wazuh/lesson-13-powershell-policy-test-tuning.xml).

## Deployment Validation

The rule was installed as:

```text
/var/ossec/etc/rules/lesson-13-powershell-policy-test-tuning.xml
```

Validation established that:

- IDs `100001` and `100100` were already used; `100110` was available.
- The installed file inherited the owner, group, and mode of
  `local_rules.xml`.
- `wazuh-analysisd -t` returned exit code `0`.
- The Wazuh manager returned `active` after restart.
- Agent `001` (`SOC-WIN11`) reconnected as Active before testing.

The syntax test proved that Wazuh could parse the complete configuration. Live
positive and control events were still required to validate behavior.

## Known-Benign Test

The test created a harmless text file with a `.ps1` extension; the file was
not executed:

```cmd
powershell.exe -NoProfile -NonInteractive -Command "$path = Join-Path $env:LOCALAPPDATA 'Temp\__PSScriptPolicyTest_SOC-LAB-LESSON13.ps1'; Set-Content -Path $path -Value '# Lesson 13 benign policy-test simulation' -Force; Write-Output $path"
```

Observed result:

| Field | Value |
|---|---|
| Wazuh timestamp | `2026-09-27 02:42:09.072 UTC` |
| Agent | `001` (`SOC-WIN11`) |
| Sysmon event | Event ID `11`, record `108914` |
| Image | `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Target | `C:\Users\socadmin\AppData\Local\Temp\__PSScriptPolicyTest_SOC-LAB-LESSON13.ps1` |
| Resulting rule | `100110` |
| Resulting level | `3` |
| Result | **PASS - known-benign pattern was downgraded** |

Evidence:

- [Sanitized JSON excerpt](evidence/lesson-13-wazuh-rule-100110-powershell-policy-test-tuned-alert.json)
- [Complete Wazuh alert export](evidence/lesson-13-wazuh-rule-100110-powershell-policy-test-tuned-alert.pdf)

## Detection Control

The control used the same PowerShell image and Temp directory but a filename
outside the exception:

```cmd
powershell.exe -NoProfile -NonInteractive -Command "$path = Join-Path $env:LOCALAPPDATA 'Temp\SOC-LAB-LESSON13-CONTROL.ps1'; Set-Content -Path $path -Value '# Lesson 13 detection control' -Force; Write-Output $path"
```

Observed result:

| Field | Value |
|---|---|
| Wazuh timestamp | `2026-09-27 02:44:59.040 UTC` |
| Agent | `001` (`SOC-WIN11`) |
| Sysmon event | Event ID `11`, record `108926` |
| Image | `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Target | `C:\Users\socadmin\AppData\Local\Temp\SOC-LAB-LESSON13-CONTROL.ps1` |
| Resulting rule | `92213` |
| Resulting level | `15` |
| Result | **PASS - differently named control retained the original alert** |

Evidence:

- [Sanitized JSON excerpt](evidence/lesson-13-wazuh-rule-92213-powershell-temp-file-control-alert.json)
- [Complete Wazuh alert export](evidence/lesson-13-wazuh-rule-92213-powershell-temp-file-control-alert.pdf)

## Cleanup Validation

After preserving the alert evidence, both temporary validation files were
removed from `SOC-WIN11`. A direct `Test-Path` check returned `False` for:

```text
C:\Users\socadmin\AppData\Local\Temp\__PSScriptPolicyTest_SOC-LAB-LESSON13.ps1
C:\Users\socadmin\AppData\Local\Temp\SOC-LAB-LESSON13-CONTROL.ps1
```

- Result: **PASS - neither temporary test file remains on the endpoint**

Any file-deletion telemetry produced during cleanup is expected lab activity
and is separate from the file-creation tuning result.

## Conclusion

The tuning behaved as designed. The verified PowerShell policy-test pattern
was reduced from a level-15 malware-style alert to a level-3 informational
record, while a differently named `.ps1` file created by the same process in
the same directory continued to trigger rule `92213` at level `15`.

This result demonstrates a bounded false-positive tuning workflow: establish
the baseline, identify the exact cause, apply a narrow child rule, validate
the benign case, and test a nearby control to confirm that broader detection
coverage remains active.

## Limitations

- Validation covers one known-benign filename family and one control filename.
- The exception relies on process-path and filename evidence; an attacker who
  deliberately imitates both could receive the lower severity.
- Level `3` retains visibility but may receive less analyst attention than the
  original level `15` alert.
- Rule `92213` and its `T1105` mapping remain product-supplied indicators, not
  proof that every matching file was transferred by an adversary.

## Skills Demonstrated

- Root-cause analysis of a false-positive alert
- Native Wazuh parent-child rule tuning
- Severity calibration without complete suppression
- Expected-match and nearby-control test design
- Sysmon and Wazuh evidence correlation
- Evidence-based ATT&CK interpretation
- Sanitized technical documentation for portfolio review
