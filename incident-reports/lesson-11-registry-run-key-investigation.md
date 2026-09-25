# Lesson 11 Incident Report: Registry Run-Key Alert Investigation

## Executive Summary

Wazuh rule `92302` reported a Registry Run-key modification on Windows
endpoint `SOC-WIN11`. The alert described a persistence-relevant behavior and
mapped it to MITRE ATT&CK `T1547.001` (Registry Run Keys / Startup Folder).

Investigation confirmed that the Registry value was created during the
authorized Lesson 10 simulation. Sysmon process and Registry telemetry linked
Wazuh rules `92041` and `92302` to the same `reg.exe` process and the documented
`SocLabLesson10` marker. A nearby severity-15 rule `92213` alert was initially
concerning, but process-GUID correlation showed that it came from a later
PowerShell command used by the lab owner to inspect Sysmon evidence. The
record contained no evidence of a downloaded tool or network transfer.

The case is closed as an **authorized security-lab simulation with benign
analyst activity**. No unauthorized persistence, payload transfer, stored-
command execution, or additional affected endpoint was identified within the
reviewed evidence. Cleanup checks confirmed that the Run value was removed and
that its harmless marker command did not create the intended output file.

## Case Identification

| Field | Finding |
|---|---|
| Case title | Controlled Registry Run-key alert investigation |
| Analyst | Lab owner |
| Investigation dates | 2026-09-24 through 2026-09-25 |
| Primary alert time | 2026-09-23 23:57:20.183 CDT, Wazuh dashboard time |
| Primary endpoint | `SOC-WIN11`, Wazuh agent `001` |
| Primary detection | Wazuh rule `92302`, level `6` |
| Related detections | Wazuh rules `92041` and `92213` |
| Primary data source | Microsoft-Windows-Sysmon/Operational |
| Final disposition | Authorized simulation; no evidence of compromise |
| Confidence | High |

## Investigation Questions

The investigation sought to answer four bounded questions:

1. Did rule `92302` identify unauthorized persistence or the authorized
   Lesson 10 simulation?
2. Was nearby rule `92041` a separate event or another observation of the same
   Registry command?
3. Did severity-15 rule `92213` indicate that a tool or payload entered the
   endpoint?
4. Did the command stored in the temporary Run value execute or leave
   persistence behind?

## Scope and Data Sources

The review covered Wazuh alerts for agent `001`, the full JSON documents for
rules `92041` and `92213`, the preserved rule `92302` export, and the local
Sysmon process event that matched the rule `92213` process GUID. Sysmon records
`101530` and `101531` were subsequently preserved together in a filtered
native `.evtx` export and verified before and after transfer with matching
SHA-256 hashes. The corrected Wazuh timeline export contained 253 alert rows
from 2026-09-23 23:43:08.610 through 2026-09-24 13:48:31.256 in dashboard
time. A bounded 2026-09-23 23:52 through 2026-09-24 00:02 review contained 22
alerts and one rule `92302` result.

The full CSV was used as working evidence but was not retained in the public
repository because most rows were unrelated background alerts. The report
preserves the relevant timeline and links the source records used for its
conclusions.

## Chronological Timeline

Dashboard and endpoint-local timestamps below use 24-hour Central Daylight
Time (UTC-05:00). UTC values are included where the source record supplied
them.

| Local time | Event | Evidence and interpretation |
|---|---|---|
| 2026-09-23 23:57:19.077 | `reg.exe` started as PID `2724` | Sysmon Event ID `1`, record `101505`, preserved by rule `92041`. Its command line contains the documented Run-key path, value name, and Lesson 10 marker. |
| 2026-09-23 23:57:20.178 | Wazuh emitted rule `92041` | The rule labeled the value as having a Base64-like pattern. The command is visible as plain text, so the obfuscation interpretation is unsupported. |
| Approximately 2026-09-23 23:57:19 | The Run value was set | Sysmon Event ID `13`, record `101507`, contains the same PID and process GUID as the `reg.exe` process. |
| 2026-09-23 23:57:20.183 | Wazuh emitted rule `92302` | The native rule detected modification of a Registry entry intended for execution at logon and mapped it to `T1547.001`. |
| 2026-09-23 23:58:32.062 | PowerShell started as PID `4500` | Local Sysmon Event ID `1`, record `101530`, shows an authorized `Get-WinEvent` command used to inspect the Lesson 10 Registry telemetry. |
| 2026-09-23 23:58:32.194 | The same PowerShell process created `__PSScriptPolicyTest_udiwgrly.l3d.ps1` | Sysmon Event ID `11`, record `101531`, shares PID `4500` and process GUID `{df1231d0-adf8-6ab4-4301-000000001000}` with the analyst's PowerShell query. |
| 2026-09-23 23:58:33.183 | Wazuh emitted rule `92213` | The rule labeled the temporary file as an executable dropped in a malware-associated folder and mapped it to `T1105`. No transfer evidence was present. |
| After validation | The temporary Run value was removed | A bounded Registry query returned that `SocLabLesson10` could not be found. |
| After validation | Stored-command execution was checked | The expected marker file did not exist, supporting that the stored command did not execute during the exercise. |

## Evidence Analysis

### Rule 92041: Process creation associated with the Registry command

Rule `92041` contains Sysmon Event ID `1`, record `101505`. It establishes the
following observed facts:

- `C:\Windows\System32\reg.exe` ran as PID `2724`.
- Its process GUID was
  `{df1231d0-adaf-6ab4-3e01-000000001000}`.
- `cmd.exe` was the parent process.
- `SOC-WIN11\socadmin` ran the process at high integrity.
- The command added value `SocLabLesson10` under the current user's `Run` key.
- The stored data contained marker `SOC-LAB-LESSON10-T1547-001` and would
  write only a text file if later executed.

Rule `92302` preserved the same PID and process GUID in Sysmon Event ID `13`.
The two Wazuh alerts are therefore two telemetry views of one command, not two
incidents: Event ID `1` records the process starting, and Event ID `13` records
the Registry value change it performed.

The evidence supports `T1112` (Modify Registry). It does not support `T1027`
(Obfuscated Files or Information), because the visible command and marker are
plain text. The phrase "Base64-like pattern" records what the Wazuh rule
matched; it does not prove that obfuscation occurred.

Supporting excerpt:
[`lesson-11-wazuh-rule-92041-registry-process-alert.json`](../docs/evidence/lesson-11-wazuh-rule-92041-registry-process-alert.json)

### Rule 92302: Registry Run-key modification

Rule `92302` accurately identified the creation of a value beneath:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SocLabLesson10
```

This location can cause a command to run when the affected user signs in, so
the observed behavior supports `T1547.001`. The alert proves that a
persistence-capable configuration change occurred; it cannot determine by
itself whether the change was authorized.

The exact value name, marker, process, endpoint, and timing match the
documented Lesson 10 procedure. Operator context therefore establishes that
the modification was authorized. No logoff or restart occurred while the
value existed, and later validation found neither the value nor its expected
marker file.

Primary evidence:

- [`lesson-10-wazuh-rule-92302-t1547-001-registry-run-alert.pdf`](../docs/evidence/lesson-10-wazuh-rule-92302-t1547-001-registry-run-alert.pdf)
- [`lesson-10-registry-run-key-simulation.md`](../simulations/lesson-10-registry-run-key-simulation.md)

### Rule 92213: PowerShell temporary-file creation

Rule `92213` contains Sysmon Event ID `11`, record `101531`. It records
PowerShell PID `4500` creating:

```text
C:\Users\socadmin\AppData\Local\Temp\__PSScriptPolicyTest_udiwgrly.l3d.ps1
```

The Event ID `11` alert did not contain the creating process's command line.
An exact process-GUID search in Wazuh returned no Event ID `1` alert, showing
that the Wazuh alert index did not preserve every raw Sysmon event needed for
the investigation. The original Sysmon Operational log on `SOC-WIN11` was
therefore queried directly.

Local Sysmon Event ID `1`, record `101530`, identified the same PID and process
GUID. Its command line was the lab owner's `Get-WinEvent` query for the Lesson
10 marker and Registry Event ID `13`. `cmd.exe` was its parent, the user was
`SOC-WIN11\socadmin`, and the file event followed process creation by 0.132
seconds. This correlation attributes the temporary file to authorized analyst
activity.

The evidence contains no network connection, remote source, download command,
or transferred payload. Rule `92213` correctly observed a file creation, but
its `T1105` (Ingress Tool Transfer) interpretation is unsupported in this
case.

Supporting evidence:

- [`lesson-11-sysmon-events-101530-101531.evtx`](../docs/evidence/lesson-11-sysmon-events-101530-101531.evtx)
- [`lesson-11-wazuh-rule-92213-powershell-temp-file-alert.json`](../docs/evidence/lesson-11-wazuh-rule-92213-powershell-temp-file-alert.json)
- [`lesson-11-sysmon-event-101530-powershell-process.txt`](../docs/evidence/lesson-11-sysmon-event-101530-powershell-process.txt)

## Evidence Handling

The native Sysmon export contains only Event ID `1`, record `101530`, and Event
ID `11`, record `101531`. The lab owner verified both records in the exported
file before transfer. SHA-256 was then calculated on `SOC-WIN11` and again on
the Mac repository copy:

```text
EA0F5204C82C0B39262E65296E87E6A9984774F51A9C48D3F398DA52D12ABAC8
```

The hashes matched, verifying that the repository copy is byte-for-byte
identical to the filtered endpoint export. The complete acquisition record,
commands, content check, transfer method, and limitations are documented in
the [`Lesson 11 evidence manifest`](../docs/evidence/lesson-11-evidence-manifest.md).

The `.txt` and JSON files are sanitized, human-readable excerpts. They improve
reviewability but are not presented as substitutes for the native `.evtx`
artifact.

## ATT&CK Assessment

| Technique | Source | Assessment |
|---|---|---|
| `T1547.001` Registry Run Keys / Startup Folder | Rule `92302` | **Supported behavior.** A Run value was created, but it was an authorized and reversible simulation. |
| `T1112` Modify Registry | Rule `92041` | **Supported behavior.** The `reg.exe` command modified the Registry. |
| `T1027` Obfuscated Files or Information | Rule `92041` | **Not supported.** The retained command line is readable plain text and contains no encoded payload. |
| `T1105` Ingress Tool Transfer | Rule `92213` | **Not supported.** The temporary file was linked to the local analyst query, and no transfer evidence was observed. |

ATT&CK mappings are detection metadata, not automatic confirmation of attacker
behavior. Each mapping was evaluated against the underlying telemetry before
being accepted or rejected for this case.

## Scope, Impact, and Cleanup

- The investigated activity was limited to `SOC-WIN11`, agent `001`.
- The Registry path, value name, and marker matched the authorized Lesson 10
  procedure.
- No other endpoint or account was connected to the controlled action in the
  reviewed evidence.
- No payload download, network transfer, or unexpected child process was
  established.
- The temporary Run value was removed.
- The expected marker output file was absent, supporting that the stored
  command did not execute during the exercise.
- No containment, account disabling, or endpoint isolation was warranted.

## Disposition and Response

| Field | Finding |
|---|---|
| Overall disposition | **Authorized security-lab simulation with benign analyst activity** |
| Primary alert classification | **Benign true positive**: rule `92302` accurately detected a real persistence-capable Registry change, but the change was authorized. |
| Related rule `92041` | Same authorized command. `T1112` is supported; its obfuscation description and `T1027` mapping are unsupported. |
| Related rule `92213` | Benign PowerShell-generated temporary file. The malicious tool-transfer interpretation and `T1105` mapping are unsupported. |
| Confidence | **High** |
| Response | Document the authorized exercise, confirm cleanup, preserve evidence, and close the case. |
| Escalation or containment | None required. |
| Follow-up | Retain the case as a portfolio example of timeline reconstruction, process-GUID correlation, and ATT&CK validation. |

## Limitations

This was a bounded investigation, not a complete forensic examination. It
used the retained Wazuh alerts, selected local Sysmon records, the documented
simulation, and cleanup results. It did not include memory acquisition, a full
disk image, packet capture, or exhaustive review of every endpoint event.

The `.evtx` artifact is a post-event filtered export from an isolated homelab,
not a forensic image or a legal chain-of-custody package. The exact acquisition
time was not retained, and GitHub is not controlled evidence storage. The
artifact and manifest demonstrate integrity and provenance practices without
claiming legal admissibility.

Wazuh Threat Hunting exposed alert-producing records rather than a guaranteed
complete copy of raw Sysmon telemetry. The missing matching Event ID `1` alert
for PowerShell was recovered from the endpoint's original Sysmon log. A result
absent from the Wazuh alert index should therefore not be interpreted as proof
that the endpoint event never occurred.

## Skills Demonstrated

- Scoping a security alert investigation
- Reconstructing a cross-source event timeline
- Correlating process and file activity with process GUIDs
- Distinguishing alert data from underlying endpoint telemetry
- Separating observed evidence from analyst-supplied authorization context
- Validating rather than automatically accepting ATT&CK mappings
- Assigning a defensible disposition and proportionate response
- Verifying cleanup and documenting investigation limitations
