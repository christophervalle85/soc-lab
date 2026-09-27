# Lesson 14 Capstone Case Plan

## Case question

Can the lab reconstruct one controlled Windows execution and persistence
sequence, distinguish observed behavior from alert labels, and support a clear
case disposition with preserved evidence?

This is an authorized exercise on `SOC-WIN11` (Wazuh agent `001`). A harmless
PowerShell command will launch `reg.exe` to create one temporary current-user
Run value. The stored command would write only a synthetic marker file if it
were executed at a later sign-in. The exercise will not sign out or restart
Windows while the value exists.

## Why this scenario

The lab has already validated PowerShell rule `100100`, Registry Run rule
`92302`, and the narrow PowerShell policy-test tuning rule `100110`. This
capstone combines those known data sources in one case. The investigation
must establish which events belong to the controlled command, whether the Run
value was executed, whether any nearby alert is unrelated, and which ATT&CK
behaviors the evidence actually supports.

## Scope and markers

| Item | Planned value |
|---|---|
| Endpoint | `SOC-WIN11` |
| Lab account | `socadmin` |
| Wazuh agent | `001` |
| Registry path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Temporary value | `SocLabCapstone` |
| Stored-command marker | `SOC-LAB-CAPSTONE-001` |
| PowerShell detection marker | `SOC-LAB-LESSON8-T1059-001` |
| Potential marker file | `C:\Users\socadmin\Documents\soc-lab-capstone.txt` |

The existing Lesson 8 marker is included in the PowerShell command only to
exercise the already validated rule `100100`. The distinct capstone marker
identifies the temporary Registry value and potential output file.

The expected ATT&CK behaviors are `T1059.001` (PowerShell execution),
`T1112` (Registry modification), and `T1547.001` (Run-key persistence
configuration). The final report will assess each mapping against the actual
records and the exercise authorization; a product tag alone is not a finding
of malicious activity.

## Preparation

1. Confirm `soc-wazuh` is healthy and agent `001` is Active.
2. Confirm the planned Registry value and marker file are absent.
3. Create a fresh `SOC-WIN11` VMware snapshot and record its exact name and
   time. Existing snapshots must be preserved.
4. Review the exact simulation and cleanup commands before execution.

Read-only preflight checks:

```bash
# On soc-wazuh: list all registered agents and their connection status.
sudo /var/ossec/bin/agent_control -l
```

```cmd
rem On SOC-WIN11: the planned value and file should both be absent.
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SocLabCapstone
if exist "C:\Users\socadmin\Documents\soc-lab-capstone.txt" (echo WARNING: marker file exists) else (echo PASS: marker file absent)
```

The project owner ran both Windows baseline checks. `reg query` returned
"The system was unable to find the specified registry key or value" for
`SocLabCapstone`, and the file check returned `PASS: marker file absent`.
These results establish that neither planned artifact was present at this
preflight checkpoint. The project owner's `agent_control -l` output listed
`SOC-WIN11` (agent `001`) as `Active`; `SOC-UBUNTU` (`002`) was `Disconnected`.
The Ubuntu endpoint is outside this Windows-only exercise. The project owner
reports creating a fresh `SOC-WIN11` snapshot on 2026-09-26 at 22:34 local
time; its VMware label has not been provided. No Lesson 14 simulation command
had been run at the end of preflight.

## Controlled simulation — command result

The project owner then ran this command once from `cmd.exe` on `SOC-WIN11`:

```cmd
powershell.exe -NoProfile -NonInteractive -Command "Write-Output 'SOC-LAB-LESSON8-T1059-001'; reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v SocLabCapstone /t REG_SZ /d 'cmd.exe /c echo SOC-LAB-CAPSTONE-001 > C:\Users\socadmin\Documents\soc-lab-capstone.txt' /f"
```

The console printed `SOC-LAB-LESSON8-T1059-001`, and `reg.exe` reported
"The operation completed successfully." This is evidence that the command
ran and `reg.exe` reported success. The project owner then queried the Run
key. It contained `SocLabCapstone` as a `REG_SZ` value with the planned
`cmd.exe /c echo SOC-LAB-CAPSTONE-001 > C:\Users\socadmin\Documents\soc-lab-capstone.txt`
data. The follow-up file check returned `PASS: marker file absent`. This
confirms the value was present and the marker file was absent at that check;
it does not by itself establish whether Sysmon or Wazuh recorded the activity.

## Cleanup and time boundary

The project owner ran `reg delete` against only the `SocLabCapstone` Run value.
`reg.exe` reported "The operation completed successfully." A follow-up
`reg query` returned "The system was unable to find the specified registry
key or value," and the file check returned `PASS: marker file absent`.
The temporary value was therefore absent after cleanup, and the marker file
was absent at both observed post-command checks. No exact timestamp was
captured from the Windows command output. The owner reported the snapshot at
2026-09-26 22:34 local time; this progress checkpoint was recorded by
2026-09-26 22:51 CDT (2026-09-27 03:51 UTC). The simulation and cleanup
occurred within those bounds. For the later Wazuh search, start with
2026-09-26 22:30–23:00 local dashboard time and refine using the actual event
timestamps. The alert search and record-level verification follow below.

## Initial Wazuh alert search

An owner-provided Wazuh Threat Hunting screenshot shows two hits for agent
`001` under `agent.id:001 and (rule.id:100100 or rule.id:92302)` with the
dashboard range 2026-09-26 22:00–23:30 local time. Both rows display
approximately 22:41:21 local dashboard time:

| Rule | Level | Displayed description |
|---|---:|---|
| `100100` | 5 | Controlled Lesson 8 PowerShell validation marker detected on SOC-WIN11 |
| `92302` | 6 | Registry entry to be executed on next logon was modified using command line application reg.exe |

The screenshot supports that both expected alert rules fired in the bounded
window. The owner subsequently supplied both full alert records. Reviewed
excerpts are retained as
[`100100` PowerShell alert](../docs/evidence/lesson-14-wazuh-rule-100100-powershell-alert.json)
and
[`92302` Registry alert](../docs/evidence/lesson-14-wazuh-rule-92302-registry-run-alert.json).

| UTC event time | Source | Verified observation |
|---|---|---|
| 2026-09-27 03:41:20.069 | Sysmon Event ID `1`, record `109053` | `powershell.exe` PID `6912`, process GUID `{df1231d0-9060-6ab8-9806-000000001000}`, launched by `cmd.exe`; command line includes both controlled markers and the `reg.exe add` command |
| 2026-09-27 03:41:20.403 | Sysmon Event ID `1`, record `109056` | `reg.exe` PID `1816`, process GUID `{df1231d0-9060-6ab8-9906-000000001000}`, has parent PID `6912` and parent process GUID `{df1231d0-9060-6ab8-9806-000000001000}`; its command line adds `SocLabCapstone` |
| 2026-09-27 03:41:20.414 | Sysmon Event ID `13`, record `109058` | `reg.exe` PID `1816`, process GUID `{df1231d0-9060-6ab8-9906-000000001000}`, set the `SocLabCapstone` Run value to the planned marker command |
| 2026-09-27 03:41:21.174 | Wazuh rule `100100` | Level `5` alert for the PowerShell process event |
| 2026-09-27 03:41:21.217 | Wazuh rule `92302` | Level `6` alert for the Registry SetValue event |

The owner-provided `Get-WinEvent` output for record `109056` confirms direct
parentage: its `ParentProcessGuid` equals the PowerShell `ProcessGuid` in
record `109053`. Its own `ProcessGuid` equals the `reg.exe` GUID in the
Registry SetValue record `109058`. Together, the three records support the
controlled PowerShell → `reg.exe` → Run-value sequence. The native Sysmon
records have not yet been exported or hash-verified for retention. The stored
Run command was not observed executing; the marker file was absent at both
observed post-command checks.

## Expected evidence

| Source | Expected observation | What it can establish |
|---|---|---|
| Sysmon Event ID `1` | PowerShell process with the controlled marker | Process start, command line, user, parent, process GUID |
| Wazuh rule `100100` | Controlled PowerShell marker alert | Native custom detection fired for the process |
| Sysmon Event ID `1` | `reg.exe` child process | Parent-child link to PowerShell through process GUIDs |
| Sysmon Event ID `13` | `SocLabCapstone` Run value set | Registry modification and value data |
| Wazuh rule `92302` | Run-key modification alert | SIEM detection of persistence-capable configuration |
| Other nearby alerts | Assessed individually | Context; alert labels alone do not prove compromise |

The expected parent-child link and both alert IDs are verified in the
owner-provided records. The three correlated Sysmon records are now preserved
in a hash-verified native export; the final case assessment remains. A missing
alert would be documented as a visibility or detection finding rather than
silently treated as a pass.

The owner checked that
`C:\Users\socadmin\Documents\lesson-14-sysmon-events-109053-109056-109058.evtx`
did not already exist, then ran `wevtutil epl` with a filter for records
`109053`, `109056`, and `109058`. The command returned no error text. The
owner queried the exported file and confirmed exactly three entries: Event ID
`1` / record `109053`, Event ID `1` / record `109056`, and Event ID `13` /
record `109058`. The SHA-256 hash calculated on `SOC-WIN11` is
`532F29C52E6701C106033A33BA677CEA7219868DFB1D8811188D3519CFD2D3A9`.
The owner transferred the export to
[`docs/evidence/lesson-14-sysmon-events-109053-109056-109058.evtx`](../docs/evidence/lesson-14-sysmon-events-109053-109056-109058.evtx).
The Mac-side SHA-256 matches, confirming byte-for-byte transfer integrity.
The [evidence manifest](../docs/evidence/lesson-14-evidence-manifest.md)
records the acquisition, checks, transfer, and limitations.
The [capstone case report](../incident-reports/lesson-14-powershell-run-key-capstone.md)
is drafted for repository review. It assesses the two alerts, the process
chain, the Run-value change, cleanup, and the limits of the selected evidence.

## Investigation questions

1. Which process created the Run value, and who launched that process?
2. Do the PowerShell and Registry records form one causal sequence?
3. Which alerts describe the observed behavior accurately, and which attach
   unsupported malicious interpretations?
4. Did the stored command execute or create its marker file?
5. Was the activity limited to the authorized endpoint and lab account?

## Evidence handling

- Record a 24-hour UTC timeline and retain the original local offset when it
  helps explain dashboard timestamps.
- Preserve the relevant Wazuh alert JSON and a filtered native Sysmon `.evtx`
  export covering the key process and Registry records.
- Hash the native export on `SOC-WIN11` and after transfer to confirm that the
  repository copy is identical.
- Publish only reviewed, sanitized excerpts and the bounded native export.
- Review the drafted final case in `incident-reports/` for evidence links,
  ATT&CK assessment, disposition, cleanup, and limitations.

## Cleanup and completion criteria

The temporary `SocLabCapstone` Run value was deleted and confirmed absent;
the marker file was absent at both observed post-command checks. Preserve
the VM snapshot as a recovery point. The case is complete when its timeline and
disposition are supported by the retained records, the endpoint is restored
to the intended state, and the report and evidence pass repository review.
