# Capstone Case Report: Controlled PowerShell and Run-Key Activity

## Executive summary

Wazuh reported a PowerShell process under custom rule `100100` and a Registry
Run-key modification under built-in rule `92302` on `SOC-WIN11`. Investigation
linked both alerts to one authorized lab command. Sysmon records show
`cmd.exe` launching PowerShell, PowerShell launching `reg.exe`, and that
`reg.exe` setting the planned `SocLabCapstone` Run value. The process GUIDs
connect the three events, rather than timing alone.

The value contained a harmless command that would write a text marker if run
at a later sign-in. The value was confirmed present after the test, then
deleted and confirmed absent. The marker file was absent at both observed
post-command checks. The reviewed evidence does **not** show the stored
command executing. This case is classified as an **authorized simulation with
benign true-positive alerts**, not an unauthorized intrusion. That conclusion
applies to the bounded activity and evidence reviewed here; it is not a claim
that every event on the endpoint was examined.

## Scope and case identification

| Field | Finding |
|---|---|
| Endpoint | `SOC-WIN11`, Wazuh agent `001` |
| Lab account | `SOC-WIN11\socadmin` |
| Activity date | 2026-09-26 CDT / 2026-09-27 UTC |
| Registry value | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SocLabCapstone` |
| PowerShell marker | `SOC-LAB-LESSON8-T1059-001` |
| Stored-command marker | `SOC-LAB-CAPSTONE-001` |
| Detections reviewed | Wazuh `100100` (level `5`) and `92302` (level `6`) |
| Native evidence | Sysmon records `109053`, `109056`, and `109058` |
| Disposition | Authorized lab simulation; benign true-positive detections |

The investigation was limited to the documented command, the two matching
Wazuh alerts, three correlated Sysmon events, and the owner's preflight and
cleanup checks. A screenshot of the Wazuh query showed two matching rows for
agent `001` and these rule IDs within the selected 2026-09-26 22:00–23:30
local dashboard range. That query did not survey every rule or endpoint.

## Timeline

Times below are 24-hour UTC. The dashboard displayed the corresponding
activity at about 2026-09-26 22:41 CDT (UTC−05:00). The owner's preflight
and cleanup outputs did not include exact timestamps, so they are shown in
sequence without invented times.

| UTC time | Observation | Evidence |
|---|---|---|
| Before 03:41:20 | `SocLabCapstone` value and planned marker file were absent; agent `001` was Active. | Owner-provided preflight and `agent_control -l` output, summarized in the [case plan](../simulations/lesson-14-capstone-plan.md). |
| 03:41:20.069 | `cmd.exe` launched PowerShell PID `6912`. The command line printed the Lesson 8 detection marker and called `reg.exe add` for `SocLabCapstone`. | Sysmon Event ID `1`, record `109053`; [Wazuh `100100` excerpt](../docs/evidence/lesson-14-wazuh-rule-100100-powershell-alert.json). |
| 03:41:20.403 | PowerShell PID `6912` launched `reg.exe` PID `1816` with the planned Run-value command. | Sysmon Event ID `1`, record `109056`, retained in the [native export](../docs/evidence/lesson-14-sysmon-events-109053-109056-109058.evtx). |
| 03:41:20.414 | The same `reg.exe` process set the `SocLabCapstone` Run value to the planned marker command. | Sysmon Event ID `13`, record `109058`; [Wazuh `92302` excerpt](../docs/evidence/lesson-14-wazuh-rule-92302-registry-run-alert.json). |
| 03:41:21.174 | Wazuh emitted rule `100100`, level `5`, for the PowerShell event. | [Reviewed alert excerpt](../docs/evidence/lesson-14-wazuh-rule-100100-powershell-alert.json). |
| 03:41:21.217 | Wazuh emitted rule `92302`, level `6`, for the Registry change. | [Reviewed alert excerpt](../docs/evidence/lesson-14-wazuh-rule-92302-registry-run-alert.json). |
| After the command; exact times not recorded | A Registry query found the planned `REG_SZ` value; the marker file was absent. The owner then deleted only `SocLabCapstone`; a second query found it absent, and the marker file was still absent. | Owner-provided command output, summarized in the [case plan](../simulations/lesson-14-capstone-plan.md). |

## Evidence and correlation

The PowerShell process in record `109053` has process GUID
`{df1231d0-9060-6ab8-9806-000000001000}`. The `reg.exe` process in record
`109056` names that exact GUID as its `ParentProcessGuid` and records parent
PID `6912`. The Registry SetValue event in record `109058` has the same
`reg.exe` process GUID as record `109056`:
`{df1231d0-9060-6ab8-9906-000000001000}`. This establishes the observed
PowerShell → `reg.exe` → Run-value chain. The lab account, value name, stored
marker, and close timestamps agree with the documented test.

The owner queried the live Registry after running the command and saw
`SocLabCapstone` as `REG_SZ` with data that would write
`SOC-LAB-CAPSTONE-001` to a text file. Setting a Run value is a configuration
change; it is not evidence that Windows executed the stored command. The
documented procedure did not include sign-out or restart while the value
existed, and the marker file was absent at both observed checks. These
observations support the bounded conclusion that no stored-command execution
was observed, not the
stronger claim that execution was impossible or could never have occurred.

The three Sysmon records are preserved together in a filtered `.evtx` file.
The owner verified its record IDs and Event IDs on `SOC-WIN11`. SHA-256 on the
Windows export and Mac repository copy matched:

```text
532f29c52e6701c106033a33ba677cea7219868dfb1d8811188d3519cfd2d3a9
```

The [evidence manifest](../docs/evidence/lesson-14-evidence-manifest.md)
records the export, content check, transfer, and handling limitations.

## Detection and ATT&CK assessment

| Mapping | Assessment |
|---|---|
| [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | **Observed behavior.** PowerShell executed the controlled command. Rule `100100` correctly detected its deliberately included fixed marker. It is a narrow lab validation rule, not proof that all PowerShell use would alert. |
| [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/) | **Observed behavior.** Sysmon record `109058` shows `reg.exe` setting a Registry value. This is an analyst assessment of the event, not a separate alert in the retained pair. |
| [T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | **Observed configuration.** Rule `92302` correctly identified a value under the current-user Run key. The key was capable of starting its stored command at a later sign-in, but the reviewed evidence does not show that happening. |

ATT&CK describes behaviors adversaries may use; an ATT&CK mapping does not
turn an authorized exercise into malicious activity. The event content and
operator context support both alerts as benign true positives. No claim of
privilege escalation is made from the Run-key change or the alert metadata.

## Disposition, response, and limits

The activity matched the documented, authorized simulation on the intended
endpoint. Cleanup output shows the specific Run value absent after deletion;
the planned text marker file was absent at the observed checks. No containment
or account action was warranted for this controlled test. The case can be
closed within its defined scope after repository review.

This was not an exhaustive endpoint investigation. The retained `.evtx`
contains only three selected events; the Wazuh excerpts represent two selected
alerts, and the dashboard query filtered to their rule IDs. The report does
not establish whether unrelated alerts occurred nearby or whether other
endpoints had unrelated activity. Preflight and cleanup checks came from
owner-provided console output without retained native timestamps. The
post-event export and matching hashes demonstrate transfer integrity, not a
legal chain of custody. The public repository is a portfolio record, not
controlled forensic storage.
