# MITRE ATT&CK Coverage Matrix

## Purpose

This matrix maps the Mini SOC Lab's retained telemetry and validated detections
to MITRE ATT&CK Enterprise behaviors. It is an evidence register, not a claim
that malicious activity occurred and not a checklist claiming complete ATT&CK
coverage.

ATT&CK describes adversary behavior:

- A **tactic** describes the adversary's objective, such as Credential Access.
- A **technique** describes a general method used to achieve an objective.
- A **sub-technique** describes a more specific implementation of a technique.

An alert can carry an ATT&CK label without proving that the full behavior
occurred. This matrix therefore separates vendor-provided mappings from
analyst-validated coverage.

## Coverage States

| State | Meaning |
|---|---|
| Telemetry available | The lab collects fields relevant to the behavior, but no suitable detection has been validated. |
| Detection observed | A rule or alert containing the mapping fired, but the available test did not reproduce the complete ATT&CK behavior. |
| Behavior validated | Retained evidence demonstrates the behavior described by the technique, even if the activity was an authorized benign test. |
| Insufficient evidence | A possible behavior is suggested, but the retained evidence does not support a defensible mapping. |
| Gap | Required telemetry or detection coverage has not been implemented. |

These states describe defensive validation maturity. They do not classify an
event as benign or malicious; that determination belongs in the associated
triage record.

## Current Coverage

| Tactic | Technique | Platform | Lab data and detection | Mapping source | Validated state | Evidence-based assessment |
|---|---|---|---|---|---|---|
| Credential Access | [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Linux | Ubuntu `journald`/`sshd`; Wazuh rule `5710` | Wazuh alert | Detection observed | Rule `5710` carried this mapping, but the lab generated one invalid-user attempt with authentication disabled. ATT&CK describes password guessing as systematic, repetitive, or iterative password attempts, so the complete behavior was not validated. |
| Lateral Movement | [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/) | Linux | Ubuntu `journald`/`sshd`; Wazuh rule `5710` | Wazuh alert | Telemetry available | The event proves visibility into an SSH connection attempt. It did not use a valid account, establish a session, or move between compromised systems, so lateral movement was not validated. |
| Execution | [T1059.003 — Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | Windows | Sysmon process telemetry; Wazuh `Suspicious Windows cmd shell execution` alert | Analyst mapping from retained process evidence | Behavior validated | The retained event shows `cmd.exe` launching the documented `wevtutil.exe` and `findstr.exe` validation sequence. This validates command-shell telemetry and detection, not malicious intent. |
| Execution | [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Windows | Local Sysmon Event ID 1 process telemetry; no visible Wazuh alert for the Lesson 7 marker | Analyst mapping from a controlled test | Telemetry available | Sysmon record `5154`, created on 2026-09-02 at 00:30:26 local time, shows `cmd.exe` launching `powershell.exe` with marker `SOC-LAB-LESSON7-T1059-001`. No corresponding Wazuh alert was visible. PowerShell execution telemetry is therefore present on the endpoint, but alerting coverage for this test is not validated. |
| Defense Evasion | [T1070.004 — Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/) | Windows | Sysmon process telemetry; Wazuh rule `92021`, level `3` | Wazuh alert | Detection observed | Wazuh recorded the separate event on 2026-09-02 at 12:59:53.122 in the dashboard (Sysmon record `8222`). The Wazuh-agent parent launched PowerShell and removed its temporary `secpol.cfg` file, satisfying the vendor mapping. This was benign agent maintenance, not the Lesson 7 marker, and it does not establish detection coverage for `T1059.001`. |

## Lesson 7 Detection-Coverage Finding

The controlled PowerShell test separates two defensive capabilities that are
often described together:

1. **Telemetry coverage:** Sysmon recorded that `powershell.exe` ran, including
   its command line and parent process.
2. **Detection coverage:** No visible Wazuh alert was produced for that specific
   benign marker.

In practical terms, the endpoint recorded the activity, but the current Wazuh
rules did not turn that activity into a visible alert. This is a detection or
rule-matching opportunity rather than evidence that endpoint collection failed.
It provides a verified starting point for the custom-rule work planned for
Lesson 8.

The Wazuh-agent `secpol.cfg` deletion is documented as a separate observation. It
shows that another PowerShell-associated Sysmon event can satisfy an existing
Wazuh rule, but it must not be presented as the result of the controlled
PowerShell marker.

## Evidence Register

| Evidence | Supports |
|---|---|
| [`lesson-05-wazuh-linux-ssh-validation.png`](../screenshots/lesson-05-wazuh-linux-ssh-validation.png) | Rule `5710`, Wazuh-provided ATT&CK tags, source, account, and SSH failure details |
| [`lesson-06-linux-alert-surrounding-events.png`](../screenshots/lesson-06-linux-alert-surrounding-events.png) | Linux alert scope and absence of visible successful follow-on authentication |
| [`lesson-04-wazuh-sysmon-event-validation.png`](../screenshots/lesson-04-wazuh-sysmon-event-validation.png) | Windows command line, parent process, marker, and Sysmon telemetry |
| [`lesson-06-windows-alert-surrounding-events.png`](../screenshots/lesson-06-windows-alert-surrounding-events.png) | Windows process sequence and surrounding-event scope |
| [`lesson-06-alert-triage-worksheet.md`](../incident-reports/lesson-06-alert-triage-worksheet.md) | Analyst context, scope, dispositions, limitations, and responses |
| [`lesson-07-sysmon-powershell-marker.png`](../screenshots/lesson-07-sysmon-powershell-marker.png) | Local Sysmon Event ID 1, record `5154`, `powershell.exe` command line, unique Lesson 7 marker, and `cmd.exe` parent |
| [`lesson-07-wazuh-rule-92021-t1070-004.pdf`](evidence/lesson-07-wazuh-rule-92021-t1070-004.pdf) | Wazuh agent `001`, `SOC-WIN11`, Sysmon Event ID 1 record `8222`, `secpol.cfg` removal command, Wazuh-agent parent process, rule `92021`, level `3`, and vendor mapping `T1070.004` |

The Lesson 7 PowerShell Event ID 1 now has sanitized public screenshot evidence.
The separate rule `92021` observation is retained as a three-page PDF export so
the process, parent-process, rule, severity, and ATT&CK fields remain readable
in one evidence artifact.

## Mapping Rules

Future entries must follow these rules:

1. Link every technique to the official ATT&CK page.
2. Identify whether the mapping came from Wazuh, another detection source, or
   analyst interpretation.
3. Cite retained evidence for every claimed coverage state.
4. Do not equate a tool name, protocol, or alert tag with complete adversary
   behavior.
5. Do not classify authorized testing as malicious merely because its behavior
   maps to ATT&CK.
6. Downgrade the state when the evidence does not establish required elements
   such as repetition, valid credentials, execution, persistence, or lateral
   movement.

## Current Gaps and Next Validation Opportunities

- Generate a bounded password-guessing simulation only after defining a safe
  threshold, account-lockout protections, and cleanup procedure.
- Create and validate a custom Wazuh rule for the bounded PowerShell marker in
  Lesson 8, including expected-match and expected-nonmatch tests.
- Validate Windows or Linux persistence telemetry with an authorized,
  reversible simulation.
- Record ATT&CK version or access date when the matrix is finalized because
  technique definitions and detection guidance evolve.

## Official References

- [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/enterprise/)
- [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1021.004 — SSH](https://attack.mitre.org/techniques/T1021/004/)
- [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1070.004 — File Deletion](https://attack.mitre.org/techniques/T1070/004/)

Technique names and descriptions were reviewed against the live official
ATT&CK pages on 2026-09-10.
