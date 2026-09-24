# Controlled Registry Run Key Simulation

## Objective

Lesson 10 validates whether the Mini SOC Lab can observe and detect a safe,
reversible Windows persistence behavior. The simulation creates one temporary
current-user Registry Run value on `SOC-WIN11`, verifies the resulting Sysmon
and Wazuh evidence, and removes the value without allowing its stored command
to execute.

This was an authorized lab exercise. It did not deploy malware, contact an
external system, or create a production persistence mechanism.

## Scope and Safety Boundaries

- Target: `SOC-WIN11`, Wazuh agent `001`
- Registry scope: `HKCU`, affecting only the current lab user
- Value name: `SocLabLesson10`
- Marker: `SOC-LAB-LESSON10-T1547-001`
- Network activity: None required
- Execution boundary: Do not log off or restart while the value exists
- Recovery: A suitable VM snapshot was confirmed before execution
- Cleanup: Delete the value and verify both Registry and filesystem state

The stored command was intentionally harmless. If Windows had executed it at a
future logon, it would only have written a marker string to a text file in the
lab user's Documents folder.

## ATT&CK Mapping

The simulated behavior maps to
[T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup
Folder](https://attack.mitre.org/techniques/T1547/001/).

Creating a value under the current user's `Run` key reproduces the observable
configuration behavior described by this sub-technique. The authorized test
validates defensive visibility; it does not imply malicious intent.

## Simulation Procedure

The initial query confirmed that the planned value was absent:

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SocLabLesson10
```

The controlled value was then created:

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SocLabLesson10 /t REG_SZ /d "cmd.exe /c echo SOC-LAB-LESSON10-T1547-001 > C:\Users\socadmin\Documents\soc-lab-lesson10.txt" /f
```

No logoff or restart was performed. The command was stored as Registry data but
was not intentionally executed.

## Telemetry and Detection Result

The Wazuh alert export verifies the complete collection and detection path:

| Field | Verified value |
|---|---|
| Endpoint | `SOC-WIN11` |
| Wazuh agent | `001` |
| Provider | `Microsoft-Windows-Sysmon` |
| Channel | `Microsoft-Windows-Sysmon/Operational` |
| Sysmon event | Event ID `13`, `SetValue` |
| Event record | `101507` |
| Process image | `C:\WINDOWS\system32\reg.exe` |
| Registry value | `...\CurrentVersion\Run\SocLabLesson10` |
| Marker | `SOC-LAB-LESSON10-T1547-001` |
| Wazuh rule | `92302`, level `6` |
| ATT&CK mapping | `T1547.001` |
| Result | **PASS - Wazuh generated the expected alert** |

Wazuh described the event as a Registry entry intended for execution at the
next logon being modified with `reg.exe`. This was an existing native Wazuh
rule, not a custom rule created for the exercise.

The cleaned source export is retained as
[`lesson-10-wazuh-rule-92302-t1547-001-registry-run-alert.pdf`](../docs/evidence/lesson-10-wazuh-rule-92302-t1547-001-registry-run-alert.pdf).

## Cleanup and Restored-State Validation

The temporary value was removed with:

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SocLabLesson10 /f
```

The following bounded checks were then performed:

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SocLabLesson10
```

Actual result:

```text
ERROR: The system was unable to find the specified registry key or value.
```

This proves that the temporary Run value was absent after cleanup.

The marker-file check was:

```cmd
if exist "C:\Users\socadmin\Documents\soc-lab-lesson10.txt" (echo WARNING: marker file exists) else (echo PASS: marker file was not created)
```

Actual result:

```text
PASS: marker file was not created
```

This proves that the stored command did not create its marker file. Together,
the two checks verify that the simulated persistence value was removed and the
endpoint returned to the intended state.

## Interpretation and Limitations

The exercise validates all of the following:

- The configured Sysmon policy records changes to the selected Run key.
- The Wazuh agent and manager preserve the relevant Registry-event fields.
- Native Wazuh rule `92302` alerts on this controlled `reg.exe` modification.
- The resulting alert carries the expected `T1547.001` mapping.
- The lab procedure includes explicit cleanup and restored-state validation.

The result does not establish that every Registry persistence variation will
be detected. It tested one current-user Run value created with `reg.exe`.
Different Registry paths, tools, users, or tampering methods require separate
tests. The alert also does not prove malicious intent without supporting
context and investigation.

## Skills Demonstrated

- Designing a bounded and reversible security simulation
- Validating Windows Registry telemetry with Sysmon
- Correlating endpoint activity with a Wazuh alert
- Interpreting native rule metadata and ATT&CK mappings
- Separating observed behavior from assumptions about intent
- Verifying cleanup and preserving reviewable evidence
