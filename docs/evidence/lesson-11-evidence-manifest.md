# Lesson 11 Evidence Manifest

## Purpose

This manifest records the acquisition, verification, transfer, and use of the
native Windows event evidence supporting the Lesson 11 Registry Run-key
investigation. It distinguishes the native event-log export from the
human-readable and sanitized excerpts used in the public report.

## Native Evidence Item

| Field | Recorded value |
|---|---|
| Evidence ID | `L11-E01` |
| Filename | `lesson-11-sysmon-events-101530-101531.evtx` |
| Evidence type | Filtered native Windows Event Log export |
| Source endpoint | `SOC-WIN11` |
| Source channel | `Microsoft-Windows-Sysmon/Operational` |
| Source records | Event ID `1`, record `101530`; Event ID `11`, record `101531` |
| Collection date | 2026-09-25; exact collection time was not retained |
| Collector | Lab owner |
| Transfer method | Secure copy over the existing SSH connection from `SOC-WIN11` to the Mac repository workspace |
| File size after transfer | 69,632 bytes |
| SHA-256 on `SOC-WIN11` | `EA0F5204C82C0B39262E65296E87E6A9984774F51A9C48D3F398DA52D12ABAC8` |
| SHA-256 on Mac | `ea0f5204c82c0b39262e65296e87e6a9984774f51a9c48d3f398da52d12abac8` |
| Integrity result | **PASS - hashes match** |

## Acquisition Command

The lab owner exported only the two process-correlated records required for
the bounded investigation:

```cmd
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Users\socadmin\Documents\lesson-11-sysmon-events-101530-101531.evtx" /q:"*[System[(EventRecordID=101530 or EventRecordID=101531)]]" /ow:true
```

The SHA-256 acquisition hash was calculated on `SOC-WIN11`:

```cmd
powershell.exe -NoProfile -Command "Get-FileHash 'C:\Users\socadmin\Documents\lesson-11-sysmon-events-101530-101531.evtx' -Algorithm SHA256 | Format-List Path,Algorithm,Hash"
```

## Content Verification

The exported file was queried directly before transfer:

```cmd
wevtutil qe "C:\Users\socadmin\Documents\lesson-11-sysmon-events-101530-101531.evtx" /lf:true /f:text
```

The query returned exactly two displayed events:

1. Sysmon Event ID `1`, record `101530`: PowerShell process creation with PID
   `4500` and process GUID
   `{df1231d0-adf8-6ab4-4301-000000001000}`.
2. Sysmon Event ID `11`, record `101531`: temporary file creation by the same
   PID and process GUID.

The Mac copy was independently hashed with:

```bash
shasum -a 256 docs/evidence/lesson-11-sysmon-events-101530-101531.evtx
```

The Windows and Mac SHA-256 values match without regard to letter case. This
verifies that the transferred repository artifact is byte-for-byte identical
to the verified filtered export.

## Related Readable Evidence

The following artifacts are derived or sanitized presentation copies. They
support review but do not replace the native `.evtx` evidence:

- [`lesson-11-sysmon-event-101530-powershell-process.txt`](lesson-11-sysmon-event-101530-powershell-process.txt): readable excerpt of the process-creation fields used for correlation.
- [`lesson-11-wazuh-rule-92041-registry-process-alert.json`](lesson-11-wazuh-rule-92041-registry-process-alert.json): sanitized Wazuh alert excerpt for the `reg.exe` process.
- [`lesson-11-wazuh-rule-92213-powershell-temp-file-alert.json`](lesson-11-wazuh-rule-92213-powershell-temp-file-alert.json): sanitized Wazuh alert excerpt for the PowerShell-created temporary file.

## Handling Limitations

This record demonstrates evidence-integrity practices in an isolated homelab;
it is not represented as a legal chain of custody. The export was collected
after the original activity from the still-available endpoint log, and the
exact acquisition time was not recorded. The public Git repository is a
portfolio and version-control location, not controlled forensic-evidence
storage. A legal or disciplinary investigation would additionally follow the
organization's evidence policy, access controls, retention requirements, and
contemporaneous custody documentation.
