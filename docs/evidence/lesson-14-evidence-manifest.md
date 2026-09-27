# Lesson 14 Evidence Manifest

## Purpose

This manifest records the acquisition and integrity checks for the filtered
native Sysmon events used in the Lesson 14 capstone investigation. The `.evtx`
file is the retained event-log export; the related JSON files are reviewed,
human-readable Wazuh alert excerpts.

## Native evidence item

| Field | Recorded value |
|---|---|
| Evidence ID | `L14-E01` |
| Repository file | [`lesson-14-sysmon-events-109053-109056-109058.evtx`](lesson-14-sysmon-events-109053-109056-109058.evtx) |
| Type | Filtered native Windows Event Log export |
| Source endpoint and channel | `SOC-WIN11`; `Microsoft-Windows-Sysmon/Operational` |
| Exported records | Event ID `1`, record `109053`; Event ID `1`, record `109056`; Event ID `13`, record `109058` |
| Collection date | 2026-09-27; exact collection time was not retained |
| Collector | Lab owner |
| Transfer | Secure copy from the Windows SSH account to the Mac repository workspace |
| Mac file size | 69,632 bytes |
| SHA-256 on `SOC-WIN11` | `532F29C52E6701C106033A33BA677CEA7219868DFB1D8811188D3519CFD2D3A9` |
| SHA-256 on Mac | `532f29c52e6701c106033a33ba677cea7219868dfb1d8811188d3519cfd2d3a9` |
| Integrity result | **Pass — hashes match** |

## Acquisition and content check

The lab owner first confirmed that the destination path did not already
exist. The export command selected only the three record IDs needed for the
bounded process and Registry correlation:

```cmd
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Users\socadmin\Documents\lesson-14-sysmon-events-109053-109056-109058.evtx" /q:"*[System[(EventRecordID=109053 or EventRecordID=109056 or EventRecordID=109058)]]"
```

The owner queried the saved `.evtx` using `Get-WinEvent -Path`. The output
listed exactly three records: `109053` (Event ID `1`), `109056` (Event ID
`1`), and `109058` (Event ID `13`). The owner calculated SHA-256 on the saved
Windows file before transfer. This content check establishes which records
the export contains; the hash establishes a fingerprint of that file.

## Transfer and Mac verification

The lab owner copied the export using the existing `soc-win11` SSH alias and
`scp -p` to `docs/evidence/`. A SHA-256 calculation on the Mac copy matched
the Windows value, ignoring hexadecimal letter case. The local file was also
identified as a Windows Event Log export and measured at 69,632 bytes. The
hash match verifies that the retained copy is byte-for-byte identical to the
export checked on `SOC-WIN11`.

## Related reviewed evidence

- [`lesson-14-wazuh-rule-100100-powershell-alert.json`](lesson-14-wazuh-rule-100100-powershell-alert.json): Wazuh alert for the PowerShell process, derived from Sysmon record `109053`.
- [`lesson-14-wazuh-rule-92302-registry-run-alert.json`](lesson-14-wazuh-rule-92302-registry-run-alert.json): Wazuh alert for the Run-value change, derived from Sysmon record `109058`.
- [`lesson-14-capstone-plan.md`](../../simulations/lesson-14-capstone-plan.md): authorized command, observed checks, correlation, and cleanup record.

The JSON files omit nonessential metadata and normalize some display fields;
they are not substitutes for the native export. The `reg.exe` process event,
record `109056`, is present in the `.evtx` even though no corresponding Wazuh
alert excerpt was retained.

## Limitations

This is an integrity-checked, post-event filtered export from an isolated
homelab. It is not a forensic disk image or a legal chain-of-custody package.
The exact export and transfer times were not recorded. A public Git repository
is a portfolio and version-control location, not controlled evidence storage.
