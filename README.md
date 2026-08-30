# Mini SOC Lab

A portfolio-focused Security Operations Center laboratory for developing
practical experience in:

- Security monitoring
- Windows and Linux telemetry
- Wazuh SIEM administration
- Sysmon
- Detection engineering
- Sigma rules
- MITRE ATT&CK
- Incident investigation
- Python security automation
- Technical reporting

## Project Status

**Current phase:** Lesson 6 alert triage is complete; the validated Ubuntu SSH
and Windows Sysmon alerts were investigated and classified as benign true
positives

## Lab Architecture

The laboratory uses VMware Fusion 26 on an Apple Silicon host. All guest
systems use ARM64 operating-system images.

| System | Operating system | vCPU | RAM | Disk | Lab IP |
|---|---|---:|---:|---:|---|
| Wazuh server | Ubuntu Server 24.04 LTS ARM64 | 4 | 8 GB | 60 GB | `192.168.132.10` |
| Windows endpoint | Windows 11 ARM64 | 4 | 5 GB | 64 GB | `192.168.132.20` |
| Linux endpoint | Ubuntu 24.04 LTS ARM64 | 2 | 3 GB | 40 GB | `192.168.132.30` |

The Wazuh server uses an all-in-one deployment containing the manager, indexer,
and dashboard. It is reachable from the Mac host at
`https://192.168.132.10` on the private lab network.

## Network Isolation

- VMware `vmnet1` provides the private host-only lab network at
  `192.168.132.0/24`.
- Static lab addresses are outside VMware's DHCP pool.
- NAT is used temporarily for trusted updates and package installation.
- Bridged networking is not used.
- NAT can be disconnected during controlled simulations that do not require
  internet access.

## Project Objectives

- Collect Windows and Linux security telemetry
- Generate controlled security activity
- Write and validate custom detections
- Map detections to MITRE ATT&CK
- Investigate resulting alerts
- Produce professional incident reports
- Automate parts of the investigation workflow with Python

## Planned Deliverables

- [x] Project directory structure
- [x] Initial objectives
- [x] Safety boundaries
- [x] Initial data-flow documentation
- [x] Virtual laboratory architecture
- [x] Wazuh server deployment
- [x] Windows endpoint deployment
- [x] Linux endpoint deployment
- [x] Sysmon configuration
- [x] Reusable alert-triage worksheet and two worked cases
- [ ] Custom Wazuh rules
- [ ] Sigma detection rules
- [ ] Controlled attack simulations
- [ ] Python alert-processing utility
- [ ] Three incident reports
- [ ] Final demonstration video

## Architecture Documentation

- [Data flow](architecture/data-flow.md)
- [Network plan](architecture/network-plan.md)
- [Resource plan](architecture/resource-plan.md)
- [Snapshot plan](architecture/snapshot-plan.md)
- [Host specifications](docs/host-specifications.md)
- [Wazuh server deployment](docs/wazuh-server-deployment.md)
- [Windows endpoint deployment and validation](docs/windows-endpoint-deployment.md)
- [Linux endpoint deployment and validation](docs/linux-endpoint-deployment.md)
- [Alert triage worksheet](incident-reports/lesson-06-alert-triage-worksheet.md)
- [Safety boundaries](docs/safety-boundaries.md)

## Current Milestone

The `soc-wazuh` ARM64 server is operational. Windows endpoint `SOC-WIN11`
(`001`) forwards Sysmon telemetry, and Ubuntu endpoint `SOC-UBUNTU` (`002`)
forwards Linux system and authentication telemetry. Controlled, benign tests
were visible in Wazuh Threat Hunting for both endpoints.

![Validated Sysmon event from SOC-WIN11](screenshots/lesson-04-wazuh-sysmon-event-validation.png)

![Validated Linux SSH event from SOC-UBUNTU](screenshots/lesson-05-wazuh-linux-ssh-validation.png)

Powered-off `03-wazuh-agent-installed` snapshots preserve both validated
endpoint states. The Linux rule `5710` alert has now been investigated using a
repeatable triage workflow and classified as a high-confidence benign true
positive. The same workflow has now been applied to the Windows Sysmon marker
alert, including parent-child process correlation and surrounding-event
review. The completed worksheet preserves both investigations and their
supporting evidence; the next milestone is MITRE ATT&CK mapping.

## Repository Structure

```text
mini-soc-lab/
├── architecture/
├── automation/
├── detections/
│   ├── sigma/
│   └── wazuh/
├── docs/
├── incident-reports/
├── sample-data/
├── screenshots/
├── simulations/
├── tests/
├── .gitignore
└── README.md
