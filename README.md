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

**Current phase:** Windows endpoint, Sysmon telemetry, and Wazuh agent
integration validated; Lesson 4 documentation is ready for review

## Lab Architecture

The laboratory uses VMware Fusion 26 on an Apple Silicon host. All guest
systems use ARM64 operating-system images.

| System | Operating system | vCPU | RAM | Disk | Lab IP |
|---|---|---:|---:|---:|---|
| Wazuh server | Ubuntu Server 24.04 LTS ARM64 | 4 | 8 GB | 60 GB | `192.168.132.10` |
| Windows endpoint | Windows 11 ARM64 | 4 | 5 GB | 64 GB | `192.168.132.20` |
| Linux endpoint | Ubuntu 24.04 LTS ARM64 | 2 | 2 GB | 40 GB | `192.168.132.30` |

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
- [ ] Linux endpoint deployment
- [x] Sysmon configuration
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
- [Safety boundaries](docs/safety-boundaries.md)

## Current Milestone

The `soc-wazuh` ARM64 server is operational, and the Windows 11 ARM64 endpoint
`SOC-WIN11` is enrolled as Wazuh agent `001`. Sysmon process and file telemetry
was validated locally and through Wazuh Threat Hunting. A benign marker test
produced an alert containing the endpoint identity, command line, parent
process, integrity level, and executable hash.

![Validated Sysmon event from SOC-WIN11](screenshots/lesson-04-wazuh-sysmon-event-validation.png)

The powered-off `03-wazuh-agent-installed` VMware snapshot preserves the
validated endpoint state. The remaining Lesson 4 checkpoint is the reviewed
Git commit; the next implementation milestone is deploying the Ubuntu
endpoint.

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
