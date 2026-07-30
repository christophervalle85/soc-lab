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

**Current phase:** Architecture and environment planning

## Planned Architecture

The laboratory will contain:

1. A central Wazuh server
2. A Windows endpoint monitored with Wazuh and Sysmon
3. An Ubuntu Linux endpoint monitored with Wazuh
4. An isolated virtual network for controlled simulations

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
- [ ] Virtual laboratory architecture
- [ ] Wazuh server deployment
- [ ] Windows endpoint deployment
- [ ] Linux endpoint deployment
- [ ] Sysmon configuration
- [ ] Custom Wazuh rules
- [ ] Sigma detection rules
- [ ] Controlled attack simulations
- [ ] Python alert-processing utility
- [ ] Three incident reports
- [ ] Final demonstration video

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
