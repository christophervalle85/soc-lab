# Virtual-Machine Snapshot Plan

## Wazuh Server

- [x] `01-clean-os` — updated Ubuntu ARM64 baseline with validated SSH and
  networking, before Wazuh installation
- [x] `02-wazuh-installed` — verified Wazuh manager, indexer, dashboard,
  Filebeat, ports, and Mac dashboard access
- `03-agents-connected`
- `04-before-custom-rules`

## Windows Endpoint

- [x] `01-clean-windows` — updated Windows 11 ARM64 baseline with VMware Tools,
  SSH, both network adapters, internet access, and Wazuh reachability validated
- [x] `02-sysmon-installed` — Sysmon 15.21 ARM64 service, driver,
  configuration, and Operational event logging validated
- [x] `03-wazuh-agent-installed` — enrolled Wazuh agent, Sysmon event-channel
  collection, active dashboard status, and end-to-end telemetry validated
- `04-before-simulation`

## Ubuntu Endpoint

- [x] `01-clean-ubuntu` — fresh Ubuntu 24.04.4 ARM64 installation with static
  lab networking and key-based SSH validated
- [x] `02-updated` — current Ubuntu updates applied; post-reboot identity,
  routing, SSH, DNS, and outbound HTTPS validated
- [x] `03-wazuh-agent-installed` — Wazuh agent `4.14.7-1` active and
  controlled SSH authentication telemetry validated as rule `5710`
- `04-before-simulation`

## Rules

- Take a snapshot before major configuration changes.
- Take a snapshot before controlled simulations.
- Use descriptive names.
- Record why each snapshot was created.
- Confirm that restoration works before relying on snapshots.
- Do not treat snapshots as backups.
