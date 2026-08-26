# Virtual-Machine Snapshot Plan

## Wazuh Server

- [x] `01-clean-os` — updated Ubuntu ARM64 baseline with validated SSH and
  networking, before Wazuh installation
- [x] `02-wazuh-installed` — verified Wazuh manager, indexer, dashboard,
  Filebeat, ports, and Mac dashboard access
- `03-agents-connected`
- `04-before-custom-rules`

## Windows Endpoint

- `01-clean-windows`
- `02-updated`
- `03-wazuh-agent-installed`
- `04-sysmon-installed`
- `05-before-simulation`

## Ubuntu Endpoint

- `01-clean-ubuntu`
- `02-updated`
- `03-wazuh-agent-installed`
- `04-before-simulation`

## Rules

- Take a snapshot before major configuration changes.
- Take a snapshot before controlled simulations.
- Use descriptive names.
- Record why each snapshot was created.
- Confirm that restoration works before relying on snapshots.
- Do not treat snapshots as backups.
