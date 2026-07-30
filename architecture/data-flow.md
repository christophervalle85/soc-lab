# Security Data Flow

1. Activity occurs on a Windows or Linux endpoint.
2. The operating system or Sysmon generates an event.
3. The Wazuh agent collects the event.
4. The agent sends the event to the Wazuh server.
5. The Wazuh server decodes and evaluates the event.
6. Matching detection rules generate alerts.
7. The Wazuh indexer stores the alerts.
8. The Wazuh dashboard makes the alerts searchable.
9. The analyst investigates related activity.
10. Findings are documented in an incident report.

## Initial Architecture

```text
                    Host Computer
                         |
                Virtualization Platform
                         |
                 Isolated Lab Network
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
  Wazuh Server      Windows 11       Ubuntu Linux
  Central Node      Endpoint          Endpoint
  - Manager         - Wazuh agent     - Wazuh agent
  - Indexer         - Sysmon          - Auth logs
  - Dashboard       - Event logs      - System logs
        |                |                |
        +------ receives security data ---+
