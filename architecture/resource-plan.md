# Mini SOC Lab Resource Plan

## Approved Virtual Machines

| System | vCPU | RAM | Virtual disk |
|---|---:|---:|---:|
| Wazuh server | 4 | 8 GB | 60 GB |
| Windows endpoint | 4 | 5 GB | 64 GB |
| Ubuntu endpoint | 2 | 3 GB | 40 GB |

## Estimated Combined Requirements

- Guest RAM: 16 GB when all three VMs are running
- Virtual storage: up to 164 GB using dynamically allocated disks
- Host operating-system resources must remain available

## Resource Rules

- Do not assign all physical RAM to guest machines.
- Leave enough RAM for the host operating system.
- Store VMs on an SSD when possible.
- Use dynamically allocated virtual disks when appropriate.
- Monitor free disk space throughout the project.
- Do not start every VM unless the current task requires it.

## Final Architecture Decision

- Hypervisor: VMware Fusion 26.0.0
- Guest architecture: ARM64
- Wazuh server operating system: Ubuntu Server 24.04 LTS ARM64
- Windows operating system: Windows 11 ARM64
- Ubuntu endpoint operating system: Ubuntu 24.04 LTS ARM64
- Allocation status: Approved by the project owner

The host has 24 GB of memory. Avoid routinely running all three guests at the
same time. Run the Wazuh server with only the endpoint needed for the current
exercise whenever practical.
