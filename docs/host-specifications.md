# Host Computer Specifications

## Operating System

- Name: macOS
- Version: 26.5.2
- Build: 25F84

## Processor

- Model: Apple M4
- Architecture: ARM64
- Total CPU cores: 10
- Performance cores: 4
- Efficiency cores: 6
- Physical CPUs reported by macOS: 10
- Logical CPUs reported by macOS: 10

## Memory

- Installed RAM: 24 GB

## Storage

- Internal filesystem capacity: ~1.8 TB
- Available free disk space at inspection: ~1.3 TB
- Storage type: SSD

## Virtualization

- Hardware virtualization support: Yes
- Selected hypervisor: VMware Fusion
- VMware Fusion version: 26.0.0 (build 25388279)
- Other installed hypervisor: UTM
- UTM version: 4.7.5
- UTM installation source: Manually downloaded through Google Chrome
- Homebrew installation detected: No
- Mac App Store receipt detected: No

## Architecture Decision

- Selected hypervisor: VMware Fusion 26.0.0
- Selected guest architecture: ARM64
- Full three-VM deployment feasible: Yes
- Wazuh deployment: All-in-one Wazuh installation on Ubuntu Server 24.04 LTS ARM64
- Required adjustments: Use ARM64-compatible guest operating systems and installation packages
- Compatibility limitation: Do not use the x86-64 Wazuh virtual appliance on this Apple Silicon host
- Decision status: Final and approved by the project owner

## Planned SOC Lab Resources

| System | vCPU | RAM | Disk |
|---|---:|---:|---:|
| Wazuh server | 4 | 8 GB | 60 GB |
| Windows 11 endpoint | 4 | 5 GB | 64 GB |
| Ubuntu endpoint | 2 | 3 GB | 40 GB |

Approximate guest RAM when all systems are running: 16 GB.

This leaves approximately 8 GB of physical memory available to macOS and host
applications before considering virtualization overhead.

## Host Suitability

The host is suitable for the planned Mini SOC Lab.

Strengths:

- Modern Apple M4 processor
- ARM64 hardware virtualization support
- 10 CPU cores
- 24 GB unified memory
- Approximately 1.3 TB of available SSD storage at inspection
- VMware Fusion 26.0.0 selected as the lab hypervisor
- Sufficient resources for a three-VM security laboratory

Primary architectural consideration:

- All lab guest operating systems must use ARM64 images. VMware Fusion on this
  Apple Silicon host does not provide an x86-64 guest path for this design.
