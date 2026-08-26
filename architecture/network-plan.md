# Mini SOC Lab Network Plan

## Design Goals

- Keep lab systems off the physical LAN
- Allow the host to access the Wazuh dashboard
- Allow monitored endpoints to communicate with the Wazuh server
- Permit temporary internet access for trusted updates
- Allow internet access to be disabled during simulations

## Prohibited Configuration

Bridged networking will not be used in the initial laboratory.

## Virtual Networks

### NAT

Used temporarily for:

- Operating-system updates
- Trusted software downloads
- Package installation

NAT adapters should be disabled during controlled simulations when internet
access is not required.

### Host-Only Lab Network

- VMware network: `vmnet1`
- Subnet: `192.168.132.0/24`
- Netmask: `255.255.255.0`
- Host address: `192.168.132.1`
- Purpose: agent communication, administration, and dashboard access
- Hypervisor: VMware Fusion 26.0.0
- Verification status: Implemented and verified on the host and Wazuh VM
- DHCP range: `192.168.132.128` through `192.168.132.254`

The Ubuntu ARM64 ISO supplies the guest operating-system installer. It does
not create the host-only network. VMware Fusion provides the verified `vmnet1`
network. The static addresses below are outside its DHCP pool.

## Address Plan

| System | Hostname | Lab address |
|---|---|---|
| Physical host | Host computer | `192.168.132.1` |
| Wazuh central node | `soc-wazuh` | `192.168.132.10` |
| Windows endpoint | `soc-win11` | `192.168.132.20` |
| Ubuntu endpoint | `soc-ubuntu` | `192.168.132.30` |

## Adapter Plan

### Wazuh Server

- Adapter 1: NAT
- Adapter 2: Host-only
- Static host-only address: `192.168.132.10`
- Ubuntu interface `enp2s0`: NAT with DHCP
- Ubuntu interface `enp10s0`: static `192.168.132.10/24`
- Default route: NAT gateway on `enp2s0`
- Validation: host reachability, DNS, HTTPS, and SSH passed

### Windows Endpoint

- Adapter 1: NAT
- Adapter 2: Host-only
- Static host-only address: `192.168.132.20`

### Ubuntu Endpoint

- Adapter 1: NAT
- Adapter 2: Host-only
- Static host-only address: `192.168.132.30`

## Security Controls

- Do not use bridged networking.
- Disable NAT adapters before controlled simulations when possible.
- Keep the physical host firewall enabled.
- Use only synthetic laboratory accounts and credentials.
- Do not run real malware.
- Take snapshots before simulations.
- Do not expose the Wazuh dashboard publicly.
