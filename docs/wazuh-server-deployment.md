# Wazuh Central Server Deployment

## Outcome

The Wazuh central components were deployed successfully on a single ARM64
Ubuntu Server virtual machine. The manager, indexer, dashboard, and Filebeat
services are operational, and the dashboard is reachable from the Mac host on
the isolated lab network.

This all-in-one design keeps the initial laboratory small enough for a personal
workstation while preserving the same collection, analysis, indexing, and
investigation workflow used in larger deployments.

## Platform

| Item | Implemented configuration |
|---|---|
| Hypervisor | VMware Fusion 26.0.0 |
| Host architecture | Apple Silicon ARM64 |
| Guest operating system | Ubuntu Server 24.04 LTS ARM64 |
| Hostname | `soc-wazuh` |
| vCPU | 4 |
| RAM | 8 GB |
| Virtual disk | 60 GB dynamically allocated |
| Root filesystem | 53 GB usable; 44 GB available after installation and updates |
| Wazuh deployment | All-in-one manager, indexer, and dashboard |

## Network Implementation

The VM uses two virtual network adapters with separate responsibilities:

| Interface | Network | Configuration | Purpose |
|---|---|---|---|
| `enp2s0` | VMware NAT | DHCP; validated address `172.16.87.134/24` | Trusted updates and package downloads |
| `enp10s0` | VMware `vmnet1` host-only | Static `192.168.132.10/24` | Agent traffic, SSH administration, and dashboard access |

The default route remains on the NAT interface. The host-only interface has no
default gateway, preventing it from replacing the intended outbound path.
Bridged networking is not used.

Validated network behavior:

- Mac host reached `192.168.132.10` with no packet loss.
- The VM reached the VMware NAT gateway.
- DNS resolution succeeded for the Wazuh package host.
- HTTPS communication with the Wazuh package host succeeded.
- The Mac connected to the VM using a dedicated SSH key and host alias.

## Installation Method

The official Wazuh installation assistant was downloaded from the Wazuh 4.14
package channel and run in all-in-one mode:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The generated dashboard administrator password was stored outside the
repository. No passwords, private keys, generated certificates, or credential
archives are included in Git.

## Validation Evidence

### System baseline

| Check | Verified result |
|---|---|
| Hostname | `soc-wazuh` |
| Architecture | `aarch64` |
| Private address | `192.168.132.10/24` on `enp10s0` |
| NAT address | `172.16.87.134/24` on `enp2s0` |
| SSH service | Active after update and reboot |

### Wazuh services

The following system services returned `active`:

- `wazuh-manager`
- `wazuh-indexer`
- `wazuh-dashboard`
- `filebeat`

### Service ports

| Port | Function | Observed exposure |
|---:|---|---|
| 443/TCP | Wazuh dashboard | Listening on VM IPv4 interfaces |
| 1514/TCP | Wazuh agent event traffic | Listening on VM IPv4 interfaces |
| 1515/TCP | Wazuh agent enrollment | Listening on VM IPv4 interfaces |
| 55000/TCP | Wazuh API | Listening on IPv4 and IPv6 interfaces |
| 9200/TCP | Wazuh indexer | Restricted to local loopback access |

An HTTPS request to the local dashboard returned `HTTP/1.1 302 Found` and
redirected to the login page. Dashboard authentication from the Mac succeeded
at `https://192.168.132.10` using the generated administrator account.

The browser warning during first access was expected because the lab uses a
self-signed certificate. The dashboard is not exposed directly to the public
internet.

## Recovery Checkpoints

Two powered-off VMware snapshots preserve known-good states:

- `01-clean-os`: Updated Ubuntu baseline with SSH and networking validated,
  created before Wazuh installation.
- `02-wazuh-installed`: Working all-in-one Wazuh deployment with services,
  ports, and dashboard access validated.

Snapshots provide fast rollback during the lab but are not treated as backups.

## Skills Demonstrated

- ARM64 virtual-machine deployment and resource planning
- Segmented NAT and host-only virtual networking
- Linux static-address configuration with Netplan
- SSH key-based administration
- SIEM component deployment and service validation
- Port and routing verification
- Secure handling of generated credentials
- Snapshot-based change control and rollback planning

## Next Milestone

Deploy the Windows 11 ARM64 endpoint at `192.168.132.20`, install the Wazuh
agent, and verify that Windows security telemetry reaches the manager and is
searchable in the dashboard.
