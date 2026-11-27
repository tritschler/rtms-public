# VMware ESXi, Workstation & Fusion — CVE-2026-123910 / CVE-2026-123911 / CVE-2026-123912 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **VMware ESX / ESXi** hypervisor (or VMware Workstation / Fusion) is affected by **CVE-2026-123910** (CVSS 9.8), **CVE-2026-123911** (CVSS 9.8), and **CVE-2026-123912** (CVSS 9.3).

## Affected & Fixed Versions
| Product Branch | Affected Versions | Patched Version / Build |
| :--- | :--- | :--- |
| VMware ESX / ESXi `9.1.x` | `< 9.1.2.0` (`< build 25946735`) | `9.1.2.0` (`25946735`) |
| VMware ESX / ESXi `9.0.x` | `< 9.0.2.0200` (`< build 25953133`) | `9.0.2.0200` (`25953133`) |
| VMware ESX / ESXi `8.0.x` | `< 8.0 U3m` (`< build 25926933`) | `8.0 U3m` (`25926933`) |
| VMware Cloud Foundation `5.x` | `< 5.2.5` | `5.2.5` |

## Usage
```bash
python3 plugins/vmware_esxi/vmware_esxi_cve_2026_123910_audit.py --target https://esxi.example.local
```
