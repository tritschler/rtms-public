# RealVNC Server — CVE-2026-137738 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **RealVNC Server** instance is affected by **CVE-2026-137738** (CVSS 9.8, Critical), an unauthenticated remote code execution and denial-of-service vulnerability in UDP-based connections.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| RealVNC Server | `6.4.0` through `7.19.0` (`< 7.19.1`) | `7.19.1` |

## Usage
```bash
python3 plugins/realvnc_server/realvnc_server_cve_2026_137738_audit.py --target 192.168.1.50
```
