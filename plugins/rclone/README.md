# Rclone — CVE-2026-134352 Passive Version Audit

## Overview
Passive compliance plugin verifying whether an **Rclone** deployment is affected by **CVE-2026-134352** (CVSS 9.2, Critical), an authentication bypass vulnerability in `rclone serve sftp --auth-proxy`.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Rclone | `1.51.0` – `1.75.x` | `1.76.0` |

## Usage
```bash
python3 plugins/rclone/rclone_cve_2026_134352_audit.py --target sftp.example.local:2022 --version 1.75.2
```
