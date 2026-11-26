# NocoDB — CVE-2026-130730 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **NocoDB** instance is affected by **CVE-2026-130730** (CVSS 9.3, Critical), an authentication bypass vulnerability in OAuth and JWT token validation.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| NocoDB | `< 2026.10.1` (including legacy `0.x`) | `2026.10.1` |

## Usage
```bash
python3 plugins/nocodb/nocodb_cve_2026_130730_audit.py --target https://nocodb.example.local
```
