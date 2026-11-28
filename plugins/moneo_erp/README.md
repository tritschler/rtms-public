# MONEO ERP — CVE-2026-59103 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **MONEO ERP** server instance is affected by **CVE-2026-59103** (CVSS 9.3, Critical), an authentication and session management flaw in its WebSocket JSON-RPC service.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| MONEO ERP | Builds prior to `2026.11.28` (`<= 2026.11.27`) | `2026.11.28+` |

## Usage
```bash
python3 plugins/moneo_erp/moneo_erp_cve_2026_59103_audit.py --target https://moneo.example.local --version 2026.11.20
```
