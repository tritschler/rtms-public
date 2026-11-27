# Direk Tech Smart Portal — CVE-2026-137706 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Direk Tech Smart Portal** instance is affected by **CVE-2026-137706** (CVSS 9.4, Critical), a missing authorization vulnerability allowing privilege escalation to Active Directory Domain Admins.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Direk Tech Smart Portal | `< 2026.12.0` (all unpatched releases prior to Nov 2026 security hotfix) | `2026.12.0+` |

## Usage
```bash
python3 plugins/direk_smart_portal/direk_smart_portal_cve_2026_137706_audit.py --target https://portal.example.local
```
