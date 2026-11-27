# Twenty CRM — CVE-2026-137584 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Twenty CRM** multi-workspace instance is affected by **CVE-2026-137584** (CVSS 9.1, Critical), an authentication bypass vulnerability leaking pending invitation tokens via the `signUp` GraphQL mutation.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Twenty CRM | `<= 2.63.0` (`< 2.63.1`) | `2.63.1+` |

## Usage
```bash
python3 plugins/twenty_crm/twenty_crm_cve_2026_137584_audit.py --target https://twenty.example.local
```
