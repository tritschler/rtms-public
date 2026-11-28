# POSTAL 2 — CVE-2026-138154 Passive Build Compliance Audit

## Overview
Passive compliance plugin verifying whether a **POSTAL 2** installation is affected by **CVE-2026-138154** (CVSS 9.3, Critical), a sandbox escape vulnerability prior to build `26810491`.

## Affected & Fixed Builds
| Product | Affected Builds | Patched Build |
| :--- | :--- | :--- |
| POSTAL 2 | `< 26810491` | `26810491+` |

## Usage
```bash
python3 plugins/postal2/postal2_cve_2026_138154_audit.py --target workstation.local --version 26810491
```
