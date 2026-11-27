# SEPPmail Secure E-Mail Gateway — CVE-2026-130637 / CVE-2026-124843 / CVE-2026-124840 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **SEPPmail Secure E-Mail Gateway** appliance is affected by **CVE-2026-130637** (CVSS 9.3, pre-authentication SSTI), **CVE-2026-124843** (CVSS 9.2, hard-coded fallback secret for GINA/LFT), and **CVE-2026-124840** (CVSS 9.2, GINA session reuse across workflows).

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| SEPPmail Secure E-Mail Gateway | `< 15.1.2` | `15.1.2` |

## Usage
```bash
python3 plugins/seppmail/seppmail_cve_2026_130637_audit.py --target https://seppmail.example.local
```
