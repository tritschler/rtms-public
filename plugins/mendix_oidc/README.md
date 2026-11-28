# Mendix OIDC Provider — CVE-2026-124981 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Mendix OIDC Provider** deployment is affected by **CVE-2026-124981** (CVSS 9.4, Critical), an improper JWT integrity validation flaw in the Token Introspection endpoint.

## Affected & Fixed Versions
| Product Track | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Mendix OIDC Provider (Mendix 9 compatible) | `< V4.3.0` | `V4.3.0+` |
| Mendix OIDC Provider (Mendix 10 & 11 compatible) | `< V6.0.0` | `V6.0.0+` |

## Usage
```bash
python3 plugins/mendix_oidc/mendix_oidc_cve_2026_124981_audit.py --target https://mendix.example.local --version 5.4.0
```
