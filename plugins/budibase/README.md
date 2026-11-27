# Budibase Server — CVE-2026-137498 / CVE-2026-137499 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Budibase** instance is affected by **CVE-2026-137498** (CVSS 9.9, prototype pollution erasing MongoDB query filters) and **CVE-2026-137499** (CVSS 9.3, OIDC/SSO unverified-email authentication bypass).

## Affected & Fixed Versions
| Vulnerability | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| `CVE-2026-137498` (`CVSS 9.9`) | `3.39.18` to `< 4.0.0` | `4.0.0` |
| `CVE-2026-137499` (`CVSS 9.3`) | `3.41.0` to `< 4.0.0` | `4.0.0` |

## Usage
```bash
python3 plugins/budibase/budibase_cve_2026_137498_audit.py --target https://budibase.example.local
```
