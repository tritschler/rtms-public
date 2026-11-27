# Parse Server — CVE-2026-137465 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Parse Server** instance is affected by **CVE-2026-137465** (CVSS 9.1, Critical), an authentication bypass vulnerability in the Google Play Games authentication adapter.

## Affected & Fixed Versions
| Product Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Parse Server `3.x`–`8.x` | `3.10.0` to `< 8.6.123` | `8.6.123` |
| Parse Server `9.x` | `9.0.0` to `< 9.11.1-alpha.4` | `9.11.1-alpha.4` / `9.11.1` |

## Usage
```bash
python3 plugins/parse_server/parse_server_cve_2026_137465_audit.py --target https://parse.example.local:1337
```
