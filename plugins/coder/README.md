# Coder — CVE-2026-137547 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Coder** cloud development environment platform is affected by **CVE-2026-137547** (CVSS 9.2, Critical), an exposure of temporary AWS IAM PostgreSQL database credentials in API key middleware error responses.

## Affected & Fixed Versions
| Release Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Coder `<= 2.29.x` | `< 2.29.27` | `2.29.27` |
| Coder `2.30`–`2.34` | `2.30.0` to `< 2.34.19` | `2.34.19` |
| Coder `2.35`–`2.37` | `2.35.0` to `< 2.37.11` | `2.37.11` |
| Coder `2.38.x` | `2.38.0` to `< 2.38.7` | `2.38.7` |
| Coder `2.39.x` | `2.39.0` (`< 2.39.1`) | `2.39.1` |

## Usage
```bash
python3 plugins/coder/coder_cve_2026_137547_audit.py --target https://coder.example.local
```
