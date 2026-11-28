# WordPress Revertix — CVE-2026-134994 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running **Revertix – Backup, Migration, Staging & Clone** (`revertix`) is affected by **CVE-2026-134994** (CVSS 9.8, Critical), a deserialization / PHP object injection vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Revertix (`revertix`) | `<= 1.0.3` | `1.0.4+` |

## Usage
```bash
python3 plugins/wordpress/wp_revertix/wp_revertix_cve_2026_134994_audit.py --target https://wp.example.local
```
