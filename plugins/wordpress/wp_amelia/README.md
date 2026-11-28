# WordPress Amelia — CVE-2026-135930 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running **Amelia** (`ameliabooking`) is affected by **CVE-2026-135930** (CVSS 9.1, Critical), an authentication bypass by spoofing vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Amelia (`ameliabooking`) | `<= 2.4.14` | `2.4.15+` |

## Usage
```bash
python3 plugins/wordpress/wp_amelia/wp_amelia_cve_2026_135930_audit.py --target https://wp.example.local
```
