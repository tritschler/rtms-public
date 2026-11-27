# WordPress Sneeit Framework — CVE-2026-106125 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **Sneeit Framework** plugin (`sneeit-framework`) is affected by **CVE-2026-106125** (CVSS 9.8, Critical), an unauthenticated remote code execution vulnerability in the `sneeit_compact_menu_mega_content` AJAX action.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Sneeit Framework (`sneeit-framework`) | `<= 8.7` | `8.8+` |

## Usage
```bash
python3 plugins/wordpress/wp_sneeit_framework/wp_sneeit_framework_cve_2026_106125_audit.py --target https://wp.example.local
```
