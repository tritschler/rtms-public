# WordPress Database for CF7, WPForms, Elementor Forms — CVE-2026-115867 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **Database for Contact Form 7, WPforms, Elementor forms** plugin (`database-for-cf7`) is affected by **CVE-2026-115867** (CVSS 9.8, Critical), an arbitrary file upload vulnerability in `copy_files`.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Database for Contact Form 7, WPforms, Elementor forms | `<= 1.5.5` | `1.5.6+` |

## Usage
```bash
python3 plugins/wordpress/wp_database_for_cf7/wp_database_for_cf7_cve_2026_115867_audit.py --target https://wp.example.local
```
