# WordPress WP Job Portal — CVE-2026-135641 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **WP Job Portal** plugin (`wp-job-portal`) is affected by **CVE-2026-135641** (CVSS 9.1, Critical), an authentication bypass vulnerability leading to account takeover.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| WP Job Portal (`wp-job-portal`) | `<= 2.7.2` | `2.7.3+` |

## Usage
```bash
python3 plugins/wordpress/wp_job_portal/wp_job_portal_cve_2026_135641_audit.py --target https://wp.example.local
```
