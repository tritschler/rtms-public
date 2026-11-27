# WordPress File Upload — CVE-2026-134173 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **WordPress File Upload** plugin (`wp-file-upload`) is affected by **CVE-2026-134173** (CVSS 9.1, Critical), an unauthenticated arbitrary file deletion vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| WordPress File Upload (`wp-file-upload`) | `<= 5.3.1` | `5.3.2+` |

## Usage
```bash
python3 plugins/wordpress/wp_file_upload/wp_file_upload_cve_2026_134173_audit.py --target https://wp.example.local
```
