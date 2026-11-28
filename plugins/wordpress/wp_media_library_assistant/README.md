# WordPress Media Library Assistant — CVE-2026-135009 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running **Media Library Assistant** (`media-library-assistant`) is affected by **CVE-2026-135009** (CVSS 9.3, Critical), a blind SQL injection vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Media Library Assistant (`media-library-assistant`) | `<= 3.43` | `3.44+` |

## Usage
```bash
python3 plugins/wordpress/wp_media_library_assistant/wp_media_library_assistant_cve_2026_135009_audit.py --target https://wp.example.local
```
