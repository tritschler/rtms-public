# WordPress WebinarIgnition — CVE-2026-135933 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running **WebinarIgnition** (`webinar-ignition`) is affected by **CVE-2026-135933** (CVSS 9.8, Critical), a privilege escalation vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| WebinarIgnition (`webinar-ignition`) | `<= 4.28.1` | `4.28.2+` |

## Usage
```bash
python3 plugins/wordpress/wp_webinar_ignition/wp_webinar_ignition_cve_2026_135933_audit.py --target https://wp.example.local
```
