# WordPress WPMasterToolKit — CVE-2026-134963 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running **WPMasterToolKit** (`wpmastertoolkit`) is affected by **CVE-2026-134963** (CVSS 9.9, Critical), a code injection vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| WPMasterToolKit (`wpmastertoolkit`) | `<= 2.26.1` | `2.26.2+` |

## Usage
```bash
python3 plugins/wordpress/wp_mastertoolkit/wp_mastertoolkit_cve_2026_134963_audit.py --target https://wp.example.local
```
