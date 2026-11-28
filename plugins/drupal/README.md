# Drupal Core — CVE-2026-136716 & CVE-2026-132165 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Drupal Core** installation is affected by **CVE-2026-136716** (CVSS 9.8, Critical) and **CVE-2026-132165** (CVSS 9.8, Critical).

## Affected & Fixed Versions
| Product | CVE | Affected Versions | Patched Version |
| :--- | :--- | :--- | :--- |
| Drupal Core | CVE-2026-136716 | `0.0.0`–`10.6.23`, `11.0.0`–`11.3.23`, `11.4.0`–`11.4.14` | `10.6.24+`, `11.3.24+`, `11.4.15+` |
| Drupal Core | CVE-2026-132165 | `0.0.0`–`10.6.22`, `11.0.0`–`11.3.22`, `11.4.0`–`11.4.13` | `10.6.23+`, `11.3.23+`, `11.4.14+` |

## Usage
```bash
python3 plugins/drupal/drupal_cve_2026_136716_audit.py --target https://drupal.example.local
```
