# WordPress FunnelKit Automations — CVE-2026-131767 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **FunnelKit Automations** plugin (`wp-marketing-automations`) is affected by **CVE-2026-131767** (CVSS 9.8, Critical), a deserialization of untrusted data (PHP Object Injection) vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| FunnelKit Automations (`wp-marketing-automations`) | `<= 3.9.0.1` | `3.9.0.2+` |

## Usage
```bash
python3 plugins/wordpress/wp_funnelkit_automations/wp_funnelkit_automations_cve_2026_131767_audit.py --target https://wp.example.local
```
