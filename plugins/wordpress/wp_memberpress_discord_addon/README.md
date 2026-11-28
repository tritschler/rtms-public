# WordPress MemberPress Discord Addon — CVE-2026-136115 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running **MemberPress Discord Addon** (`expresstechsoftwares-memberpress-discord-add-on`) is affected by **CVE-2026-136115** (CVSS 9.8, Critical), a privilege escalation vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| MemberPress Discord Addon | `<= 1.1.5` | `1.1.6+` |

## Usage
```bash
python3 plugins/wordpress/wp_memberpress_discord_addon/wp_memberpress_discord_addon_cve_2026_136115_audit.py --target https://wp.example.local
```
