# SiYuan — CVE-2026-137471 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **SiYuan** note-taking and knowledge management server/desktop instance is affected by **CVE-2026-137471** (CVSS 9.0, Critical), a cross-site scripting vulnerability in WebDAV sync error rendering with Electron Node integration.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| SiYuan | `< 3.8.10` | `3.8.10` |

## Usage
```bash
python3 plugins/siyuan/siyuan_cve_2026_137471_audit.py --target http://siyuan.example.local:6806
```
