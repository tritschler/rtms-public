# LaraDashboard — CVE-2026-137544 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **LaraDashboard** instance is affected by **CVE-2026-137544** (CVSS 9.4, Critical), a path traversal vulnerability in `module.json` and `composer.json` namespace parsing leading to remote code execution.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| LaraDashboard | `< 1.5.0` | `1.5.0` |

## Usage
```bash
python3 plugins/laradashboard/laradashboard_cve_2026_137544_audit.py --target https://laradashboard.example.local
```
