# Webmin — CVE-2026-134639 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Webmin** instance is affected by **CVE-2026-134639** (CVSS 9.2, Critical), an insecure default administrative provisioning flaw in Webmin `<= 2.670`.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Webmin | `<= 2.670` | `2.671` |

## Usage
```bash
python3 plugins/webmin/webmin_cve_2026_134639_audit.py --target https://webmin.example.local:10000
```
