# Zoho ManageEngine Log360 & EventLog Analyzer Audit (`CVE-2026-13594`)

## Overview
- **CVE:** `CVE-2026-13594` (CVSS 9.1 Critical)
- **Affected Component:** Zoho ManageEngine Log360 and EventLog Analyzer builds `<= 13062`
- **Patched Version:** Build `>= 13063`
- **Target Ports:** `80`, `443`, `8080`, `8095` (Log360), `8400` (EventLog Analyzer), `8443`

## Vulnerability Summary
Zoho Corporation's ManageEngine Log360 and EventLog Analyzer versions `13062` and below are vulnerable to an improper authentication and access control flaw that allows an unauthenticated adversary to gain unauthorized access to the product.

## Usage
```bash
python plugins/manageengine_log360/manageengine_cve_2026_13594_audit.py <target_ip> -p 8400 8095 443
```
