# WordPress LatePoint Authentication Bypass Auditor (CVE-2026-118066)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--118066-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect WordPress web servers running vulnerable versions of the **LatePoint – Appointment Booking & Scheduling** plugin (`<= 5.7.6`) exposed to **CVE-2026-118066**.

---

## 🔍 Vulnerability Summary (CVE-2026-118066)

* **Severity**: **Critical (CVSS 9.1)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **CWE**: CWE-287 (Improper Authentication) / CWE-89 (SQL Injection)
* **Affected Ecosystems**: WordPress sites using the **LatePoint** plugin (`latepoint`) in versions up to and including `5.7.6`.

### Flaw Mechanics
The Appointment Booking Plugin – LatePoint for WordPress is vulnerable to **Authentication Bypass via Account Takeover** in all versions up to, and including, **`5.7.6`**.

`OsModel::build_conditions_query()` in `lib/models/model.php` compares WHERE-clause values against the literal strings `'IS NULL'` and `'IS NOT NULL'` and concatenates matches directly into SQL without parameter binding, allowing unauthenticated requests to match non-null reset tokens and overwrite customer passwords.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **LatePoint (`latepoint`)** | Active | All releases **`<= 5.7.6`** | **`5.7.7+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_latepoint/wp_latepoint_cve_2026_118066_audit.py your-wordpress-site.com -p 80 443
```

---

## 💡 Remediation
1. **Update Plugin Immediately**: Upgrade **LatePoint** to **`5.7.7`** or later.
2. **Review Linked Accounts**: Audit accounts if `wp_users_as_customers` is enabled.
3. **Web Server Hardening**: Block direct public HTTP access to `/wp-content/plugins/latepoint/readme.txt`.
