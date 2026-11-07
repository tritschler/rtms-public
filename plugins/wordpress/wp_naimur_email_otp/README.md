# WordPress Naimur Email OTP Verification Auth Bypass Auditor (CVE-2026-104014)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--104014-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect WordPress web servers running vulnerable versions of the **Naimur Email OTP Verification for WooCommerce** plugin (`<= 2.1.0`) exposed to **CVE-2026-104014**.

---

## 🔍 Vulnerability Summary (CVE-2026-104014)

* **Severity**: **Critical (CVSS 9.8)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE**: CWE-287 (Improper Authentication)
* **Affected Ecosystems**: WordPress sites using the **Naimur Email OTP Verification for WooCommerce** plugin (`naimur-email-otp-verification-for-woocommerce`) in versions up to and including `2.1.0`.

### Flaw Mechanics
The Naimur Email OTP Verification for WooCommerce plugin for WordPress is vulnerable to **authentication bypass** in versions up to, and including, **`2.1.0`**.

Specifically, the plugin's password-reset finalization endpoint (`wp_ajax_nopriv_ceovw_update_new_password` handled by `CEOVW_AJAX::update_new_password()`) authorizes password resets solely by checking for a database row marking an email address as `'VERIFIED'`, without verifying a timestamp, session binding, or per-reset token. Furthermore, `mark_otp_as_verified_for_reset()` leaves the row in that state when a flow is abandoned, and the scheduled `ceovw_cleanup_expired_otps_event` cron lacks an `add_action()` handler.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **Naimur Email OTP Verification for WooCommerce** | Active | All releases **`<= 2.1.0`** | **`2.1.1+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_naimur_email_otp/wp_naimur_email_otp_cve_2026_104014_audit.py your-wordpress-site.com -p 80 443
```

---

## 💡 Remediation
1. **Update Plugin Immediately**: Upgrade **Naimur Email OTP Verification for WooCommerce** to **`2.1.1`** or later.
2. **Database Cleanup**: Clear residual `'VERIFIED'` OTP entries from the plugin's verification table.
3. **Web Server Hardening**: Block direct public HTTP access to `/wp-content/plugins/*/readme.txt`.
