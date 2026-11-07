# WordPress Registration Form for WooCommerce Privilege Escalation Auditor (CVE-2026-119075)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--119075-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect WordPress web servers running vulnerable versions of the **Registration Form for WooCommerce** plugin by ThemeGrill (`<= 1.1.4`) exposed to **CVE-2026-119075**.

---

## 🔍 Vulnerability Summary (CVE-2026-119075)

* **Severity**: **Critical (CVSS 9.8)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE**: CWE-269 (Improper Privilege Management)
* **Affected Ecosystems**: WordPress sites using the **Registration Form for WooCommerce** plugin (`registration-form-for-woocommerce`) in versions up to and including `1.1.4`.

### Flaw Mechanics
The Registration Form for WooCommerce plugin for WordPress is vulnerable to **unauthenticated privilege escalation** in versions up to, and including, **`1.1.4`**.

While the My Account registration path (`validate_fields()`) validates submitted `tgwcfb/user-roles` values against the form's configured allowed roles, the checkout registration path (`FormHandler::validate_checkout_fields()`, hooked to `woocommerce_after_checkout_validation`) stores the raw `user_roles` parameter into `$this->valid_data` without any allow-list check, which `add_user_data()` then passes into `woocommerce_new_customer_data` as the new user's role.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **Registration Form for WooCommerce (`registration-form-for-woocommerce`)** | Active | All releases **`<= 1.1.4`** | **`1.1.5+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_registration_form_woocommerce/wp_registration_form_woocommerce_cve_2026_119075_audit.py your-wordpress-site.com -p 80 443
```

---

## 💡 Remediation
1. **Update Plugin Immediately**: Upgrade **Registration Form for WooCommerce** to **`1.1.5`** or later.
2. **Audit User Accounts**: Review WordPress administrator accounts for unexpected registrations created via checkout.
3. **Web Server Hardening**: Block direct public HTTP access to `/wp-content/plugins/*/readme.txt` and `changelog.txt`.
