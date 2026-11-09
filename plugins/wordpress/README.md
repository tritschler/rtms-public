# WordPress Security Audit Plugins (`plugins/wordpress/`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-WordPress_&_WooCommerce-blue.svg)]()

This directory groups all standalone security audit tools and **[RTMS Suite](https://3ts.ai)** detection plugins dedicated to **WordPress Core**, **WooCommerce**, and **WordPress Plugins**.

All plugins in this folder perform strictly **passive, non-intrusive** HTTP/HTTPS version and metadata fingerprinting (such as `readme.txt`, `changelog.txt`, static CSS/JS `?ver=` query strings, and passive HTML markers) to identify vulnerable installations without sending exploit payloads.

---

## 📚 Available WordPress Security Plugins

| Plugin Name | Target CVE | Severity | Affected Component & Versions | Patched Version | Subdirectory |
|:---|:---:|:---:|:---|:---:|:---:|
| **Gravity Forms PHP Object Injection Audit** | **CVE-2026-103039** | `CRITICAL 9.8` | Gravity Forms `<= 3.1.2` | `3.1.3+` | [`wp_gravityforms/`](wp_gravityforms/) |
| **Naimur Email OTP Verification Auth Bypass Audit** | **CVE-2026-104014** | `CRITICAL 9.8` | Naimur Email OTP Verification for WooCommerce `<= 2.1.0` | `2.1.1+` | [`wp_naimur_email_otp/`](wp_naimur_email_otp/) |
| **Registration Form for WooCommerce Privilege Escalation Audit** | **CVE-2026-119075** | `CRITICAL 9.8` | Registration Form for WooCommerce (ThemeGrill) `<= 1.1.4` | `1.1.5+` | [`wp_registration_form_woocommerce/`](wp_registration_form_woocommerce/) |
| **LatePoint Authentication Bypass Audit** | **CVE-2026-118066** | `CRITICAL 9.1` | LatePoint – Appointment Booking & Scheduling `<= 5.7.6` | `5.7.7+` | [`wp_latepoint/`](wp_latepoint/) |
| **Printcart Product Designer Arbitrary File Upload Audit** | **CVE-2026-19803** | `CRITICAL 9.8` | Printcart Store – Web to Print Product Designer `<= 2.13.2` | `2.13.3+` | [`wp_printcart_designer/`](wp_printcart_designer/) |
| **payever WooCommerce Gateway Arbitrary File Upload Audit** | **CVE-2026-93754** | `CRITICAL 9.8` | payever – WooCommerce Gateway `<= 4.8.0` | `4.8.1+` | [`wp_payever_gateway/`](wp_payever_gateway/) |
| **Contact Form 7 File Upload Validation Audit** | **CVE-2026-114432** | `CRITICAL 9.8` | Contact Form 7 `< 6.2.4` (`<= 6.2.3`) | `6.2.4+` | [`wp_contact_form_7/`](wp_contact_form_7/) |
