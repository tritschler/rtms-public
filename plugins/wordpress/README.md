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
| **Clockinator Lite SQL Injection & Access Control Audit** | **CVE-2026-124815** | `CRITICAL 10.0` | Clockinator Lite `< 1.1.0` (`<= 1.0.9`) | `1.1.0+` | [`wp_clockinator_lite/`](wp_clockinator_lite/) |
| **Ultimate Addons for Elementor Forms File Upload Audit** | **CVE-2026-124814** | `CRITICAL 9.8` | Ultimate Addons for Elementor Forms `< 1.0.8` (`<= 1.0.7`) | `1.0.8+` | [`wp_uae_forms/`](wp_uae_forms/) |
| **Descope Authentication Bypass Audit** | **CVE-2026-110959** | `CRITICAL 9.8` | Descope `< 1.2.0` (`<= 1.1.x`) | `1.2.0+` | [`wp_descope/`](wp_descope/) |
| **AutomatorWP Pro Webhook Auth Bypass Audit** | **CVE-2026-126173** | `CRITICAL 9.8` | AutomatorWP Pro Webhooks Addon `<= 1.4.4` | `1.4.5+` | [`wp_automatorwp_pro/`](wp_automatorwp_pro/) |
| **ELEX HelpDesk PHP Object Injection Audit** | **CVE-2026-119077** / **CVE-2026-125855** | `CRITICAL 9.8` | ELEX WordPress HelpDesk & Customer Ticketing `<= 3.3.9` | `3.3.10+` | [`wp_elex_helpdesk/`](wp_elex_helpdesk/) |
| **Advance Guest Post File Upload Validation Audit** | **CVE-2026-118063** / **CVE-2026-118064** | `CRITICAL 9.8` | Advance Guest Post `<= 1.9` | `1.9.1+` | [`wp_advance_guest_post/`](wp_advance_guest_post/) |
| **Easy DragDrop File Uploader Arbitrary File Deletion Audit** | **CVE-2026-124822** | `CRITICAL 10.0` | Easy DragDrop File Uploader `< 1.1.10` (`<= 1.1.9`) | `1.1.10+` | [`wp_easy_dragdrop_uploader/`](wp_easy_dragdrop_uploader/) |
| **Hotel Booking Lite Unrestricted File Upload Audit** | **CVE-2026-125851** | `CRITICAL 9.9` | Hotel Booking Lite `<= 2.5.1` | `2.5.2+` | [`wp_hotel_booking_lite/`](wp_hotel_booking_lite/) |
| **Streamit Unauthenticated AJAX Authorization Audit** | **CVE-2026-126119** | `CRITICAL 9.8` | Streamit `< 1.3.10` (`<= 1.3.9`) | `1.3.10+` | [`wp_streamit/`](wp_streamit/) |
| **Chatterbug Forms File Upload Validation Audit** | **CVE-2026-125055** | `CRITICAL 9.8` | Chatterbug Forms `<= 1.0.2` | `1.0.3+` | [`wp_chatterbug_forms/`](wp_chatterbug_forms/) |
| **Ahime Image Printer File Upload Validation Audit** | **CVE-2026-124833** | `CRITICAL 9.8` | Ahime Image Printer `<= 1.0.0` | `1.0.1+` | [`wp_ahime_image_printer/`](wp_ahime_image_printer/) |
| **Alex Reservations SQL Injection Compliance Audit** | **CVE-2026-124415** | `CRITICAL 9.3` | Alex Reservations `<= 2.4.8` | `2.4.9+` | [`wp_alex_reservations/`](wp_alex_reservations/) |
| **WP BASE Booking SQL Injection Compliance Audit** | **CVE-2026-124970** | `CRITICAL 9.3` | WP BASE Booking `<= 6.5.2` | `6.5.3+` | [`wp_base_booking/`](wp_base_booking/) |
| **Woocommerce Wishlist Missing Authorization & CSRF Audit** | **CVE-2026-124763** | `CRITICAL 9.1` | Woocommerce Wishlist `<= 1.1.0` | `1.1.1+` | [`wp_woocommerce_wishlist/`](wp_woocommerce_wishlist/) |
