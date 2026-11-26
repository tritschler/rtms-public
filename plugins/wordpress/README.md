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
| **Cloud Storage Manager for Fluent Forms File Write Audit** | **CVE-2026-120522** | `CRITICAL 9.8` | Cloud Storage Manager for Fluent Forms `<= 1.2.0` | `1.2.1+` | [`wp_fluent_forms_cloud_storage/`](wp_fluent_forms_cloud_storage/) |
| **Shipo Authentication Bypass Audit** | **CVE-2026-19907** | `CRITICAL 9.8` | Shipo `1.6` through `1.8.0` | `1.8.1+` | [`wp_shipo/`](wp_shipo/) |
| **Advanced Form Integration Privilege Escalation Audit** | **CVE-2026-125769** | `CRITICAL 9.8` | Advanced Form Integration `<= 2.11.3` | `2.11.4+` | [`wp_advanced_form_integration/`](wp_advanced_form_integration/) |
| **Document Library Pro Object Injection Audit** | **CVE-2026-122662** | `CRITICAL 9.8` | Document Library Pro `< 4.2.2` (`<= 4.2.1`) | `4.2.2+` | [`wp_document_library_pro/`](wp_document_library_pro/) |
| **Estatik Local File Inclusion Audit** | **CVE-2026-125795** | `CRITICAL 9.8` | Estatik `<= 4.3.6` | `4.3.7+` | [`wp_estatik/`](wp_estatik/) |
| **Custom Block Builder REST Authorization Audit** | **CVE-2026-127048** | `CRITICAL 9.8` | Custom Block Builder `< 3.0.0` | `3.0.0+` | [`wp_custom_block_builder/`](wp_custom_block_builder/) |
| **Auth Armor Missing Authentication Audit** | **CVE-2026-110960** | `CRITICAL 9.8` | Auth Armor `<= 1.0.3` | `1.0.4+` | [`wp_auth_armor/`](wp_auth_armor/) |
| **WP Duplicate Migration Plugin RCE Audit** | **CVE-2026-14492** | `CRITICAL 9.8` | WP Duplicate – WordPress Migration Plugin `<= 1.1.11` | `1.1.12+` | [`wp_duplicate/`](wp_duplicate/) |
| **WP Photo Album Plus Code Injection Audit** | **CVE-2026-129048** | `CRITICAL 9.9` | WP Photo Album Plus `<= 9.3.06.003` | `9.3.06.004+` | [`wp_photo_album_plus/`](wp_photo_album_plus/) |
| **miniOrange OTP Verification Auth Bypass Audit** | **CVE-2026-129073** | `CRITICAL 9.8` | miniOrange OTP Verification `<= 5.6.1` | `5.6.2+` | [`wp_miniorange_otp_verification/`](wp_miniorange_otp_verification/) |
| **Tribulant Newsletters Object Injection & SQLi Audit** | **CVE-2026-129039** / **CVE-2026-129043** | `CRITICAL 9.8` | Tribulant Newsletters (`newsletters-lite`) `<= 4.18.2` | `4.18.3+` | [`wp_newsletters_lite/`](wp_newsletters_lite/) |
| **Nexter Blocks Pro Privilege Escalation Audit** | **CVE-2026-125294** | `CRITICAL 9.8` | Nexter Blocks Pro `<= 5.0.10` | `5.0.11+` | [`wp_nexter_blocks_pro/`](wp_nexter_blocks_pro/) |
| **Simple Shopping Cart Object Injection Audit** | **CVE-2026-131782** | `CRITICAL 9.8` | Simple Shopping Cart (`wordpress-simple-paypal-shopping-cart`) `<= 5.3.3` | `5.3.4+` | [`wp_simple_shopping_cart/`](wp_simple_shopping_cart/) |
| **WP Rocket Path Traversal Audit** | **CVE-2026-125812** | `CRITICAL 9.8` | WP Media WP Rocket (`wp-rocket`) `< 3.24.2` | `3.24.2+` | [`wp_rocket/`](wp_rocket/) |
