from plugins.wordpress.wp_product_input_fields_woocommerce.wp_product_input_fields_woocommerce_cve_2026_104998_audit import (
    WPProductInputFieldsWooCommerceAuditPlugin,
    is_product_input_fields_wc_version_vulnerable,
    parse_product_input_fields_wc_version,
)


def test_parse_product_input_fields_wc_version():
    assert parse_product_input_fields_wc_version("Stable tag: 2.1.0") == (2, 1, 0)
    assert parse_product_input_fields_wc_version("2.1.1") == (2, 1, 1)
    assert parse_product_input_fields_wc_version("") is None


def test_is_product_input_fields_wc_version_vulnerable():
    assert is_product_input_fields_wc_version_vulnerable((2, 1, 0))[0] is True
    assert is_product_input_fields_wc_version_vulnerable((2, 1, 1))[0] is False


def test_wp_product_input_fields_wc_run_audit():
    res_v = WPProductInputFieldsWooCommerceAuditPlugin("wp.local", {"plugin_version": "2.1.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-104998" in res_v["cve"]

    res_ok = WPProductInputFieldsWooCommerceAuditPlugin("wp.local", {"plugin_version": "2.1.1"}).run_audit()
    assert res_ok["status"] == "OK"
