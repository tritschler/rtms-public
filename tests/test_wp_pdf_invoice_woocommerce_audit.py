from plugins.wordpress.wp_pdf_invoice_woocommerce.wp_pdf_invoice_woocommerce_cve_2026_136240_audit import (
    WPPDFInvoiceWooCommerceAuditPlugin,
    is_pdf_invoice_wc_version_vulnerable,
    parse_pdf_invoice_wc_version,
)


def test_parse_pdf_invoice_wc_version():
    assert parse_pdf_invoice_wc_version("Stable tag: 7.2.0") == (7, 2, 0)
    assert parse_pdf_invoice_wc_version("7.2.1") == (7, 2, 1)
    assert parse_pdf_invoice_wc_version("") is None


def test_is_pdf_invoice_wc_version_vulnerable():
    assert is_pdf_invoice_wc_version_vulnerable((7, 2, 0))[0] is True
    assert is_pdf_invoice_wc_version_vulnerable((7, 2, 1))[0] is False


def test_wp_pdf_invoice_wc_run_audit():
    res_v = WPPDFInvoiceWooCommerceAuditPlugin("wp.local", {"plugin_version": "7.2.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-136240" in res_v["cve"]

    res_ok = WPPDFInvoiceWooCommerceAuditPlugin("wp.local", {"plugin_version": "7.2.1"}).run_audit()
    assert res_ok["status"] == "OK"
