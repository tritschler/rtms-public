from plugins.wordpress.wp_hello_clever_gateway.wp_hello_clever_gateway_cve_2026_136113_audit import (
    WPHelloCleverGatewayAuditPlugin,
    is_hello_clever_version_vulnerable,
    parse_hello_clever_version,
)


def test_parse_hello_clever_version():
    assert parse_hello_clever_version("Stable tag: 1.8.4") == (1, 8, 4)
    assert parse_hello_clever_version("1.8.5") == (1, 8, 5)
    assert parse_hello_clever_version("") is None


def test_is_hello_clever_version_vulnerable():
    assert is_hello_clever_version_vulnerable((1, 8, 4))[0] is True
    assert is_hello_clever_version_vulnerable((1, 8, 5))[0] is False


def test_wp_hello_clever_gateway_run_audit():
    res_v = WPHelloCleverGatewayAuditPlugin("wp.local", {"plugin_version": "1.8.4"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-136113" in res_v["cve"]

    res_ok = WPHelloCleverGatewayAuditPlugin("wp.local", {"plugin_version": "1.8.5"}).run_audit()
    assert res_ok["status"] == "OK"
