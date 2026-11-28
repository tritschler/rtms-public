from plugins.trendnet_tew.trendnet_tew_cve_2026_138004_audit import (
    TrendnetTEWAuditPlugin,
    is_trendnet_firmware_vulnerable,
    parse_trendnet_firmware,
)


def test_parse_trendnet_firmware():
    assert parse_trendnet_firmware("1.03B01") == (1, 3, 1)
    assert parse_trendnet_firmware("1.03B02") == (1, 3, 2)
    assert parse_trendnet_firmware("") is None


def test_is_trendnet_firmware_vulnerable():
    assert is_trendnet_firmware_vulnerable((1, 3, 1))[0] is True
    assert is_trendnet_firmware_vulnerable((1, 3, 2))[0] is False


def test_trendnet_tew_run_audit():
    res_v = TrendnetTEWAuditPlugin("192.168.10.1", {"firmware_version": "1.03B01"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-138004" in res_v["cve"]
    assert "CVE-2026-138003" in res_v["cve"]

    res_ok = TrendnetTEWAuditPlugin("192.168.10.1", {"firmware_version": "1.03B02"}).run_audit()
    assert res_ok["status"] == "OK"
