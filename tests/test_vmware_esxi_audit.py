from plugins.vmware_esxi.vmware_esxi_cve_2026_123910_audit import (
    VMwareESXiAuditPlugin,
    is_esxi_version_vulnerable,
    parse_esxi_version,
)


def test_parse_esxi_version():
    assert parse_esxi_version("9.1.1.0") == (9, 1, 1, 0)
    assert parse_esxi_version("8.0 U3l") == (8, 0, 3, 12)
    assert parse_esxi_version("8.0 U3m") == (8, 0, 3, 13)
    assert parse_esxi_version("") is None


def test_is_esxi_version_vulnerable():
    assert is_esxi_version_vulnerable((9, 1, 1, 0))[0] is True
    assert is_esxi_version_vulnerable((9, 1, 2, 0))[0] is False
    assert is_esxi_version_vulnerable((9, 0, 2, 100))[0] is True
    assert is_esxi_version_vulnerable((9, 0, 2, 200))[0] is False
    assert is_esxi_version_vulnerable((8, 0, 3, 12))[0] is True
    assert is_esxi_version_vulnerable((8, 0, 3, 13))[0] is False


def test_vmware_esxi_run_audit():
    res_v = VMwareESXiAuditPlugin("esxi.local", {"esxi_version": "9.1.1.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-123910" in res_v["cve"]
    assert "CVE-2026-123911" in res_v["cve"]
    assert "CVE-2026-123912" in res_v["cve"]

    res_ok = VMwareESXiAuditPlugin("esxi.local", {"esxi_version": "9.1.2.0"}).run_audit()
    assert res_ok["status"] == "OK"
