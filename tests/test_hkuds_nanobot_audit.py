from plugins.hkuds_nanobot.hkuds_nanobot_cve_2026_137463_audit import (
    HKUDSNanobotAuditPlugin,
    is_nanobot_version_vulnerable,
    parse_nanobot_version,
)


def test_parse_nanobot_version():
    assert parse_nanobot_version("0.4.0") == (0, 4, 0)
    assert parse_nanobot_version("0.4.1") == (0, 4, 1)
    assert parse_nanobot_version("") is None


def test_is_nanobot_version_vulnerable():
    assert is_nanobot_version_vulnerable((0, 4, 0))[0] is True
    assert is_nanobot_version_vulnerable((0, 4, 1))[0] is False


def test_hkuds_nanobot_run_audit():
    res_v = HKUDSNanobotAuditPlugin("nanobot.local", {"nanobot_version": "0.4.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137463" in res_v["cve"]

    res_ok = HKUDSNanobotAuditPlugin("nanobot.local", {"nanobot_version": "0.4.1"}).run_audit()
    assert res_ok["status"] == "OK"
