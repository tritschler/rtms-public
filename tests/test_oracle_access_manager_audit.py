from plugins.oracle_access_manager.oracle_access_manager_cve_2026_91510_audit import (
    OracleAccessManagerAuditPlugin,
    is_oam_version_vulnerable,
    parse_oam_version,
)


def test_parse_oam_version():
    assert parse_oam_version("Oracle Access Manager 12.2.1.4.0") == (12, 2, 1, 4, 0, "12.2.1.4.0")
    assert parse_oam_version("OAM Server 14.1.2.1.0") == (14, 1, 2, 1, 0, "14.1.2.1.0")
    assert parse_oam_version("") is None


def test_is_oam_version_vulnerable():
    assert is_oam_version_vulnerable(12, 2, 1, 4, 0)[0] is True
    assert is_oam_version_vulnerable(14, 1, 2, 1, 0)[0] is True
    assert is_oam_version_vulnerable(12, 2, 1, 4, 1)[0] is False
    assert is_oam_version_vulnerable(14, 1, 2, 2, 0)[0] is False


def test_oam_run_audit(mocker):
    plugin = OracleAccessManagerAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-91510"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 14100,
            "service_detected": True,
            "version": "12.2.1.4.0",
            "source": "OAM Console",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-91510",
        },
    )
    res_v = plugin.run_audit("10.0.0.10", [14100])
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-91510" in res_v["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 14100,
            "service_detected": True,
            "version": "14.1.2.2.0",
            "source": "OAM Console",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    res_ok = plugin.run_audit("10.0.0.10", [14100])
    assert res_ok["status"] == "OK"
