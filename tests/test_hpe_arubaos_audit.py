from plugins.hpe_arubaos.hpe_arubaos_cve_2026_95787_audit import (
    HPEArubaOSAuditPlugin,
    is_hpe_arubaos_version_vulnerable,
    parse_hpe_arubaos_version,
)


def test_parse_hpe_arubaos_version():
    assert parse_hpe_arubaos_version("ArubaOS 10.7.2.6") == (10, 7, 2, 6, "10.7.2.6")
    assert parse_hpe_arubaos_version("ArubaOS 10.4.1.14") == (10, 4, 1, 14, "10.4.1.14")
    assert parse_hpe_arubaos_version("invalid") is None


def test_is_hpe_arubaos_version_vulnerable():
    assert is_hpe_arubaos_version_vulnerable(10, 4, 1, 13)[0] is True
    assert is_hpe_arubaos_version_vulnerable(10, 4, 1, 14)[0] is False
    assert is_hpe_arubaos_version_vulnerable(10, 7, 2, 6)[0] is True
    assert is_hpe_arubaos_version_vulnerable(10, 8, 1, 1)[0] is True
    assert is_hpe_arubaos_version_vulnerable(10, 8, 1, 2)[0] is False


def test_hpe_arubaos_run_audit(mocker):
    plugin = HPEArubaOSAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-95787"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4343,
            "service_detected": True,
            "version": "10.7.2.6",
            "source": "ArubaOS WebUI",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-95787",
        },
    )
    res_v = plugin.run_audit("10.0.0.11", [4343])
    assert res_v["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4343,
            "service_detected": True,
            "version": "10.7.2.7",
            "source": "ArubaOS WebUI",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.11", [4343])["status"] == "OK"
