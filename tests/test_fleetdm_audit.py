from plugins.fleetdm.fleetdm_cve_2026_130759_audit import (
    FleetDMAuditPlugin,
    is_fleetdm_version_vulnerable,
    parse_fleetdm_version,
)


def test_parse_fleetdm_version():
    assert parse_fleetdm_version("FleetDM 4.92.2") == (4, 92, 2, "4.92.2")
    assert parse_fleetdm_version("Fleet v4.92.3") == (4, 92, 3, "4.92.3")
    assert parse_fleetdm_version("") is None


def test_is_fleetdm_version_vulnerable():
    assert is_fleetdm_version_vulnerable(4, 88, 1)[0] is True
    assert is_fleetdm_version_vulnerable(4, 89, 2)[0] is True
    assert is_fleetdm_version_vulnerable(4, 90, 2)[0] is True
    assert is_fleetdm_version_vulnerable(4, 91, 1)[0] is True
    assert is_fleetdm_version_vulnerable(4, 92, 2)[0] is True
    assert is_fleetdm_version_vulnerable(4, 92, 3)[0] is False


def test_fleetdm_run_audit(mocker):
    plugin = FleetDMAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-130759"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "4.92.2",
            "source": "Fleet API",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-130759",
        },
    )
    assert plugin.run_audit("10.0.0.22", [8080])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "4.92.3",
            "source": "Fleet API",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.22", [8080])["status"] == "OK"
