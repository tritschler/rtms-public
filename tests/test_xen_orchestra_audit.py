from plugins.xen_orchestra.xen_orchestra_cve_2026_133469_audit import (
    XenOrchestraAuditPlugin,
    is_xen_orchestra_version_vulnerable,
    parse_xen_orchestra_version,
)


def test_parse_xen_orchestra_version():
    assert parse_xen_orchestra_version("Xen Orchestra 6.9.1") == (6, 9, 1, "6.9.1")
    assert parse_xen_orchestra_version("xo-server 5.211.1") == (5, 211, 1, "5.211.1")
    assert parse_xen_orchestra_version("") is None


def test_is_xen_orchestra_version_vulnerable():
    assert is_xen_orchestra_version_vulnerable(6, 9, 1)[0] is True
    assert is_xen_orchestra_version_vulnerable(6, 9, 2)[0] is False
    assert is_xen_orchestra_version_vulnerable(6, 10, 0)[0] is True
    assert is_xen_orchestra_version_vulnerable(5, 211, 1)[0] is True
    assert is_xen_orchestra_version_vulnerable(5, 211, 2)[0] is False


def test_xen_orchestra_run_audit(mocker):
    plugin = XenOrchestraAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-133469"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "6.9.1",
            "source": "Xen Orchestra UI",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-133469",
        },
    )
    assert plugin.run_audit("10.0.0.19", [443])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "6.10.1",
            "source": "Xen Orchestra UI",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.19", [443])["status"] == "OK"
