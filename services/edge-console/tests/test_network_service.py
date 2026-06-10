"""Network interface inventory — state derivation and shaping logic."""

from __future__ import annotations

from src import network_service as ns


def test_derive_state_green_when_ipv4():
    state, label = ns.derive_state({"operstate": "up", "carrier": "1", "ipv4": "192.168.1.50"})
    assert state == "up_ip"
    assert "IP" in label


def test_derive_state_green_when_routable_ipv6_only():
    state, _ = ns.derive_state({"operstate": "up", "carrier": "1", "ipv6": ["2001:db8::1"]})
    assert state == "up_ip"


def test_derive_state_orange_when_link_up_no_ip():
    state, _ = ns.derive_state({"operstate": "up", "carrier": "1", "ipv4": None, "ipv6": []})
    assert state == "up_no_ip"


def test_derive_state_orange_ignores_link_local_ipv6():
    state, _ = ns.derive_state({"operstate": "up", "carrier": "1", "ipv6": ["fe80::1"]})
    assert state == "up_no_ip"


def test_derive_state_red_when_link_down():
    state, _ = ns.derive_state({"operstate": "down", "carrier": "0", "ipv4": None})
    assert state == "down"


def test_unknown_operstate_uses_carrier():
    assert ns._link_up({"operstate": "unknown", "carrier": "1"}) is True
    assert ns._link_up({"operstate": "unknown", "carrier": "0"}) is False


def test_is_virtual_detection():
    assert ns._is_virtual("lo", {"has_device": False}) is True
    assert ns._is_virtual("docker0", {"has_device": False}) is True
    assert ns._is_virtual("veth123", {"has_device": False}) is True
    assert ns._is_virtual("eth0", {"has_device": True}) is False
    assert ns._is_virtual("wlan0", {"has_device": True}) is False


def test_shape_maps_dot_and_kind():
    shaped = ns._shape({
        "name": "wlan0",
        "wireless": True,
        "operstate": "up",
        "carrier": "1",
        "ipv4": "10.0.0.5",
        "ipv6": ["fe80::abcd"],
        "speed": "300",
        "mac": "aa:bb:cc:dd:ee:ff",
        "has_device": True,
    })
    assert shaped["kind"] == "wireless"
    assert shaped["dot"] == "ok"
    assert shaped["state"] == "up_ip"
    assert shaped["ipv6"] == []  # link-local filtered from routable list
    assert shaped["speed_mbps"] == 300
    assert shaped["virtual"] is False


def test_collect_interfaces_orders_and_summarizes(monkeypatch):
    raw = [
        {"name": "lo", "operstate": "unknown", "carrier": None, "ipv4": "127.0.0.1", "has_device": False},
        {"name": "eth0", "operstate": "up", "carrier": "1", "ipv4": "192.168.1.10", "has_device": True},
        {"name": "eth1", "operstate": "up", "carrier": "1", "ipv4": None, "ipv6": [], "has_device": True},
        {"name": "eth2", "operstate": "down", "carrier": "0", "ipv4": None, "has_device": True},
        {"name": "wlan0", "wireless": True, "operstate": "up", "carrier": "1", "ipv4": "10.0.0.2", "has_device": True},
    ]
    monkeypatch.setattr(ns, "_run_probe_remote", lambda *a, **k: raw)
    out = ns.collect_interfaces()
    assert out["ok"] is True
    assert out["source"] == "packet-sensor"
    # physical only in summary (lo excluded)
    assert out["summary"] == {"total": 4, "up_ip": 2, "up_no_ip": 1, "down": 1}
    # wireless physical sorts before wired physical; virtual (lo) last
    names = [i["name"] for i in out["interfaces"]]
    assert names[0] == "wlan0"
    assert names[-1] == "lo"


def test_collect_interfaces_error_when_probe_unavailable(monkeypatch):
    monkeypatch.setattr(ns, "_run_probe_remote", lambda *a, **k: None)
    monkeypatch.setattr(ns, "_run_probe_local", lambda *a, **k: None)
    out = ns.collect_interfaces()
    assert out["ok"] is False
    assert out["interfaces"] == []
    assert out["error"]


def test_can_toggle_flags(monkeypatch):
    raw = [
        {"name": "eth0", "operstate": "up", "carrier": "1", "ipv4": "192.168.1.123", "has_device": True, "default_route": True},
        {"name": "eth1", "operstate": "up", "carrier": "1", "ipv4": "10.0.0.9", "has_device": True},
        {"name": "wlan0", "wireless": True, "operstate": "down", "carrier": "0", "has_device": True},
        {"name": "docker0", "operstate": "up", "carrier": "1", "ipv4": "172.17.0.1", "has_device": False},
    ]
    monkeypatch.setattr(ns, "_run_probe_remote", lambda *a, **k: raw)
    out = ns.collect_interfaces(capture_interface="eth1")
    by_name = {i["name"]: i for i in out["interfaces"]}
    assert by_name["eth0"]["can_toggle"] is False  # default route (mgmt)
    assert by_name["eth1"]["can_toggle"] is False  # capture interface
    assert by_name["wlan0"]["can_toggle"] is True
    assert by_name["docker0"]["can_toggle"] is False  # virtual


def test_set_interface_state_requires_flag(monkeypatch):
    monkeypatch.delenv("EDGE_CONSOLE_NET_ADMIN", raising=False)
    out = ns.set_interface_state("wlan0", False)
    assert out["ok"] is False
    assert out["status"] == 403


def test_set_interface_state_rejects_bad_name(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_NET_ADMIN", "true")
    out = ns.set_interface_state("eth0; rm -rf /", False)
    assert out["ok"] is False
    assert out["status"] == 400


def test_set_interface_state_blocks_default_route(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_NET_ADMIN", "true")
    raw = [{"name": "eth0", "operstate": "up", "carrier": "1", "ipv4": "192.168.1.123", "has_device": True, "default_route": True}]
    monkeypatch.setattr(ns, "_run_probe_remote", lambda *a, **k: raw)
    out = ns.set_interface_state("eth0", False)
    assert out["ok"] is False
    assert out["status"] == 409


def test_set_interface_state_blocks_capture_iface(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_NET_ADMIN", "true")
    raw = [{"name": "eth1", "operstate": "up", "carrier": "1", "ipv4": "10.0.0.9", "has_device": True}]
    monkeypatch.setattr(ns, "_run_probe_remote", lambda *a, **k: raw)
    out = ns.set_interface_state("eth1", False, capture_interface="eth1")
    assert out["ok"] is False
    assert out["status"] == 409


def test_set_interface_state_up_invokes_exec(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_NET_ADMIN", "true")
    raw = [{"name": "wlan0", "wireless": True, "operstate": "down", "carrier": "0", "has_device": True}]
    monkeypatch.setattr(ns, "_run_probe_remote", lambda *a, **k: raw)
    calls = {}

    class _Proc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(ns.subprocess, "run", _fake_run)
    out = ns.set_interface_state("wlan0", True)
    assert out["ok"] is True
    assert out["up"] is True
    assert calls["cmd"][-2:] == ["wlan0", "up"]
