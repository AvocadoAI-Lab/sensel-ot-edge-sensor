import json
import subprocess

import pytest

from src import vpn_service as vs


MINIMAL_OVPN = """client
dev tun
proto udp
remote 123.192.126.214 1194
<ca>
-----BEGIN CERTIFICATE-----
abc
-----END CERTIFICATE-----
</ca>
<key>
-----BEGIN PRIVATE KEY-----
SECRETKEYMATERIAL
-----END PRIVATE KEY-----
</key>
"""


@pytest.fixture()
def vpn_env(tmp_path, monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_VPN_ADMIN", "true")
    monkeypatch.setenv("VPN_STATE_DIR", str(tmp_path))
    return tmp_path


def test_admin_gate_blocks_mutations(monkeypatch, tmp_path):
    monkeypatch.delenv("EDGE_CONSOLE_VPN_ADMIN", raising=False)
    monkeypatch.setenv("VPN_STATE_DIR", str(tmp_path))
    assert vs.save_profile("x", MINIMAL_OVPN.encode())["status"] == 403
    assert vs.connect("x")["status"] == 403
    assert vs.disconnect()["status"] == 403


def test_validate_ovpn_rejects_garbage():
    assert vs.validate_ovpn(b"") is not None
    assert vs.validate_ovpn(b"hello world no remote") is not None
    assert vs.validate_ovpn(MINIMAL_OVPN.encode()) is None


def test_invalid_profile_name(vpn_env):
    assert vs.save_profile("../evil", MINIMAL_OVPN.encode())["status"] == 400
    assert vs.save_profile("a b", MINIMAL_OVPN.encode())["status"] == 400


def test_save_list_and_extract_remote(vpn_env):
    r = vs.save_profile("home", MINIMAL_OVPN.encode())
    assert r["ok"] is True
    assert r["remote"] == "123.192.126.214:1194"
    listing = vs.list_profiles()
    names = [p["name"] for p in listing["profiles"]]
    assert "home" in names
    home = next(p for p in listing["profiles"] if p["name"] == "home")
    assert home["remote"] == "123.192.126.214:1194"


def test_view_masks_private_key(vpn_env):
    vs.save_profile("home", MINIMAL_OVPN.encode())
    view = vs.view_profile("home")
    assert view["ok"] is True
    assert "SECRETKEYMATERIAL" not in view["content"]
    assert "遮蔽" in view["content"]
    # Non-secret directives stay visible.
    assert "remote 123.192.126.214 1194" in view["content"]


def test_connect_writes_desired_with_incrementing_epoch(vpn_env):
    vs.save_profile("home", MINIMAL_OVPN.encode())
    r1 = vs.connect("home")
    assert r1["ok"] is True and r1["epoch"] == 1
    desired = json.loads((vpn_env / "desired.json").read_text())
    assert desired["connect"] is True
    assert desired["profile"] == "home"
    # Lockout-safe default: do NOT redirect the gateway.
    assert desired["redirect_gateway"] is False
    r2 = vs.connect("home")
    assert r2["epoch"] == 2


def test_connect_unknown_profile_404(vpn_env):
    assert vs.connect("missing")["status"] == 404


def test_connect_with_credentials_writes_auth_file(vpn_env):
    vs.save_profile("home", MINIMAL_OVPN.encode())
    r = vs.connect("home", username="alice", password="s3cret")
    assert r["ok"] is True
    auth = (vpn_env / "profiles" / "home.auth").read_text()
    assert auth.splitlines() == ["alice", "s3cret"]
    desired = json.loads((vpn_env / "desired.json").read_text())
    assert desired["auth"] is True


def test_disconnect_sets_connect_false(vpn_env):
    vs.save_profile("home", MINIMAL_OVPN.encode())
    vs.connect("home")
    vs.disconnect()
    desired = json.loads((vpn_env / "desired.json").read_text())
    assert desired["connect"] is False


def test_delete_blocked_while_active(vpn_env):
    vs.save_profile("home", MINIMAL_OVPN.encode())
    vs.connect("home")
    assert vs.delete_profile("home")["status"] == 409
    vs.disconnect()
    assert vs.delete_profile("home")["ok"] is True


def test_status_reports_stale_when_supervisor_silent(vpn_env):
    (vpn_env / "status.json").write_text(json.dumps({
        "state": "connected", "assigned_ip": "10.8.0.6",
        "updated_at": "2000-01-01T00:00:00+00:00",
    }))
    st = vs.get_status()
    assert st["supervisor_alive"] is False
    assert st["state"] == "stale"


def test_diagnose_parses_probe(vpn_env, monkeypatch):
    monkeypatch.setattr(vs, "_docker_available", lambda: True)
    probe = {
        "tun_interfaces": [{"name": "tun0", "ipv4": "10.8.0.6"}],
        "tun_up": True,
        "assigned_ip": "10.8.0.6",
        "routes": [],
        "tcp_target": {"ok": True, "host": "192.168.1.203", "ip": "192.168.1.203", "port": 1883},
    }

    def _fake_run(*a, **k):
        return subprocess.CompletedProcess(args=a, returncode=0, stdout=json.dumps(probe), stderr="")

    monkeypatch.setattr(vs.subprocess, "run", _fake_run)
    r = vs.diagnose("192.168.1.203", 1883)
    assert r["ok"] is True
    assert r["reachable"] is True
    assert "可連線" in r["summary"]


def test_diagnose_rejects_bad_port(vpn_env):
    assert vs.diagnose("192.168.1.203", 0)["status"] == 400
