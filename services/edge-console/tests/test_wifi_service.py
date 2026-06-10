import subprocess

from src import wifi_service as ws


def test_split_terse_handles_escaped_colon():
    assert ws._split_terse(r"a:b:c") == ["a", "b", "c"]
    assert ws._split_terse(r"AA\:BB:ssid:90") == ["AA:BB", "ssid", "90"]
    assert ws._split_terse(r"name\\with\\backslash:1") == [r"name\with\backslash", "1"]


def _fake_proc(stdout="", returncode=0, stderr=""):
    p = subprocess.CompletedProcess(args=["nmcli"], returncode=returncode)
    p.stdout = stdout
    p.stderr = stderr
    return p


def test_scan_dedups_and_sorts(monkeypatch):
    out = "\n".join([
        "*:mao:70:WPA2:2412",
        ":mao:40:WPA2:5180",          # weaker dup -> in-use row kept
        ":TPLink:88:WPA2:5200",
        "::55:WPA2:2437",             # hidden -> dropped
        ":Open-Cafe:30::2462",        # open network
    ])
    monkeypatch.setattr(ws, "_nmcli", lambda *a, **k: _fake_proc(stdout=out))
    nets = ws.scan(rescan=False)
    ssids = [n["ssid"] for n in nets]
    assert "mao" in ssids and "TPLink" in ssids and "Open-Cafe" in ssids
    assert ssids.count("mao") == 1
    cafe = next(n for n in nets if n["ssid"] == "Open-Cafe")
    assert cafe["open"] is True and cafe["security"] == "open"
    tp = next(n for n in nets if n["ssid"] == "TPLink")
    assert tp["band"] == "5G"
    mao = next(n for n in nets if n["ssid"] == "mao")
    assert mao["in_use"] is True


def test_connect_requires_flag(monkeypatch):
    monkeypatch.delenv("EDGE_CONSOLE_WIFI_ADMIN", raising=False)
    out = ws.connect("ssid", "pw")
    assert out["ok"] is False and out["status"] == 403


def test_connect_rejects_empty_ssid(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_WIFI_ADMIN", "true")
    monkeypatch.setattr(ws, "nmcli_available", lambda: True)
    out = ws.connect("   ", "pw")
    assert out["ok"] is False and out["status"] == 400


def test_connect_maps_secret_error(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_WIFI_ADMIN", "true")
    monkeypatch.setattr(ws, "nmcli_available", lambda: True)
    monkeypatch.setattr(ws, "radio_on", lambda: True)
    monkeypatch.setattr(ws, "_nmcli", lambda *a, **k: _fake_proc(returncode=4, stderr="Error: Secrets were required, but not provided."))
    out = ws.connect("mao", "wrongpw")
    assert out["ok"] is False
    assert "密碼" in out["error"]


def test_connect_success(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_WIFI_ADMIN", "true")
    monkeypatch.setattr(ws, "nmcli_available", lambda: True)
    monkeypatch.setattr(ws, "radio_on", lambda: True)
    captured = {}

    def _fake(args, **k):
        captured["args"] = args
        return _fake_proc(stdout="Device 'wlan0' successfully activated")

    monkeypatch.setattr(ws, "_nmcli", _fake)
    out = ws.connect("mao", "secret123")
    assert out["ok"] is True
    assert "password" in captured["args"] and "secret123" in captured["args"]
