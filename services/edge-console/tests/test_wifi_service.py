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
    monkeypatch.setattr(ws, "promote_and_prune_wifi", lambda ssid, **k: {"kept": [ssid], "deleted": []})
    captured = {}

    def _fake(args, **k):
        captured["args"] = args
        return _fake_proc(stdout="Device 'wlan0' successfully activated")

    monkeypatch.setattr(ws, "_nmcli", _fake)
    out = ws.connect("mao", "secret123")
    assert out["ok"] is True
    assert "password" in captured["args"] and "secret123" in captured["args"]
    assert out["history"]["kept"] == ["mao"]


def test_saved_wifi_connections_filters_wifi_only(monkeypatch):
    out = "\n".join([
        "mao:uuid-1:802-11-wireless:1700000300",
        "Wired connection 1:uuid-2:802-3-ethernet:1700000000",
        "TPLink:uuid-3:802-11-wireless:1700000200",
        "Cafe:uuid-4:802-11-wireless:0",
    ])
    monkeypatch.setattr(ws, "_nmcli", lambda *a, **k: _fake_proc(stdout=out))
    rows = ws._saved_wifi_connections()
    names = [r["name"] for r in rows]
    assert names == ["mao", "TPLink", "Cafe"]  # ethernet dropped
    assert next(r for r in rows if r["name"] == "Cafe")["timestamp"] == 0


def test_promote_and_prune_keeps_recent_three_and_prioritises(monkeypatch):
    saved = [
        {"name": "old1", "uuid": "u-old1", "timestamp": 100},
        {"name": "mao", "uuid": "u-mao", "timestamp": 500},
        {"name": "office", "uuid": "u-office", "timestamp": 400},
        {"name": "home", "uuid": "u-home", "timestamp": 300},
        {"name": "old2", "uuid": "u-old2", "timestamp": 50},
    ]
    monkeypatch.setattr(ws, "_saved_wifi_connections", lambda: list(saved))
    calls = []

    def _fake(args, **k):
        calls.append(args)
        return _fake_proc()

    monkeypatch.setattr(ws, "_nmcli", _fake)
    result = ws.promote_and_prune_wifi("mao", keep=3)

    assert result["kept"] == ["mao", "office", "home"]
    assert set(result["deleted"]) == {"old1", "old2"}

    # Most-recent (mao) gets the highest priority; descending after that.
    mods = {a[2]: a for a in calls if a[0:2] == ["connection", "modify"]}
    assert mods["u-mao"][-1] == "100"
    assert mods["u-office"][-1] == "99"
    assert mods["u-home"][-1] == "98"
    # The two oldest are deleted by uuid.
    deletes = {a[3] for a in calls if a[0:2] == ["connection", "delete"]}
    assert deletes == {"u-old1", "u-old2"}


def test_promote_forces_active_ssid_to_front(monkeypatch):
    # Active SSID has a stale (older) timestamp but must still survive + lead.
    saved = [
        {"name": "a", "uuid": "ua", "timestamp": 900},
        {"name": "b", "uuid": "ub", "timestamp": 800},
        {"name": "c", "uuid": "uc", "timestamp": 700},
        {"name": "justconnected", "uuid": "ujc", "timestamp": 0},
    ]
    monkeypatch.setattr(ws, "_saved_wifi_connections", lambda: list(saved))
    monkeypatch.setattr(ws, "_nmcli", lambda *a, **k: _fake_proc())
    result = ws.promote_and_prune_wifi("justconnected", keep=3)
    assert result["kept"][0] == "justconnected"
    assert "c" in result["deleted"]


def test_known_networks_recent_first(monkeypatch):
    saved = [
        {"name": "old", "uuid": "u1", "timestamp": 100},
        {"name": "mao", "uuid": "u2", "timestamp": 500},
        {"name": "office", "uuid": "u3", "timestamp": 400},
    ]
    monkeypatch.setattr(ws, "_saved_wifi_connections", lambda: list(saved))
    monkeypatch.setattr(ws, "_load_pinned", lambda: ["mao"])
    known = ws.known_networks(keep=3)
    assert [k["ssid"] for k in known] == ["mao", "office", "old"]
    assert known[0]["order"] == 1
    assert known[0]["pinned"] is True and known[1]["pinned"] is False


def test_promote_never_prunes_or_reprioritises_pinned(monkeypatch):
    # "hotspot" is pinned: it must survive pruning and keep its pinned band
    # (promote only touches the non-pinned recency list).
    saved = [
        {"name": "hotspot", "uuid": "u-hot", "timestamp": 10},   # oldest, but pinned
        {"name": "mao", "uuid": "u-mao", "timestamp": 500},
        {"name": "office", "uuid": "u-office", "timestamp": 400},
        {"name": "home", "uuid": "u-home", "timestamp": 300},
        {"name": "stale", "uuid": "u-stale", "timestamp": 50},
    ]
    monkeypatch.setattr(ws, "_saved_wifi_connections", lambda: list(saved))
    monkeypatch.setattr(ws, "_load_pinned", lambda: ["hotspot"])
    calls = []
    monkeypatch.setattr(ws, "_nmcli", lambda args, **k: (calls.append(args), _fake_proc())[1])

    result = ws.promote_and_prune_wifi("mao", keep=3)

    # pinned hotspot is not deleted even though it is the oldest non-kept by time
    deletes = {a[3] for a in calls if a[0:2] == ["connection", "delete"]}
    assert "u-hot" not in deletes
    assert "hotspot" in result["pinned"]
    # hotspot priority is never modified here
    modded = {a[2] for a in calls if a[0:2] == ["connection", "modify"]}
    assert "u-hot" not in modded


def test_set_wifi_priority_assigns_high_band(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_WIFI_ADMIN", "true")
    monkeypatch.setattr(ws, "nmcli_available", lambda: True)
    saved = [
        {"name": "hotspot", "uuid": "u-hot", "timestamp": 10},
        {"name": "switch", "uuid": "u-sw", "timestamp": 20},
        {"name": "ghost", "uuid": "u-ghost", "timestamp": 0},
    ]
    monkeypatch.setattr(ws, "_saved_wifi_connections", lambda: list(saved))
    monkeypatch.setattr(ws, "_load_pinned", lambda: [])
    persisted = {}
    monkeypatch.setattr(ws, "_save_pinned", lambda order: persisted.update(order=order))
    calls = []
    monkeypatch.setattr(ws, "_nmcli", lambda args, **k: (calls.append(args), _fake_proc())[1])

    # "missing" is not a saved profile and must be dropped silently.
    out = ws.set_wifi_priority(["hotspot", "switch", "missing"])
    assert out["ok"] is True
    assert persisted["order"] == ["hotspot", "switch"]
    mods = {a[2]: a[-1] for a in calls if a[0:2] == ["connection", "modify"]}
    assert mods["u-hot"] == str(ws._WIFI_PINNED_BASE)        # highest
    assert mods["u-sw"] == str(ws._WIFI_PINNED_BASE - 1)     # next


def test_set_wifi_priority_requires_flag(monkeypatch):
    monkeypatch.delenv("EDGE_CONSOLE_WIFI_ADMIN", raising=False)
    out = ws.set_wifi_priority(["x"])
    assert out["ok"] is False and out["status"] == 403
