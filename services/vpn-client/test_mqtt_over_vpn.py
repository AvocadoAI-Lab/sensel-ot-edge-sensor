#!/usr/bin/env python3
"""End-to-end VPN reachability test for the SenseL OT Edge appliance.

Exercises the FULL pipeline against a running Edge Console (default
http://127.0.0.1:8090): upload an .ovpn profile -> connect -> wait until the
tunnel is CONNECTED (internal IP assigned) -> diagnose TCP reachability to the
internal MQTT broker (default 192.168.1.203:1883).

This must run on the appliance (or any host with network access to the Console)
because the actual tunnel is established on the appliance host by the
vpn-client sidecar — it cannot be validated from a developer laptop without the
VPN server being reachable.

Stdlib only. Exit code 0 = PASS (MQTT reachable over VPN), non-zero = FAIL.

Example:
    python3 test_mqtt_over_vpn.py \
        --ovpn "/Users/ericmao/Downloads/OpenVPN-Config拷貝.ovpn" \
        --console http://127.0.0.1:8090 \
        --password "$EDGE_CONSOLE_PASSWORD" \
        --mqtt-host 192.168.1.203 --mqtt-port 1883
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class Console:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def _req(self, method: str, path: str, *, body=None, ctype="application/json"):
        url = self.base + path
        data = None
        headers = {}
        if body is not None:
            data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = ctype
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"{method} {path} -> HTTP {e.code}: {raw[:300]}") from e
        return json.loads(raw) if raw.strip() else {}

    def login(self, password: str) -> None:
        self._req("POST", "/api/auth/login", body={"password": password or ""})

    def upload(self, name: str, content: str) -> dict:
        q = urllib.parse.urlencode({"name": name})
        return self._req("POST", f"/api/vpn/profiles?{q}", body=content, ctype="text/plain")

    def connect(self, name: str) -> dict:
        return self._req("POST", "/api/vpn/connect", body={"profile": name})

    def disconnect(self) -> dict:
        return self._req("POST", "/api/vpn/disconnect")

    def status(self) -> dict:
        return self._req("GET", "/api/vpn/status")

    def diagnose(self, host: str, port: int) -> dict:
        q = urllib.parse.urlencode({"host": host, "port": port})
        return self._req("POST", f"/api/vpn/diagnose?{q}")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="VPN -> MQTT reachability test")
    ap.add_argument("--ovpn", default="/Users/ericmao/Downloads/OpenVPN-Config拷貝.ovpn",
                    help="Path to the .ovpn profile to test")
    ap.add_argument("--console", default="http://127.0.0.1:8090")
    ap.add_argument("--name", default="e2e-test")
    ap.add_argument("--password", default="", help="Edge Console password (if set)")
    ap.add_argument("--mqtt-host", default="192.168.1.203")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--timeout", type=int, default=60, help="Seconds to wait for CONNECTED")
    ap.add_argument("--keep", action="store_true", help="Leave the tunnel connected after test")
    args = ap.parse_args()

    try:
        with open(args.ovpn, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as e:
        log(f"FAIL: 無法讀取 ovpn：{e}")
        return 2

    c = Console(args.console)
    try:
        c.login(args.password)
        log(f"已登入 Console {args.console}")

        c.upload(args.name, content)
        log(f"已上傳設定檔：{args.name}")

        c.connect(args.name)
        log("已要求連線，等待 tunnel CONNECTED…")

        deadline = time.time() + args.timeout
        assigned_ip = None
        while time.time() < deadline:
            st = c.status()
            data = st.get("status_data") or {}
            state = st.get("state")
            assigned_ip = data.get("assigned_ip")
            log(f"  state={state} ip={assigned_ip} err={data.get('last_error')}")
            if state == "connected" and assigned_ip:
                break
            time.sleep(3)
        else:
            log("FAIL: 逾時仍未取得內網 IP（tunnel 未 CONNECTED）")
            if not args.keep:
                c.disconnect()
            return 3

        log(f"PASS(1/2): tunnel 已連線，內網 IP = {assigned_ip}")

        diag = c.diagnose(args.mqtt_host, args.mqtt_port)
        reachable = diag.get("reachable")
        log(f"診斷結果：{diag.get('summary')}")
        tcp = (diag.get("probe") or {}).get("tcp_target") or {}
        if not reachable:
            log(f"FAIL: 無法連到 MQTT {args.mqtt_host}:{args.mqtt_port}（{tcp.get('error')}）")
            if not args.keep:
                c.disconnect()
            return 4

        log(f"PASS(2/2): 可透過 VPN 連到 MQTT {args.mqtt_host}:{args.mqtt_port} ✓")
        if not args.keep:
            c.disconnect()
            log("已中斷連線（測試結束）")
        log("=== 整體結果：PASS ===")
        return 0
    except Exception as e:  # noqa: BLE001
        log(f"FAIL: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
