# SenseL VPN Client (OpenVPN sidecar)

Declarative, self-healing OpenVPN client for the OT Edge appliance. The Edge
Console (port 8090) is the control plane; this sidecar is the data plane.

## How it works

```
┌────────────────────┐  writes desired.json   ┌──────────────────────┐
│  edge-console:8090  │ ──────────────────────▶│  ./data/agent/vpn/   │
│  (bridge net)       │ ◀────────────────────── │  profiles/*.ovpn     │
│  vpn_service.py     │   reads status.json     │  desired.json        │
└─────────┬──────────┘                          │  status.json         │
          │ docker exec (diagnose)              └──────────┬───────────┘
          ▼                                                │ reconcile
┌────────────────────────────────────────────────────────▼───────────┐
│  vpn-client  (network_mode: host, NET_ADMIN, /dev/net/tun)           │
│  supervisor.py  ──spawns──▶  openvpn ──creates──▶  tun0 (internal IP) │
└──────────────────────────────────────────────────────────────────────┘
```

* **Declarative** — the Console only writes a *desired* state. The supervisor
  reconciles the running OpenVPN process to it, so a Console restart never
  leaves the tunnel in an unknown state.
* **Self-healing** — if OpenVPN exits while it should be connected the
  supervisor restarts it with capped backoff; `--ping-restart` handles dead
  peers. On container restart the desired state is re-applied automatically.
* **Host namespace** — the tunnel lives on the appliance host, so pushed LAN
  routes let the sensor reach the remote internal network (e.g. MQTT at
  `192.168.1.203`).
* **Lockout-safe default** — split tunnel: pushed LAN routes are kept but the
  server may **not** seize the default gateway unless a profile opts in
  (`redirect_gateway: true`). Embedded `up`/`down` scripts never run
  (`--script-security 1`).

## State files (`/data/agent/vpn/`)

| File | Writer | Purpose |
|------|--------|---------|
| `profiles/<name>.ovpn` | console | uploaded profile (chmod 600) |
| `profiles/<name>.auth`  | console | optional `user\npass` (chmod 600) |
| `desired.json` | console | `{connect, profile, redirect_gateway, auth, epoch}` |
| `status.json`  | supervisor | live `{state, assigned_ip, tun_device, server, since, bytes_*}` |
| `run/openvpn.log` | openvpn | current session log |

## Enable

Set in `.env` / compose (defaults to on):

```
EDGE_CONSOLE_VPN_ADMIN=true
```

Bring it up:

```
docker compose up -d --build vpn-client edge-console
```

The host must have the `tun` module loaded (`modprobe tun`) and
`/dev/net/tun` present.

## End-to-end test (on the appliance)

```
python3 services/vpn-client/test_mqtt_over_vpn.py \
    --ovpn "/path/to/profile.ovpn" \
    --console http://127.0.0.1:8090 \
    --password "$EDGE_CONSOLE_PASSWORD" \
    --mqtt-host 192.168.1.203 --mqtt-port 1883
```

Exit code `0` = the tunnel connected, an internal IP was assigned, and the MQTT
broker was reachable over the VPN.
