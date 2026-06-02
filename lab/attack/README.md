# Attack Lab — Real Adversarial Traffic (OT-001 ~ OT-018)

Every scenario here sends **genuine packets on the wire** via Scapy. Nothing is
mocked — the passive `packet-sensor` observes them exactly as it would a live
adversary, so this doubles as an end-to-end detection test.

> ⚠️ **Safety**: `arp-spoof` performs real bidirectional ARP cache poisoning and
> *will* disrupt the victim's traffic. Run it **only** on a fully isolated lab
> segment. It restores the correct ARP bindings on exit (SIGINT/SIGTERM).

## Offline self-test (no network, deterministic)

```bash
make verify-attacks        # runs scripts/attacks-selftest.py
```

Feeds crafted packets through the real `PacketPipeline` and asserts all 16
implemented rules fire (OT-001..014, OT-016, OT-018).

## Live lab

```bash
# 1. start base stack + 61850 publishers + broadened capture filter
ATTACK_INTERFACE=eth0 make up-attack-lab

# 2. fire the full sweep (OT-001~018; OT-009 is absence-based)
make attack-all

# 3. targeted scenarios
make attack-goose     # OT-011/012/013
make attack-mms       # OT-014/016/018
make attack-modbus    # OT-007 (+OT-010)
make attack-portscan  # OT-006
make attack-arp       # OT-003 real MITM (isolated lab only!)

# 4. confirm what fired
make verify-attacks
```

## Direct invocation

```bash
docker compose -f docker-compose.yml -f docker-compose.attack-lab.yml \
  --profile attack run --rm attacker-all python attacker.py port-scan --ports 30
```

## Scenario → rule map

| Sub-command        | Rule(s)            | What it sends |
|--------------------|--------------------|---------------|
| `new-mac`          | OT-001             | Frames from a never-seen MAC |
| `new-ip`           | OT-002             | Gratuitous ARP announcing a novel IP |
| `new-pair`         | OT-004, OT-005     | A brand-new src→dst:port TCP SYN |
| `arp-spoof`        | OT-003             | Real bidirectional ARP MITM poisoning |
| `port-scan`        | OT-006             | SYN sweep across many ports |
| `modbus-write`     | OT-007, OT-010     | Modbus write (FC16) from a non-baselined host |
| `unauth-relay`     | OT-010             | Any contact from a non-allowed peer to the relay |
| `traffic-flood`    | OT-008             | Burst far above the asset baseline rate |
| `relay-silence`    | OT-009             | (Helper) prints the absence-based procedure |
| `rogue-goose`      | OT-011             | GOOSE from a publisher not in the baseline |
| `goose-test`       | OT-012             | GOOSE test bit set on a production publisher |
| `goose-stnum`      | OT-013             | stNum rollback / large forward jump |
| `mms-rogue`        | OT-014, OT-016, OT-018 | Non-allowed MMS client writes to a baselined IED |
| `mms-flood`        | OT-015             | Burst of new MMS sessions (distinct client IPs) to one IED |
| `all`              | OT-001~018         | Full sweep (OT-009/OT-017 absence-based; arp-spoof run separately) |

## Configuration (CLI flag or `ATTACK_*` env)

| Env / flag             | Default            | Meaning |
|------------------------|--------------------|---------|
| `ATTACK_INTERFACE` / `--iface`   | `eth0`             | Egress interface |
| `ATTACK_RELAY_IP` / `--relay`    | `192.168.10.20`    | Baselined relay asset |
| `ATTACK_IED_IP` / `--dst`        | `192.168.10.50`    | Baselined MMS IED |
| `ATTACK_ROGUE_IP` / `--rogue`    | `192.168.10.231`   | Attacker / non-baselined source |
| `ATTACK_GATEWAY_IP` / `--gateway`| `192.168.10.1`     | ARP MITM gateway |

The addresses must match `config/policy/baseline.json` for the relay/IED-targeted
rules (OT-007/008/009/010/018) to recognise the asset.

## Notes

- **OT-009 (relay offline)** is absence-based — it cannot be "sent". Seed relay
  traffic once, then keep the relay silent for >120s; it fires on the next 60s
  feature window.
- **OT-017 (GOOSE silence)** is absence-based like OT-009: stop the baselined
  GOOSE publisher and it fires on the next feature window once `max_silence_sec`
  is exceeded.
- The attack-lab overlay broadens the sensor's BPF filter to
  `arp or (ether proto 0x88b8) or (tcp port 102) or (tcp port 502) or ip` so
  every attack class reaches the pipeline.
