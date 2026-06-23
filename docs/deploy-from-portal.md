# Deploy from SenseL Portal

Download a pre-configured Docker deploy bundle from the SMB Portal instead of hand-editing `.env`.

## Where to download

| Product | Portal tab | Sub-tab | Profile |
|---------|------------|---------|---------|
| IT NDR | Network Security (NDR) | Sensors | `it_ndr` |
| OT IDS | OT Security | Sensors | `ot_ids` |

Click **下載部署包 ZIP**. The zip includes:

- `.env` — pre-filled `SENSEL_API_URL`, MQTT broker, tenant IDs, and profile flags
- `install.sh` — clones this repo and starts the correct Compose stack
- `README-DEPLOY.md` — quick start for your workspace
- `COMPOSE-COMMAND.txt` — manual compose one-liner

## Quick start (Linux)

```bash
unzip sensel-it-ndr-*.zip -d sensel-deploy   # or sensel-ot-ids-*.zip
cd sensel-deploy
# Edit .env: SENSOR_ID, OT_REGISTRATION_TOKEN (Portal invite code)
chmod +x install.sh
./install.sh
```

Open `http://<edge-ip>:8090` and complete the Setup wizard if registration did not finish automatically.

## Compose stacks

**IT NDR** (`it_ndr`):

```bash
docker compose -f docker-compose.openwrt.yml -f docker-compose.ndr-it.yml -f docker-compose.suricata.yml up -d --build
```

Light Avocado Sentinel UI, Suricata enabled, no EdgeX.

**OT IDS** (`ot_ids`):

```bash
docker compose up -d --build
```

Dark EdgeX OT Console, full OT stack.

## API (for automation)

Authenticated workspace members can call:

```http
GET /api/v1/smb/workspaces/{workspace_id}/ot-security/deploy-bundle?profile=it_ndr
GET /api/v1/smb/workspaces/{workspace_id}/ot-security/deploy-bundle?profile=ot_ids
```

Response: `application/zip` with `Content-Disposition: attachment`.

## Source repository

This edge sensor project is published under [Apache License 2.0](https://github.com/AvocadoAI-Lab/sensel-ot-edge-sensor/blob/main/LICENSE).

See also [deployment-openwrt.md](./deployment-openwrt.md) for SPAN/mirror and hardware notes.
