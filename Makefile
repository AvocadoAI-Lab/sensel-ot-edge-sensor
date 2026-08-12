.PHONY: help up down logs build health test lint up-ui up-site down-site train-site validate-site verify-modbus verify-61850 verify-mqtt verify-mvp up-lab-61850 apply-lab-61850-edgex wait-upstream verify-pi-health deploy-pi deploy-pi-full

help:
	@echo "SenseL OT Edge Sensor"
	@echo ""
	@echo "  make up             - Start stack (Ubuntu, includes EdgeX)"
	@echo "  make up-ui          - Start stack with EdgeX lab UI (port 4000)"
	@echo "  make up-lab-61850   - Start stack + IEC 61850 lab overlay"
	@echo "  make up-pi4         - Start stack with Pi4 overlay"
	@echo "  make up-site        - Start isolated Tier 2 Site broker/ingress"
	@echo "  make train-site JOB_ID=...    - Run offline P3-B XGBoost trainer"
	@echo "  make validate-site JOB_ID=... - Validate/quarantine signed candidate"
	@echo "  make deploy-pi      - Deploy to lab Pi (existing EdgeX, default edgex@192.168.1.123)"
	@echo "  make deploy-pi-full - Stop existing EdgeX on Pi, deploy full stack"
	@echo "  make verify-modbus  - Verify Modbus sim → Core Data telemetry"
	@echo "  make verify-mqtt    - Verify feature summary → device-mqtt → Core Data (S1-03)"
	@echo "  make verify-61850   - Verify IEC 61850 passive parser (S1-02b)"
	@echo "  make verify-mvp     - Verify MVP detection OT-001~010 (S2)"
	@echo "  Lab Events UI       - http://<host>:8080 (with pi-lab overlay)"
	@echo "  make down     - Stop stack"
	@echo "  make build    - Build all service images"
	@echo "  make logs     - Tail all service logs"
	@echo "  make health   - Run health check script"
	@echo "  make test     - Run unit tests"

up:
	docker compose up -d

up-ui:
	docker compose --profile lab-ui up -d

up-pi4:
	docker compose -f docker-compose.yml -f docker-compose.pi4.yml up -d

up-site:
	docker compose --env-file .env.site -f docker-compose.site.yml up -d --build

down-site:
	docker compose --env-file .env.site -f docker-compose.site.yml down

train-site:
	@test -n "$(JOB_ID)" || (echo "JOB_ID is required" && exit 2)
	SENSEL_SITE_TRAINER_JOB_ID="$(JOB_ID)" docker compose --env-file .env.site -f docker-compose.site.yml --profile training run --rm sensel-site-trainer

validate-site:
	@test -n "$(JOB_ID)" || (echo "JOB_ID is required" && exit 2)
	SENSEL_SITE_VALIDATOR_JOB_ID="$(JOB_ID)" docker compose --env-file .env.site -f docker-compose.site.yml --profile training run --rm sensel-site-validator

up-lab-61850:
	docker compose -f docker-compose.yml -f docker-compose.lab-61850.yml up -d

apply-lab-61850-edgex:
	./scripts/apply-lab-61850-edgex.sh

wait-upstream:
	./scripts/wait-for-upstream.sh

verify-pi-health:
	./scripts/verify-pi-stack-health.sh

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

health:
	./scripts/health-check.sh

verify-modbus:
	chmod +x ./scripts/edgex-modbus-verify.sh
	./scripts/edgex-modbus-verify.sh

verify-mqtt:
	chmod +x ./scripts/verify-mqtt.sh
	./scripts/verify-mqtt.sh

verify-61850:
	chmod +x ./scripts/verify-61850.sh ./scripts/61850-selftest.py
	./scripts/verify-61850.sh

verify-mvp:
	chmod +x ./scripts/verify-mvp.sh ./scripts/mvp-selftest.py
	./scripts/verify-mvp.sh

test:
	python3 -m pip install -q -r tests/requirements.txt
	python3 -m pip install -q -r services/sensel-edge-agent/requirements.txt
	python3 -m pip install -q -r services/packet-sensor/requirements.txt
	PYTHONPATH=.:services/sensel-edge-agent:services/packet-sensor python3 -m pytest tests -v

lint:
	@echo "Lint targets TBD per service"

deploy-pi:
	chmod +x ./scripts/deploy-pi.sh
	./scripts/deploy-pi.sh $(DEPLOY_TARGET)

deploy-pi-full:
	chmod +x ./scripts/deploy-pi-full.sh
	./scripts/deploy-pi-full.sh $(DEPLOY_TARGET)
