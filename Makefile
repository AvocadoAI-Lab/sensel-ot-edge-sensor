.PHONY: help up down logs build health test lint up-ui verify-modbus verify-61850 verify-mqtt verify-mvp verify-attacks up-lab-61850 up-attack-lab attack-all attack-arp attack-goose attack-mms attack-modbus attack-portscan deploy-pi deploy-pi-full

help:
	@echo "SenseL OT Edge Sensor"
	@echo ""
	@echo "  make up             - Start stack (Ubuntu, includes EdgeX)"
	@echo "  make up-ui          - Start stack with EdgeX lab UI (port 4000)"
	@echo "  make up-lab-61850   - Start stack + IEC 61850 lab overlay"
	@echo "  make up-pi4         - Start stack with Pi4 overlay"
	@echo "  make deploy-pi      - Deploy to lab Pi (existing EdgeX, default edgex@192.168.1.123)"
	@echo "  make deploy-pi-full - Stop existing EdgeX on Pi, deploy full stack"
	@echo "  make verify-modbus  - Verify Modbus sim → Core Data telemetry"
	@echo "  make verify-mqtt    - Verify feature summary → device-mqtt → Core Data (S1-03)"
	@echo "  make verify-61850   - Verify IEC 61850 passive parser (S1-02b)"
	@echo "  make verify-mvp     - Verify MVP detection OT-001~010 (S2)"
	@echo "  make verify-attacks - Verify attack detection coverage OT-001~018 (offline self-test)"
	@echo "  make scd-baseline      - Derive detection baseline from an SCD/SCL file (SCD=path)"
	@echo "  make observed-baseline - Derive candidate baseline from learning state (DB=path)"
	@echo "  make up-attack-lab  - Start stack + 61850 lab + broadened capture (attack lab)"
	@echo "  make attack-all     - Fire REAL OT-001~018 attack sweep (OT-009 absence-based)"
	@echo "  make attack-arp     - REAL MITM ARP poisoning → OT-003 (isolated lab only!)"
	@echo "  make attack-goose   - Rogue/test/stNum GOOSE → OT-011/012/013"
	@echo "  make attack-mms     - Rogue MMS client write → OT-014/016/018"
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

up-lab-61850:
	docker compose -f docker-compose.yml -f docker-compose.lab-61850.yml up -d

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

verify-attacks:
	chmod +x ./scripts/verify-attacks.sh ./scripts/attacks-selftest.py
	./scripts/verify-attacks.sh

# Derive baseline from an SCD/SCL file:  make scd-baseline SCD=substation.scd
scd-baseline:
	python3 scripts/scd-to-baseline.py $(SCD) --out config/policy/baseline.json --force

# Derive candidate baseline from learning state:  make observed-baseline DB=data/assets/learned-state.db
observed-baseline:
	python3 scripts/observed-to-baseline.py $(DB) --out config/policy/baseline.json --force

COMPOSE_ATTACK = docker compose -f docker-compose.yml -f docker-compose.lab-61850.yml -f docker-compose.attack-lab.yml

up-attack-lab:
	$(COMPOSE_ATTACK) up -d --build

attack-all:
	$(COMPOSE_ATTACK) --profile attack run --rm attacker-all

attack-arp:
	$(COMPOSE_ATTACK) --profile attack-arp run --rm attacker-arp

attack-goose:
	$(COMPOSE_ATTACK) --profile attack-goose run --rm attacker-goose

attack-mms:
	$(COMPOSE_ATTACK) --profile attack-mms run --rm attacker-mms

attack-modbus:
	$(COMPOSE_ATTACK) --profile attack-modbus run --rm attacker-modbus

attack-portscan:
	$(COMPOSE_ATTACK) --profile attack-portscan run --rm attacker-portscan

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
