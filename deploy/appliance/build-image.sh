#!/usr/bin/env bash
# One-shot guided packaging flow for the SenseL appliance VM:
#
#   1) build   — build the minimal-stack Docker images into the local cache
#   2) install — wire systemd auto-start + first-boot + promisc + banner units
#   3) prepare — sanitize identity/runtime, ready the image for export
#
# Run on the image-builder box (a sudo-capable user). Steps are confirmed
# interactively; pass --yes to run non-interactively, or limit with
# --only=build|install|prepare (comma-separated).
#
#   sudo ./deploy/appliance/build-image.sh                 # full guided flow
#   sudo ./deploy/appliance/build-image.sh --only=build    # just (re)build
#   sudo ./deploy/appliance/build-image.sh --yes           # no prompts
set -euo pipefail

APP_DIR="${APP_DIR:-/home/sensel/sensel-ot-edge-sensor}"
RUN_USER="${RUN_USER:-sensel}"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.minimal-edgex.yml"
ASSUME_YES=0
ONLY=""

for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=1 ;;
    --only=*) ONLY="${arg#--only=}" ;;
    -h|--help) grep -E '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

want() {
  [[ -z "${ONLY}" || ",${ONLY}," == *",$1,"* ]]
}
confirm() {
  [[ "${ASSUME_YES}" -eq 1 ]] && return 0
  read -r -p "$1 [y/N] " ans
  [[ "${ans}" =~ ^[Yy]$ ]]
}
step() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }

cd "${APP_DIR}"

# 1) BUILD ---------------------------------------------------------------------
if want build; then
  step "Step 1/3 — Build minimal-stack images"
  if confirm "Build/refresh Docker images now? (a few minutes on 2 vCPU)"; then
    sudo -u "${RUN_USER}" docker compose ${COMPOSE_FILES} build
    echo "    images built."
  else
    echo "    skipped build."
  fi
fi

# 2) INSTALL -------------------------------------------------------------------
if want install; then
  step "Step 2/3 — Install systemd units (auto-start / first-boot / promisc / banner)"
  if confirm "Install + enable appliance systemd units?"; then
    APP_DIR="${APP_DIR}" "${APP_DIR}/deploy/appliance/install-appliance.sh"
  else
    echo "    skipped install."
  fi
fi

# 3) PREPARE -------------------------------------------------------------------
if want prepare; then
  step "Step 3/3 — Sanitize image for distribution (DESTRUCTIVE)"
  echo "    This stops the stack and wipes identity + runtime state."
  echo "    Do NOT run on a live production sensor."
  if confirm "Prepare image for export now?"; then
    "${APP_DIR}/deploy/appliance/prepare-image.sh"
    step "Done. Power off and export the VM:  sudo poweroff"
  else
    echo "    skipped prepare. Run later:"
    echo "      sudo ${APP_DIR}/deploy/appliance/prepare-image.sh"
  fi
fi

step "Packaging flow complete."
