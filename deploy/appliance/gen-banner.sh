#!/usr/bin/env bash
# Render the console login banner (/etc/issue) and MOTD (/etc/motd) so an operator
# sitting at the VM console immediately sees HOW to reach the Edge Console — the
# live device IP(s) plus the sensel.local name. Run by sensel-banner.service on
# every boot (after the network is up). Must run as root.
set -euo pipefail

CONSOLE_PORT="${CONSOLE_PORT:-8090}"
CONSOLE_HTTPS_PORT="${CONSOLE_HTTPS_PORT:-8443}"
MDNS_NAME="${MDNS_NAME:-sensel}"

# Collect non-loopback IPv4 addresses on physical NICs (skip docker/bridge/virt
# interfaces so the operator only sees reachable management IPs).
IPS="$(ip -4 -o addr show scope global 2>/dev/null \
  | awk '$2 !~ /^(docker|br-|veth|virbr|cni|flannel|tun|tap|kube)/ {print $4}' \
  | cut -d/ -f1 | paste -sd' ' -)"
[[ -z "${IPS}" ]] && IPS="(尚未取得 IP — 請確認網路/DHCP)"

PRIMARY="$(printf '%s' "${IPS}" | awk '{print $1}')"

URL_LINES=""
for ip in ${IPS}; do
  case "${ip}" in
    *.*) URL_LINES+="    http://${ip}:${CONSOLE_PORT}\n" ;;
  esac
done
[[ -z "${URL_LINES}" ]] && URL_LINES="    (尚未取得 IP)\n"

banner() {
cat <<EOF
========================================================================
  SenseL OT Edge Sensor  ·  RelayGuard
------------------------------------------------------------------------
  在同網段的瀏覽器開啟 Edge Console：

    http://${MDNS_NAME}.local:${CONSOLE_PORT}     (mDNS 名稱)
$(printf "${URL_LINES}")
  HTTPS（自簽）： https://${MDNS_NAME}.local:${CONSOLE_HTTPS_PORT}

  首次使用：進 Console → 操作手冊 → 接入精靈（三步）→ 送出測試事件
========================================================================
EOF
}

# /etc/issue shows BEFORE login on the local/serial console.
banner > /etc/issue
# /etc/motd shows AFTER SSH/console login.
banner > /etc/motd

echo "gen-banner: published console banner (primary IP ${PRIMARY:-none})"
