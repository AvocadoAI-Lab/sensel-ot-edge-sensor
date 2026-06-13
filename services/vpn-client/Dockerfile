# SenseL VPN client sidecar.
#
# Runs in the HOST network namespace (see docker-compose) with NET_ADMIN and
# /dev/net/tun so the OpenVPN tunnel (tun0) and any pushed LAN routes apply on
# the appliance host — that is what lets the sensor / operator reach the remote
# internal network (e.g. the MQTT broker at 192.168.1.203) once connected.
#
# The container's main process is a declarative supervisor that reconciles the
# running OpenVPN process to the desired state written by the Edge Console.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openvpn \
        iproute2 \
        iputils-ping \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY supervisor.py /app/supervisor.py

ENV PYTHONUNBUFFERED=1
ENV VPN_STATE_DIR=/data/agent/vpn
ENV VPN_MGMT_PORT=7505

# OpenVPN needs to create the tun device + routes; the supervisor runs it.
CMD ["python3", "/app/supervisor.py"]
