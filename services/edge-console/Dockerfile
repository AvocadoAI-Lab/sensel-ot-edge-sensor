<<<<<<< Updated upstream
FROM python:3.11-slim-bookworm

WORKDIR /app

# nmcli (NetworkManager client) lets the console drive the host's NetworkManager
# over the mounted system D-Bus socket for Wi-Fi scan/connect. --no-install-recommends
# keeps the image lean (avoids modemmanager/ppp/etc). The NM daemon is NOT run here.
# openssl: generate the self-signed TLS cert for HTTPS on .local at startup.
RUN apt-get update \
    && apt-get install -y --no-install-recommends network-manager openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY static/ ./static/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PLATFORM_CONFIG_PATH=/data/agent/platform.json
ENV ASSETS_DIR=/data/assets

# 8090 = HTTP (unchanged), 8443 = HTTPS (self-signed, for https://sensel.local)
EXPOSE 8090 8443
ENTRYPOINT ["/app/entrypoint.sh"]
=======
FROM python:3.11-slim-bookworm

WORKDIR /app

# nmcli (NetworkManager client) lets the console drive the host's NetworkManager
# over the mounted system D-Bus socket for Wi-Fi scan/connect. --no-install-recommends
# keeps the image lean (avoids modemmanager/ppp/etc). The NM daemon is NOT run here.
# openssl: generate the self-signed TLS cert for HTTPS on .local at startup.
RUN apt-get update \
    && apt-get install -y --no-install-recommends network-manager openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY static/ ./static/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PLATFORM_CONFIG_PATH=/data/agent/platform.json
ENV ASSETS_DIR=/data/assets

# 8090 = HTTP (unchanged), 8443 = HTTPS (self-signed, for https://sensel.local)
EXPOSE 8090 8443
ENTRYPOINT ["/app/entrypoint.sh"]
>>>>>>> Stashed changes
