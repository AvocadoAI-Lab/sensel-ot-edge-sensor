FROM python:3.11-slim-bookworm

WORKDIR /app

# nmcli (NetworkManager client) lets the console drive the host's NetworkManager
# over the mounted system D-Bus socket for Wi-Fi scan/connect. --no-install-recommends
# keeps the image lean (avoids modemmanager/ppp/etc). The NM daemon is NOT run here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends network-manager \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY static/ ./static/

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PLATFORM_CONFIG_PATH=/data/agent/platform.json
ENV ASSETS_DIR=/data/assets

EXPOSE 8090
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8090"]
