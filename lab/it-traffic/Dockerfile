FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY services/packet-sensor/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY lab/it-traffic/publish.py ./publish.py

CMD ["python", "publish.py"]
