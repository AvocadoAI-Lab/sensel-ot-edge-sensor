FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY services/packet-sensor/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/packet-sensor/src ./src
COPY lab/attack/attacker.py ./attacker.py

ENV PYTHONPATH=/app
ENTRYPOINT ["python", "attacker.py"]
CMD ["all"]
