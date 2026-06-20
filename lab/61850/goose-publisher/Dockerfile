FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY services/packet-sensor/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/packet-sensor/src ./src
COPY lab/61850/goose-publisher/publish.py ./publish.py

ENV PYTHONPATH=/app
CMD ["python", "publish.py"]
