FROM python:3.11-slim-bookworm

WORKDIR /app

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
