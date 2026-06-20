FROM python:3.11-slim-bookworm

WORKDIR /app
COPY src /app/src

ENV PYTHONPATH=/app/src

CMD ["python", "-m", "edgex_event_bridge"]
