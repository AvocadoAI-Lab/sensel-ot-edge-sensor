FROM python:3.11-slim-bookworm

WORKDIR /app
COPY lab/mock-sensel/server.py ./server.py

ENV MOCK_SENSEL_HOST=0.0.0.0
ENV MOCK_SENSEL_PORT=8765
ENV UPLOADED_EVENTS_PATH=/data/assets/uploaded-events.jsonl

EXPOSE 8765
CMD ["python", "server.py"]
