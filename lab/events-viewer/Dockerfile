FROM python:3.11-slim-bookworm

WORKDIR /app
COPY lab/events-viewer/app.py ./app.py
COPY lab/events-viewer/static ./static

ENV ASSETS_DIR=/data/assets
ENV EVENTS_VIEWER_HOST=0.0.0.0
ENV EVENTS_VIEWER_PORT=8080

EXPOSE 8080
CMD ["python", "app.py"]
