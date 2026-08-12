FROM python:3.11-slim-bookworm

RUN groupadd --system --gid 10001 sensel-site \
    && useradd --system --uid 10001 --gid sensel-site --home /nonexistent sensel-site

WORKDIR /app

COPY services/sensel-site/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/sensel-site/sensel_site/ ./sensel_site/
COPY services/sensel-edge-agent/sensel/ ./sensel/
COPY config/model/feature-contract.*.json ./contracts/

RUN mkdir -p /var/lib/sensel-site \
    && chown -R sensel-site:sensel-site /var/lib/sensel-site

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

USER 10001:10001

CMD ["python", "-m", "sensel_site.main"]
