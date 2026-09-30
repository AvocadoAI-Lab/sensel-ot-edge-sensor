# Track A: build eBPF object + libxdp_capture.so, then Python runtime.
FROM debian:bookworm-slim AS bpf-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-libc-dev make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/bpf
COPY bpf/ ./
RUN make clean all && test -f xdp_redirect.bpf.o

FROM debian:bookworm-slim AS native-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make libbpf-dev libxdp-dev linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/native
COPY native/ ./
RUN make clean all && test -f libxdp_capture.so

FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev tcpdump libbpf1 libxdp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY requirements-ml.txt .
ARG INSTALL_ML_RUNTIME=false
RUN if [ "${INSTALL_ML_RUNTIME}" = "true" ]; then \
      pip install --no-cache-dir -r requirements-ml.txt; \
    fi

COPY src/ ./src/
COPY --from=bpf-builder /build/bpf/xdp_redirect.bpf.o /app/bpf/xdp_redirect.bpf.o
COPY --from=native-builder /build/native/libxdp_capture.so /app/lib/libxdp_capture.so

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV XDP_BPF_OBJECT=/app/bpf/xdp_redirect.bpf.o
ENV XDP_CAPTURE_LIB=/app/lib/libxdp_capture.so

CMD ["python", "-m", "src.main"]
