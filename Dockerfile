# LogSync ULPF - one image, several roles (serve | ingest | worker | api | replay).
# Everything the container needs is inside the image: it runs with no network
# access, and `docker save` turns it into a file for an air-gapped site.

# ---- UI: static build, no CDN assets
FROM node:24-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- WASM tokenizer, rebuilt from source (no C toolchain needed)
FROM rust:1.93-slim AS wasm
RUN rustup target add wasm32-unknown-unknown
WORKDIR /runtime
COPY runtime/ ./
RUN cargo build --release --target wasm32-unknown-unknown

# ---- runtime
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY backend/ backend/
COPY --from=wasm /runtime/target/wasm32-unknown-unknown/release/logsync_runtime.wasm \
     backend/logsync/core/wasm/logsync_runtime.wasm
RUN pip install --no-cache-dir ".[kafka]"
COPY packs/ packs/
COPY --from=ui /ui/dist ui/
ENV LOGSYNC_DATA=/data \
    LOGSYNC_PACKS=/app/packs \
    LOGSYNC_STATIC=/app/ui \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8000 5514/tcp 5514/udp
ENTRYPOINT ["logsync"]
CMD ["serve", "--host", "0.0.0.0"]
