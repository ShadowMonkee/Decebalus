# Decebalus — multi-stage build producing one image that serves the API + web UI.
# The AD modules shell out to nmap / NetExec / smbclient, installed in the runtime
# stage. Run `decebalus doctor` in the container to see tool status.

# 1. Build the Svelte frontend.
FROM node:20-slim AS frontend
WORKDIR /app/decebalus-frontend
COPY decebalus-frontend/package*.json ./
RUN npm ci
COPY decebalus-frontend/ ./
RUN npm run build

# 2. Build the Rust backend.
FROM rust:1-slim AS backend
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /app/decebalus-backend
COPY decebalus-backend/ ./
RUN cargo build --release

# 3. Runtime image with the orchestrated tools.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap smbclient pipx ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN pipx install netexec && pipx install certipy-ad || true
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY --from=backend  /app/decebalus-backend/target/release/decebalus-backend /usr/local/bin/decebalus
COPY --from=frontend /app/decebalus-frontend/dist ./frontend
ENV FRONTEND_DIR=/app/frontend
ENV DATABASE_URL=sqlite:/app/data/decebalus.db
EXPOSE 8080
CMD ["decebalus"]
