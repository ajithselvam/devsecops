# syntax=docker/dockerfile:1
#
# Full-stack image for the DevSecOps AI platform: the Fastify API plus the Vite
# SPA served by nginx, which also proxies /api and /ws to the API.
#
# Deliberately NOT included:
#   - any .env file; every setting arrives as a runtime env var (see
#     docker/entrypoint.sh, which turns the InsForge ones into runtime-config.js)
#   - the legacy Prisma/SQLite directory; the DAL talks to InsForge Postgres
#   - dev dependencies; only the hoisted root node_modules is shipped
#
# Build (from the repo root):
#   docker buildx build --platform linux/amd64 -t ajith567890/devsecops-ai:latest .
#   docker push ajith567890/devsecops-ai:latest

# ---------------------------------------------------------------- API deps
FROM node:22-alpine AS api-deps
WORKDIR /app
RUN apk add --no-cache openssl
COPY package.json package-lock.json ./
COPY shared/package.json shared/
COPY backend/package.json backend/
COPY frontend/package.json frontend/
# Only shared + backend are needed for the API build; installing all three
# manifests keeps the lockfile in sync across the workspace.
RUN npm ci --workspace=shared --workspace=backend --include-workspace-root

FROM api-deps AS api-build
WORKDIR /app
COPY shared ./shared
COPY backend ./backend
RUN npm run build --workspace=shared \
  && npm run build --workspace=backend

# ------------------------------------------------------------ frontend deps
FROM node:22-alpine AS web-deps
WORKDIR /app
RUN apk add --no-cache openssl
COPY package.json package-lock.json ./
COPY shared/package.json shared/
COPY backend/package.json backend/
COPY frontend/package.json frontend/
RUN npm ci --workspace=shared --workspace=frontend --include-workspace-root

FROM web-deps AS web-build
WORKDIR /app
COPY shared ./shared
COPY frontend ./frontend
# tsc runs first and needs the built shared types.
RUN npm run build --workspace=shared \
  && npm run build --workspace=frontend

# ------------------------------------------------------------------ runtime
FROM node:22-alpine AS runner
WORKDIR /app
RUN apk add --no-cache ca-certificates openssl tar curl nginx tini

# The scanners shell out to these binaries, so they ship with the image.
ARG TRIVY_VERSION=0.74.0
ARG GRYPE_VERSION=0.117.0
ARG SYFT_VERSION=1.51.0
# TARGETARCH is set by buildkit; fall back to uname for a plain legacy build.
ARG TARGETARCH
RUN set -eu; \
  arch="${TARGETARCH:-}"; \
  if [ -z "$arch" ]; then \
    case "$(uname -m)" in \
      x86_64) arch=amd64 ;; \
      aarch64) arch=arm64 ;; \
      *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
  fi; \
  case "$arch" in \
    amd64) trivy_arch=Linux-64bit; anchore_arch=linux_amd64 ;; \
    arm64) trivy_arch=Linux-ARM64; anchore_arch=linux_arm64 ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac; \
  cd /tmp; \
  fetch() { \
    url="$1"; file="$2"; sums="$3"; \
    curl -fsSL -o "$file" "$url/$file"; \
    curl -fsSL -o "$sums" "$url/$sums"; \
    grep " $file\$" "$sums" | sha256sum -c -; \
    tar -xzf "$file"; \
  }; \
  fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
        "trivy_${TRIVY_VERSION}_${trivy_arch}.tar.gz" \
        "trivy_${TRIVY_VERSION}_checksums.txt"; \
  fetch "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}" \
        "grype_${GRYPE_VERSION}_${anchore_arch}.tar.gz" \
        "grype_${GRYPE_VERSION}_checksums.txt"; \
  fetch "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
        "syft_${SYFT_VERSION}_${anchore_arch}.tar.gz" \
        "syft_${SYFT_VERSION}_checksums.txt"; \
  install -m 0755 trivy grype syft /usr/local/bin/; \
  rm -rf /tmp/*; \
  trivy --version; grype version; syft version

ARG APP_VERSION=1.0.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="devsecops-ai" \
      org.opencontainers.image.description="AI-powered DevSecOps command center (Fastify API + React SPA on nginx)" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/ajith567890/devsecops-ai" \
      org.opencontainers.image.vendor="ajith567890"

ENV NODE_ENV=production \
  HOST=0.0.0.0 \
  PORT=3001 \
  UPLOAD_DIR=/data/uploads

COPY --from=api-build /app/package.json /app/package-lock.json ./
# npm hoists workspace dependencies to the root node_modules, which also holds
# the @devsecops/shared symlink, so it is the only one that needs copying.
COPY --from=api-build /app/node_modules ./node_modules
COPY --from=api-build /app/shared/package.json ./shared/package.json
COPY --from=api-build /app/shared/dist ./shared/dist
COPY --from=api-build /app/backend/package.json ./backend/package.json
COPY --from=api-build /app/backend/dist ./backend/dist

COPY --from=web-build /app/frontend/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN set -eux; \
  chmod +x /usr/local/bin/entrypoint.sh; \
  mkdir -p /data/uploads /var/lib/nginx/tmp; \
  rm -f /etc/nginx/http.d/default.conf

EXPOSE 80 3001

# Runs through nginx, so it also covers the API being up: if node is down the
# /health proxy returns 502 and curl -f fails.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1/health || exit 1

# The container stays root so it can bind :80 and reach the mounted
# /var/run/docker.sock, which the image scans need. nginx workers still drop
# to the unprivileged nginx user (nginx.conf sets no `user`, so the master
# keeps :80 and the workers do not).
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
