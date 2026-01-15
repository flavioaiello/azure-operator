# Azure Landing Zone Operator - Go Build
#
# ARCHITECTURE:
# - Controller is a pure Go application (~10-15MB image)
# - ARM templates are NOT baked into the image
# - Templates and specs are mounted at runtime via git-sync sidecar
#
# This enables:
# - Zero container rebuilds when Bicep/specs change
# - CI compiles Bicep → ARM JSON → commits to repo
# - Git-sync pulls changes to mounted volumes
# - Reconciler picks up new templates/specs automatically
#
# Volume mounts (provided by ACI/ACA):
# - /templates: Compiled ARM JSON from git-sync
# - /specs: YAML specifications from git-sync

# =============================================================================
# Stage 1: Build Go binary
# =============================================================================
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Download dependencies first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Build arguments for version info
ARG VERSION=dev
ARG BUILD_TIME=unknown

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
    -o /controller \
    ./cmd/controller

# =============================================================================
# Stage 2: Minimal runtime image
# =============================================================================
FROM scratch

# Labels for container metadata
LABEL org.opencontainers.image.title="Azure Landing Zone Operator"
LABEL org.opencontainers.image.description="Kubernetes-style operator for Azure Landing Zones"
LABEL org.opencontainers.image.source="https://github.com/flavioaiello/azure-operator"
LABEL org.opencontainers.image.licenses="MIT"

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /controller /controller

# Default configuration - templates and specs are mounted at runtime
ENV TEMPLATES_DIR=/templates
ENV SPECS_DIR=/specs

# Volumes for runtime-mounted content (git-sync provides these)
VOLUME /templates
VOLUME /specs

# Run as non-root (UID 65532 is the "nonroot" user in distroless)
USER 65532:65532

# Entry point
ENTRYPOINT ["/controller"]
