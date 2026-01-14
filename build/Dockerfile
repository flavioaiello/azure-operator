# Azure Landing Zone Operator - Minimal Python Runtime
#
# ARCHITECTURE:
# - Controller is a pure Python application (~50MB image)
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
# Stage 1: Build Python dependencies
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into a target directory
COPY requirements.txt ./
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

# Copy application source (controller module)
COPY src/controller/ /app/controller/

# =============================================================================
# Stage 2: Distroless Python runtime
# =============================================================================
FROM gcr.io/distroless/python3-debian12:nonroot

# Labels for container metadata
LABEL org.opencontainers.image.title="Azure Landing Zone Operator"
LABEL org.opencontainers.image.description="Kubernetes-style operator for Azure Landing Zones"
LABEL org.opencontainers.image.source="https://github.com/flavioaiello/azure-operator"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy installed dependencies
COPY --from=builder /deps /app/deps

# Copy application source
COPY --from=builder /app/controller /app/controller

# Set Python path to include our deps and app
ENV PYTHONPATH=/app/deps:/app
ENV PYTHONUNBUFFERED=1

# Default configuration - templates and specs are mounted at runtime
ENV TEMPLATES_DIR=/templates
ENV SPECS_DIR=/specs

# Volumes for runtime-mounted content (git-sync provides these)
VOLUME /templates
VOLUME /specs

# Run as non-root (distroless:nonroot already sets UID 65532)
USER nonroot

# Entry point - run controller module
ENTRYPOINT ["python", "-m", "controller.main"]
