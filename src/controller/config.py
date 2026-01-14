"""Configuration management with validation.

Security constraints are enforced at configuration load time to ensure
the operator runs in a secure mode by default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class DeploymentScope(str, Enum):
    """Supported Azure deployment scopes."""

    SUBSCRIPTION = "subscription"
    MANAGEMENT_GROUP = "managementGroup"
    RESOURCE_GROUP = "resourceGroup"


class ConfigurationError(Exception):
    """Raised when configuration validation fails."""

    pass


# Configuration constants with documented bounds
DEFAULT_RECONCILE_INTERVAL_SECONDS = 300
MIN_RECONCILE_INTERVAL_SECONDS = 60
MAX_RECONCILE_INTERVAL_SECONDS = 3600

DEFAULT_WHATIF_TIMEOUT_SECONDS = 300
DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS = 1800

MAX_DEPLOYMENT_RETRIES = 3
RETRY_BACKOFF_BASE_SECONDS = 5

# Security constraints - enforced limits to prevent abuse
MAX_SPEC_FILE_SIZE_BYTES = 1024 * 1024  # 1MB max spec file
MAX_TEMPLATE_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB max ARM template
MAX_DEPLOYMENT_NAME_LENGTH = 64
MAX_RESOURCE_GROUP_NAME_LENGTH = 90
MAX_CONCURRENT_DEPLOYMENTS = 1  # No parallel deployments per operator
MAX_WHATIF_CHANGES = 1000  # Max WhatIf changes to process (prevent OOM)

# Input validation patterns
VALID_DOMAIN_PATTERN = r"^[a-z][a-z0-9-]{0,62}[a-z0-9]$"
VALID_SUBSCRIPTION_ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
VALID_LOCATION_PATTERN = r"^[a-z]{2,}[a-z0-9]*$"


@dataclass(frozen=True)
class SecurityConfig:
    """Security-related configuration with safe defaults.

    SECRETLESS ARCHITECTURE:
    This operator enforces a secretless security model where:
    - ALL authentication uses User-Assigned Managed Identities (UAMIs)
    - NO service principal secrets or passwords are allowed
    - NO credentials are stored in environment variables or files
    - ALL Azure API calls are authenticated via Azure AD / Entra ID tokens

    This is NOT configurable - secretless is mandatory by design.
    See src/controller/security.py for enforcement details.

    SECURITY: All flags are enforced at runtime:
    - Secretless architecture: Enforced in security.py via get_managed_identity_credential()
    - max_resources_per_deployment: Enforced in Reconciler._reconcile_once()
    - enable_audit_logging: Enforced in main.setup_logging()
    """

    # Maximum resources per deployment to prevent runaway changes
    # Exceeding this limit causes reconciliation to fail with an error
    max_resources_per_deployment: int = 100

    # Enable structured audit logging (JSON format to stdout)
    enable_audit_logging: bool = True


@dataclass(frozen=True)
class Config:
    """Operator configuration loaded from environment variables.

    All fields are validated at construction time. Invalid configurations
    raise ConfigurationError immediately rather than failing at runtime.
    """

    # Required fields
    domain: str
    subscription_id: str
    location: str

    # Paths
    specs_dir: Path = field(default_factory=lambda: Path("/specs"))
    templates_dir: Path = field(default_factory=lambda: Path("/templates"))

    # Deployment scope
    scope: DeploymentScope = DeploymentScope.SUBSCRIPTION
    management_group_id: str | None = None
    resource_group_name: str | None = None

    # Timing
    reconcile_interval_seconds: int = DEFAULT_RECONCILE_INTERVAL_SECONDS
    whatif_timeout_seconds: int = DEFAULT_WHATIF_TIMEOUT_SECONDS
    deployment_timeout_seconds: int = DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS

    # Behavior
    dry_run: bool = False

    # Security configuration
    security: SecurityConfig = field(default_factory=SecurityConfig)

    def __post_init__(self) -> None:
        """Validate configuration after initialization.

        SECURITY: All inputs are validated at the boundary (fail-fast).
        This includes format validation to prevent injection attacks.
        """
        import re

        errors: list[str] = []

        # Required field validation
        if not self.domain:
            errors.append("DOMAIN is required")
        elif not re.match(VALID_DOMAIN_PATTERN, self.domain):
            errors.append(f"DOMAIN must match pattern {VALID_DOMAIN_PATTERN}: {self.domain}")

        if not self.subscription_id:
            errors.append("AZURE_SUBSCRIPTION_ID is required")
        elif not re.match(VALID_SUBSCRIPTION_ID_PATTERN, self.subscription_id.lower()):
            errors.append(f"AZURE_SUBSCRIPTION_ID must be a valid GUID: {self.subscription_id}")

        if not self.location:
            errors.append("AZURE_LOCATION is required")
        elif not re.match(VALID_LOCATION_PATTERN, self.location.lower()):
            errors.append(f"AZURE_LOCATION must be a valid Azure region: {self.location}")

        # Scope-specific validation
        if self.scope == DeploymentScope.MANAGEMENT_GROUP and not self.management_group_id:
            errors.append("MANAGEMENT_GROUP_ID is required when scope is managementGroup")

        if self.scope == DeploymentScope.RESOURCE_GROUP and not self.resource_group_name:
            errors.append("RESOURCE_GROUP_NAME is required when scope is resourceGroup")

        rg_name_len = len(self.resource_group_name) if self.resource_group_name else 0
        if self.resource_group_name and rg_name_len > MAX_RESOURCE_GROUP_NAME_LENGTH:
            errors.append(
                f"RESOURCE_GROUP_NAME exceeds maximum length of {MAX_RESOURCE_GROUP_NAME_LENGTH}"
            )

        # Timing validation
        if not (
            MIN_RECONCILE_INTERVAL_SECONDS
            <= self.reconcile_interval_seconds
            <= MAX_RECONCILE_INTERVAL_SECONDS
        ):
            errors.append(
                f"RECONCILE_INTERVAL must be between {MIN_RECONCILE_INTERVAL_SECONDS} "
                f"and {MAX_RECONCILE_INTERVAL_SECONDS} seconds"
            )

        # Path validation
        if not self.specs_dir.exists():
            errors.append(f"Specs directory does not exist: {self.specs_dir}")

        if not self.templates_dir.exists():
            errors.append(f"Templates directory does not exist: {self.templates_dir}")

        # Security constraint validation
        if self.security.max_resources_per_deployment < 1:
            errors.append("max_resources_per_deployment must be at least 1")
        elif self.security.max_resources_per_deployment > 800:
            # ARM limit is 800 resources per deployment
            errors.append("max_resources_per_deployment cannot exceed 800 (ARM limit)")

        if errors:
            error_msg = "Configuration validation failed:\n  - " + "\n  - ".join(errors)
            raise ConfigurationError(error_msg)

    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables.

        Environment Variables:
            DOMAIN: The domain to reconcile (management, connectivity, etc.)
            AZURE_SUBSCRIPTION_ID: Target Azure subscription
            AZURE_LOCATION: Default deployment location
            DEPLOYMENT_SCOPE: One of subscription, managementGroup, resourceGroup
            MANAGEMENT_GROUP_ID: Required if scope is managementGroup
            RESOURCE_GROUP_NAME: Required if scope is resourceGroup
            SPECS_DIR: Path to YAML specs (default: /specs)
            TEMPLATES_DIR: Path to compiled ARM templates (default: /templates)
            RECONCILE_INTERVAL: Seconds between reconciliation loops (default: 300)
            WHATIF_TIMEOUT: Timeout for WhatIf operations in seconds (default: 300)
            DEPLOYMENT_TIMEOUT: Timeout for deployments in seconds (default: 1800)
            DRY_RUN: If "true", only detect drift without applying (default: false)

        Bootstrap Cascade Variables:
            BOOTSTRAP_IDENTITY_RESOURCE_GROUP: If set, enables cascade mode.
                The operator will wait for its UAMI to be provisioned by the
                bootstrap operator in this resource group before starting.
                Format: Resource group name (e.g., "rg-operator-identities")

        Security Variables:
            MAX_RESOURCES_PER_DEPLOYMENT: Max resources per deployment (default: 100)
            ENABLE_AUDIT_LOGGING: Enable JSON audit logs (default: true)
        """

        def get_int(key: str, default: int) -> int:
            value = os.environ.get(key)
            if value is None:
                return default
            try:
                return int(value)
            except ValueError as e:
                raise ConfigurationError(f"{key} must be an integer: {value}") from e

        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(key, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes")

        def get_scope(value: str | None) -> DeploymentScope:
            if not value:
                return DeploymentScope.SUBSCRIPTION
            try:
                return DeploymentScope(value)
            except ValueError as e:
                valid = [s.value for s in DeploymentScope]
                raise ConfigurationError(f"DEPLOYMENT_SCOPE must be one of {valid}: {value}") from e

        return cls(
            domain=os.environ.get("DOMAIN", ""),
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
            location=os.environ.get("AZURE_LOCATION", ""),
            specs_dir=Path(os.environ.get("SPECS_DIR", "/specs")),
            templates_dir=Path(os.environ.get("TEMPLATES_DIR", "/templates")),
            scope=get_scope(os.environ.get("DEPLOYMENT_SCOPE")),
            management_group_id=os.environ.get("MANAGEMENT_GROUP_ID"),
            resource_group_name=os.environ.get("RESOURCE_GROUP_NAME"),
            reconcile_interval_seconds=get_int(
                "RECONCILE_INTERVAL", DEFAULT_RECONCILE_INTERVAL_SECONDS
            ),
            whatif_timeout_seconds=get_int("WHATIF_TIMEOUT", DEFAULT_WHATIF_TIMEOUT_SECONDS),
            deployment_timeout_seconds=get_int(
                "DEPLOYMENT_TIMEOUT", DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS
            ),
            dry_run=get_bool("DRY_RUN", False),
            # Security config - secretless is enforced at runtime in security.py
            security=SecurityConfig(
                max_resources_per_deployment=get_int("MAX_RESOURCES_PER_DEPLOYMENT", 100),
                enable_audit_logging=get_bool("ENABLE_AUDIT_LOGGING", True),
            ),
        )
