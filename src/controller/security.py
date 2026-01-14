"""Security enforcement for secretless architecture.

This module enforces the secretless security model where:
- ALL operators use User-Assigned Managed Identities (UAMIs)
- NO service principal secrets are allowed
- NO credentials are stored in environment variables or files

SECURITY INVARIANTS:
1. AZURE_CLIENT_SECRET must never be present in the environment
2. ManagedIdentityCredential is the ONLY allowed credential type
3. All authentication flows through Azure AD / Entra ID

Why Secretless?
- Zero secrets to rotate, leak, or manage
- RBAC scoped to exactly what each operator needs
- Full audit trail via Azure AD / Entra ID
- Zero trust - identity verified on every Azure API call
- Token lifecycle managed by Azure, not by us
"""

from __future__ import annotations

import logging
import os

from azure.identity import ManagedIdentityCredential

logger = logging.getLogger(__name__)

# Environment variables that indicate credential leakage
FORBIDDEN_CREDENTIAL_ENV_VARS: tuple[str, ...] = (
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
)

# Error message for security violations
SECRETLESS_VIOLATION_MESSAGE = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                         SECURITY VIOLATION DETECTED                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This operator enforces a SECRETLESS architecture using Managed Identity.    ║
║                                                                               ║
║  Detected: {env_var}                                                          ║
║                                                                               ║
║  This environment variable indicates service principal or password-based     ║
║  authentication, which is NOT ALLOWED.                                        ║
║                                                                               ║
║  RESOLUTION:                                                                  ║
║  1. Remove all credential environment variables                              ║
║  2. Assign a User-Assigned Managed Identity (UAMI) to this container         ║
║  3. Grant the UAMI appropriate RBAC roles on target resources                ║
║                                                                               ║
║  See: https://learn.microsoft.com/azure/active-directory/managed-identities  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


class SecretlessViolationError(Exception):
    """Raised when secretless architecture is violated.

    This is a fatal security error that prevents operator startup.
    The operator MUST NOT proceed when credentials are detected.
    """

    pass


def enforce_secretless_architecture() -> None:
    """Enforce that no credential secrets are present in the environment.

    This MUST be called at operator startup before any Azure SDK usage.

    Raises:
        SecretlessViolationError: If any credential environment variables detected.
    """
    for env_var in FORBIDDEN_CREDENTIAL_ENV_VARS:
        if os.environ.get(env_var):
            error_message = SECRETLESS_VIOLATION_MESSAGE.format(env_var=env_var)
            logger.critical(
                "Secretless architecture violation",
                extra={
                    "security_event": "credential_detected",
                    "env_var": env_var,
                    "action": "startup_blocked",
                },
            )
            raise SecretlessViolationError(error_message)

    logger.info(
        "Secretless architecture verified",
        extra={
            "security_event": "secretless_verified",
            "credential_type": "ManagedIdentity",
        },
    )


def get_managed_identity_credential(
    client_id: str | None = None,
) -> ManagedIdentityCredential:
    """Get a ManagedIdentityCredential after verifying secretless architecture.

    This is the ONLY way to obtain credentials in this codebase.

    Args:
        client_id: Optional client ID for user-assigned managed identity.
                   If None, uses system-assigned managed identity.

    Returns:
        ManagedIdentityCredential configured for the specified identity.

    Raises:
        SecretlessViolationError: If credential environment variables detected.
    """
    # Always enforce secretless before returning credentials
    enforce_secretless_architecture()

    if client_id:
        logger.info(
            "Using user-assigned managed identity",
            extra={"client_id": client_id[:8] + "..." if len(client_id) > 8 else client_id},
        )
        return ManagedIdentityCredential(client_id=client_id)

    logger.info("Using system-assigned managed identity")
    return ManagedIdentityCredential()


def log_security_audit_event(
    event_type: str,
    operator_name: str,
    target_resource: str | None = None,
    action: str | None = None,
    result: str | None = None,
) -> None:
    """Log a security-relevant audit event.

    All security events are logged with structured data for SIEM ingestion.

    Args:
        event_type: Type of security event (auth, access, deployment, etc.)
        operator_name: Name of the operator generating the event.
        target_resource: Azure resource being accessed.
        action: Action being performed.
        result: Result of the action (success, failure, denied).
    """
    logger.info(
        f"Security audit: {event_type}",
        extra={
            "security_audit": True,
            "event_type": event_type,
            "operator": operator_name,
            "target_resource": target_resource,
            "action": action,
            "result": result,
        },
    )
