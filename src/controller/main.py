"""Main entry point for the Azure Landing Zone Operator.

SECRETLESS ARCHITECTURE:
This operator enforces a secretless security model where:
- ALL authentication uses User-Assigned Managed Identities (UAMIs)
- NO service principal secrets or passwords are allowed
- Credentials are NEVER stored - Entra ID tokens are ephemeral

Supports bootstrap cascade pattern:
- Bootstrap operator: provisions UAMIs for downstream operators
- Downstream operators: wait for their UAMI before starting reconciliation
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import UTC

from .bootstrap import (
    BootstrapReconciler,
    is_bootstrap_operator,
    wait_for_identity,
)
from .config import Config, ConfigurationError
from .models import BootstrapSpec
from .reconciler import Reconciler
from .security import SecretlessViolationError
from .spec_loader import SpecLoadError, load_spec


def setup_logging() -> None:
    """Configure structured logging with JSON output for production."""
    import json
    from datetime import datetime

    class JsonFormatter(logging.Formatter):
        """Format logs as JSON for structured logging."""

        def format(self, record: logging.LogRecord) -> str:
            log_data = {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "level": record.levelname,
                "message": record.getMessage(),
                "logger": record.name,
            }

            # Add extra fields from the record
            if hasattr(record, "__dict__"):
                for key, value in record.__dict__.items():
                    if key not in (
                        "name",
                        "msg",
                        "args",
                        "created",
                        "filename",
                        "funcName",
                        "levelname",
                        "levelno",
                        "lineno",
                        "module",
                        "msecs",
                        "pathname",
                        "process",
                        "processName",
                        "relativeCreated",
                        "stack_info",
                        "exc_info",
                        "exc_text",
                        "thread",
                        "threadName",
                        "taskName",
                        "message",
                    ):
                        log_data[key] = value

            # Add exception info if present
            if record.exc_info:
                log_data["exception"] = self.formatException(record.exc_info)

            return json.dumps(log_data)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    # Reduce noise from Azure SDK
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


async def main() -> int:
    """Run the operator.

    Supports two modes:
    1. Bootstrap operator: provisions identities for all downstream operators
    2. Standard operator: waits for identity (if cascade enabled), then reconciles

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    setup_logging()
    logger = logging.getLogger(__name__)

    try:
        config = Config.from_env()
    except ConfigurationError as e:
        logger.error("Configuration error", extra={"error": str(e)})
        return 1

    logger.info(
        "Starting Azure Landing Zone Operator",
        extra={
            "domain": config.domain,
            "subscription_id": config.subscription_id,
            "location": config.location,
            "scope": config.scope.value,
        },
    )

    # Check if this is the bootstrap operator
    if is_bootstrap_operator(config.domain):
        return await run_bootstrap_operator(config, logger)

    # Check if identity cascade is enabled (wait for identity from bootstrap)
    identity_resource_group = os.environ.get("BOOTSTRAP_IDENTITY_RESOURCE_GROUP")
    if identity_resource_group:
        return await run_cascaded_operator(config, logger, identity_resource_group)

    # Standard mode: operator has pre-provisioned identity
    return await run_standard_operator(config, logger)


async def run_bootstrap_operator(config: Config, logger: logging.Logger) -> int:
    """Run the bootstrap cascade operator.

    This operator provisions identities for all downstream operators.
    """
    logger.info("Running as BOOTSTRAP operator - provisioning downstream identities")

    try:
        # Load bootstrap spec
        spec = load_spec(config.specs_dir, config.domain)
        if not isinstance(spec, BootstrapSpec):
            logger.error("Bootstrap operator requires BootstrapSpec")
            return 1

        bootstrap_reconciler = BootstrapReconciler(config, spec)
        result = await bootstrap_reconciler.provision_identities()

        if not result.success:
            logger.error(
                "Bootstrap failed",
                extra={
                    "error": result.error,
                    "identities_failed": [
                        r.operator_name for r in result.identities_provisioned if not r.success
                    ],
                },
            )
            return 1

        logger.info(
            "Bootstrap completed successfully",
            extra={
                "identities_created": len(result.identities_provisioned),
                "duration_seconds": result.duration_seconds,
            },
        )

        # Bootstrap is a one-shot operation, exit after completion
        # Downstream operators will start when their identities are ready
        return 0

    except SpecLoadError as e:
        # Spec loading/validation failed - user configuration error
        logger.error(
            "Bootstrap spec loading failed",
            extra={"error": str(e), "specs_dir": str(config.specs_dir)},
        )
        return 1

    except SecretlessViolationError as e:
        # SECURITY: Credential detected in environment - fatal security error
        logger.critical(
            "Security violation: credentials detected in environment",
            extra={"error": str(e)},
        )
        return 2

    except Exception as e:
        # Unexpected error - log with full traceback for debugging
        logger.exception("Bootstrap operator failed unexpectedly", extra={"error": str(e)})
        return 1


async def run_cascaded_operator(
    config: Config,
    logger: logging.Logger,
    identity_resource_group: str,
) -> int:
    """Run an operator that waits for its identity from the bootstrap cascade.

    Args:
        config: Operator configuration.
        logger: Logger instance.
        identity_resource_group: Resource group where identities are created.
    """
    identity_name = f"uami-operator-{config.domain}"

    logger.info(
        "Waiting for identity from bootstrap cascade",
        extra={
            "identity_name": identity_name,
            "resource_group": identity_resource_group,
        },
    )

    # Wait for identity to be provisioned by bootstrap operator
    client_id = await wait_for_identity(
        subscription_id=config.subscription_id,
        resource_group=identity_resource_group,
        identity_name=identity_name,
    )

    if not client_id:
        logger.error(f"Timeout waiting for identity '{identity_name}' - bootstrap may have failed")
        return 1

    logger.info(
        "Identity available, proceeding with reconciliation",
        extra={"client_id": client_id},
    )

    # Now run standard operator with the provisioned identity
    return await run_standard_operator(config, logger)


async def run_standard_operator(config: Config, logger: logging.Logger) -> int:
    """Run a standard operator with pre-provisioned identity."""
    reconciler: Reconciler | None = None

    try:
        reconciler = Reconciler(config)
    except SpecLoadError as e:
        # Template loading failed - configuration error
        logger.error(
            "Failed to load template",
            extra={"error": str(e), "domain": config.domain},
        )
        return 1
    except SecretlessViolationError as e:
        # SECURITY: Credential detected - fatal security error
        logger.critical(
            "Security violation: credentials detected in environment",
            extra={"error": str(e)},
        )
        return 2
    except Exception as e:
        # Unexpected initialization error
        logger.error(
            "Failed to initialize reconciler",
            extra={"error": str(e), "error_type": type(e).__name__},
        )
        return 1

    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()

    def signal_handler(sig: signal.Signals) -> None:
        logger.info("Received signal", extra={"signal": sig.name})
        if reconciler:
            reconciler.shutdown()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))

    try:
        await reconciler.run()
    except Exception as e:
        logger.exception("Unhandled exception", extra={"error": str(e)})
        return 1

    logger.info("Operator stopped")
    return 0


def run() -> None:
    """Entry point for the operator CLI."""
    sys.exit(asyncio.run(main()))


if __name__ == "__main__":
    run()
