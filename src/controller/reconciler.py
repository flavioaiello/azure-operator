"""Core reconciliation loop using Azure SDK for Python.

This module implements the Kubernetes-style reconciliation pattern:
1. Load desired state from YAML spec
2. Fast-path check via Resource Graph (detect recent changes)
3. Precise diff using ARM WhatIf API (if changes detected)
4. Apply changes if drift is confirmed
5. Repeat on interval

ARCHITECTURE:
Resource Graph provides fast (~2s) queries for:
- Recent changes in scope (ResourceChanges table)
- Change attribution (who modified what)
- Orphan detection (resources not in template)

ARM WhatIf provides precise (~30s) template-to-state diff:
- Property-level change detection
- Deployment preview

Combined approach reduces WhatIf calls by ~90% while maintaining accuracy.

SECURITY: Timeouts are enforced on all Azure API calls to prevent indefinite hangs.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentMode,
    DeploymentProperties,
    DeploymentWhatIf,
    DeploymentWhatIfProperties,
    ScopedDeployment,
    ScopedDeploymentWhatIf,
    WhatIfChange,
    WhatIfOperationResult,
)

from .config import (
    MAX_DEPLOYMENT_NAME_LENGTH,
    MAX_DEPLOYMENT_RETRIES,
    MAX_WHATIF_CHANGES,
    RETRY_BACKOFF_BASE_SECONDS,
    Config,
    DeploymentScope,
    ReconciliationMode,
)
from .guardrails import (
    ConcurrencyViolation,
    GuardrailEnforcer,
    GuardrailsConfig,
    GuardrailViolation,
    KillSwitchActive,
    RateLimitViolation,
    ScopePauseViolation,
    ScopeViolation,
)
from .ignore_rules import IgnoreRulesConfig, IgnoreRulesEvaluator
from .provenance import (
    ChangeProvenanceSummary,
    get_provenance_logger,
)
from .resource_graph import GraphQueryResult, ResourceChange, ResourceGraphQuerier
from .security import get_managed_identity_credential
from .spec_loader import SpecLoadError, load_spec, load_template

logger = logging.getLogger(__name__)

# Deployment name prefix for tracking
DEPLOYMENT_NAME_PREFIX = "azure-operator"

# Circuit breaker constants
MAX_CONSECUTIVE_FAILURES = 5
CIRCUIT_BREAKER_RESET_SECONDS = 300  # 5 minutes


class ChangeType(str, Enum):
    """ARM WhatIf change types."""

    CREATE = "Create"
    DELETE = "Delete"
    DEPLOY = "Deploy"
    IGNORE = "Ignore"
    MODIFY = "Modify"
    NO_CHANGE = "NoChange"
    UNSUPPORTED = "Unsupported"


class _EarlyReturnSignal(Exception):
    """Internal signal for early returns that should still log provenance.

    This is used to break out of the try block while still executing
    the provenance logging code. Not a real error.
    """

    pass


@dataclass
class ReconcileResult:
    """Result of a single reconciliation cycle."""

    domain: str
    mode: ReconciliationMode = ReconciliationMode.OBSERVE
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    drift_found: bool = False
    changes_applied: int = 0
    changes_blocked: int = 0  # For PROTECT mode: drift detected but blocked
    error: Exception | None = None

    @property
    def duration_seconds(self) -> float:
        """Calculate duration in seconds."""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    @property
    def success(self) -> bool:
        """Check if reconciliation succeeded."""
        return self.error is None


class Reconciler:
    """Core reconciler implementing the control loop.

    The reconciler:
    1. Loads YAML spec from disk (synced by git-sync sidecar)
    2. Fast-path: Queries Resource Graph for recent changes
    3. If changes detected: Runs ARM WhatIf for precise diff
    4. Applies changes using ARM deployment

    HYBRID DRIFT DETECTION:
    - Resource Graph: Fast queries (~2s), change attribution, orphan detection
    - ARM WhatIf: Precise template-to-state diff, deployment preview

    Combined approach reduces WhatIf calls by ~90% when no external changes occurred.

    SECURITY: Managed identity is enforced when configured.
    Circuit breaker prevents runaway retries on persistent failures.
    """

    def __init__(self, config: Config) -> None:
        """Initialize reconciler with configuration.

        Args:
            config: Validated operator configuration.

        Raises:
            SpecLoadError: If template cannot be loaded.
            RuntimeError: If managed identity is required but service principal detected.
        """
        self._config = config
        self._template = load_template(config.templates_dir, config.domain)

        # SECURITY: Secretless architecture - always use managed identity
        # This call enforces that no credential secrets are in the environment
        self._credential = get_managed_identity_credential()

        self._client = ResourceManagementClient(
            credential=self._credential,
            subscription_id=config.subscription_id,
        )

        # Resource Graph client for fast-path drift detection
        self._graph_querier: ResourceGraphQuerier | None = None
        if config.enable_graph_check:
            self._graph_querier = ResourceGraphQuerier(
                credential=self._credential,
                config=config,
            )

        # SECURITY: Guardrails enforcer for blast radius control
        # Enforces kill switch, scope allowlists, and rate limits
        self._guardrails = GuardrailEnforcer(GuardrailsConfig.from_env())

        # Ignore rules for filtering WhatIf noise
        self._ignore_rules = IgnoreRulesEvaluator(IgnoreRulesConfig.from_env())

        self._shutdown_event = asyncio.Event()

        # Circuit breaker state
        self._consecutive_failures = 0
        self._circuit_open_until: datetime | None = None

    @property
    def config(self) -> Config:
        """Get the reconciler configuration."""
        return self._config

    async def run(self) -> None:
        """Run the reconciliation loop until shutdown.

        This is the main entry point for the operator. It runs
        reconciliation cycles at the configured interval until
        a shutdown signal is received.

        Implements circuit breaker pattern: after MAX_CONSECUTIVE_FAILURES,
        the circuit opens and reconciliation pauses for CIRCUIT_BREAKER_RESET_SECONDS.
        """
        logger.info(
            "Starting reconciler",
            extra={
                "domain": self._config.domain,
                "scope": self._config.scope.value,
                "mode": self._config.mode.value,
                "interval_seconds": self._config.reconcile_interval_seconds,
                "dry_run": self._config.dry_run,
            },
        )

        while not self._shutdown_event.is_set():
            # Circuit breaker check
            if self._circuit_open_until is not None:
                now = datetime.now(UTC)
                if now < self._circuit_open_until:
                    remaining = (self._circuit_open_until - now).total_seconds()
                    logger.warning(
                        "Circuit breaker open, skipping reconciliation",
                        extra={
                            "domain": self._config.domain,
                            "remaining_seconds": remaining,
                            "consecutive_failures": self._consecutive_failures,
                        },
                    )
                    # Wait for circuit breaker reset or shutdown
                    try:
                        await asyncio.wait_for(
                            self._shutdown_event.wait(),
                            timeout=min(remaining, self._config.reconcile_interval_seconds),
                        )
                    except TimeoutError:
                        pass
                    continue
                else:
                    # Circuit breaker reset
                    logger.info(
                        "Circuit breaker reset, resuming reconciliation",
                        extra={"domain": self._config.domain},
                    )
                    self._circuit_open_until = None
                    self._consecutive_failures = 0

            result = await self._reconcile_once()
            self._log_result(result)

            # Update circuit breaker state
            if result.error is not None:
                self._consecutive_failures += 1
                if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    self._circuit_open_until = datetime.now(UTC)
                    # Add backoff time
                    from datetime import timedelta

                    self._circuit_open_until += timedelta(seconds=CIRCUIT_BREAKER_RESET_SECONDS)
                    logger.error(
                        "Circuit breaker opened after consecutive failures",
                        extra={
                            "domain": self._config.domain,
                            "consecutive_failures": self._consecutive_failures,
                            "reset_seconds": CIRCUIT_BREAKER_RESET_SECONDS,
                        },
                    )
            else:
                # Reset on success
                self._consecutive_failures = 0

            # Wait for next cycle or shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._config.reconcile_interval_seconds,
                )
            except TimeoutError:
                # Normal timeout, continue to next cycle
                pass

        logger.info("Reconciler shutdown complete", extra={"domain": self._config.domain})

    def shutdown(self) -> None:
        """Signal the reconciler to stop."""
        logger.info("Shutdown requested", extra={"domain": self._config.domain})
        self._shutdown_event.set()

    def _check_scope_guardrails(self) -> None:
        """Check if deployment scope is allowed by guardrails.

        Validates the current deployment scope (management group, subscription,
        or resource group) against the configured allowlists and denylists.

        Raises:
            ScopeViolation: If the scope is denied or not in allowlist.
            ScopePauseViolation: If the scope or domain is paused.
        """
        # Import here to avoid circular import

        scope_type, scope_value = self._get_scope_for_guardrails()

        if scope_value:
            self._guardrails.check_scope(scope_type, scope_value)

        # Check if domain or scope is paused (less severe than kill switch)
        if scope_value:
            self._guardrails.check_pause(
                domain=self._config.domain,
                scope_type=scope_type,
                scope_value=scope_value,
            )

    def _get_scope_for_guardrails(self) -> tuple[str, str]:
        """Get scope type and value for guardrail checks.

        Returns:
            Tuple of (scope_type, scope_value)
        """
        scope_type = ""
        scope_value = ""

        match self._config.scope:
            case DeploymentScope.MANAGEMENT_GROUP:
                if self._config.management_group_id:
                    scope_type = "management_group"
                    scope_value = self._config.management_group_id
            case DeploymentScope.SUBSCRIPTION:
                scope_type = "subscription"
                scope_value = self._config.subscription_id
            case DeploymentScope.RESOURCE_GROUP:
                # Resource group scope uses subscription for guardrails
                scope_type = "subscription"
                scope_value = self._config.subscription_id

        return scope_type, scope_value

    async def _reconcile_once(self) -> ReconcileResult:
        """Execute a single reconciliation cycle.

        HYBRID APPROACH:
        1. Fast-path: Query Resource Graph for recent changes (~2s)
        2. If no changes AND not first run: Skip WhatIf (save rate limit)
        3. If changes OR first run: Run WhatIf for precise diff (~30s)
        4. Apply if drift confirmed

        Returns:
            ReconcileResult with details of the operation.
        """
        result = ReconcileResult(domain=self._config.domain, mode=self._config.mode)
        graph_result: GraphQueryResult | None = None

        # PROVENANCE: Initialize provenance record for audit trail
        provenance_logger = get_provenance_logger()
        provenance = provenance_logger.create_provenance(
            domain=self._config.domain,
            subscription_id=self._config.subscription_id,
            management_group_id=self._config.management_group_id,
            deployment_scope=self._config.scope.value,
            mode=self._config.mode.value,
        )
        change_summary = ChangeProvenanceSummary()

        try:
            # GUARDRAIL: Check kill switch before any operations
            self._guardrails.check_kill_switch()

            # GUARDRAIL: Check scope is allowed
            self._check_scope_guardrails()

            # Load and validate spec
            spec = load_spec(self._config.specs_dir, self._config.domain)
            params = spec.to_arm_parameters()

            # FAST PATH: Check Resource Graph for recent changes
            skip_whatif = False
            if self._graph_querier is not None:
                try:
                    graph_result = await self._graph_querier.check_for_changes()

                    if not graph_result.has_changes:
                        logger.info(
                            "No recent changes detected via Resource Graph, skipping WhatIf",
                            extra={
                                "domain": self._config.domain,
                                "query_time_seconds": graph_result.query_time_seconds,
                            },
                        )
                        skip_whatif = True
                    else:
                        # Log change attribution for audit
                        self._log_change_attribution(graph_result.recent_changes)

                except HttpResponseError as e:
                    # Graph query failed - fall back to WhatIf
                    logger.warning(
                        "Resource Graph query failed, falling back to WhatIf",
                        extra={"domain": self._config.domain, "error": str(e)},
                    )

            # If Graph check passed with no changes, skip expensive WhatIf
            if skip_whatif:
                result.drift_found = False
                # Early exit - provenance is logged after the try/except block
                result.end_time = datetime.now(UTC)
                # Don't return early - let the code flow to provenance logging
                raise _EarlyReturnSignal()

            # PRECISE CHECK: Detect drift using ARM WhatIf
            changes = await self._detect_drift(params)
            significant_changes = self._filter_significant_changes(changes, change_summary)

            if not significant_changes:
                logger.info("No drift detected", extra={"domain": self._config.domain})
                result.drift_found = False
                result.end_time = datetime.now(UTC)
                raise _EarlyReturnSignal()

            result.drift_found = True

            # SECURITY: Enforce max resources limit to prevent runaway deployments
            if len(significant_changes) > self._config.security.max_resources_per_deployment:
                error_msg = (
                    f"Deployment would modify {len(significant_changes)} resources, "
                    f"exceeding limit of {self._config.security.max_resources_per_deployment}. "
                    f"This may indicate a misconfiguration. Review changes manually."
                )
                logger.error(
                    "Max resources limit exceeded",
                    extra={
                        "domain": self._config.domain,
                        "change_count": len(significant_changes),
                        "limit": self._config.security.max_resources_per_deployment,
                    },
                )
                result.error = RuntimeError(error_msg)
                result.end_time = datetime.now(UTC)
                raise _EarlyReturnSignal()

            logger.info(
                "Drift detected",
                extra={
                    "domain": self._config.domain,
                    "mode": self._config.mode.value,
                    "change_count": len(significant_changes),
                },
            )

            for change in significant_changes:
                logger.debug(
                    "Change detail",
                    extra={
                        "change_type": change.change_type,
                        "resource_id": change.resource_id,
                    },
                )

            # RECONCILIATION MODE: Handle based on configured mode
            match self._config.mode:
                case ReconciliationMode.OBSERVE:
                    # Report only - never apply changes
                    logger.info(
                        "OBSERVE mode: drift reported but not remediated",
                        extra={
                            "domain": self._config.domain,
                            "change_count": len(significant_changes),
                        },
                    )
                    result.changes_applied = 0
                    result.end_time = datetime.now(UTC)
                    raise _EarlyReturnSignal()

                case ReconciliationMode.PROTECT:
                    # Block changes - drift is a violation
                    logger.warning(
                        "PROTECT mode: drift detected, changes blocked",
                        extra={
                            "domain": self._config.domain,
                            "change_count": len(significant_changes),
                        },
                    )
                    result.changes_blocked = len(significant_changes)
                    result.changes_applied = 0
                    # Report but don't error - PROTECT is intentional blocking
                    result.end_time = datetime.now(UTC)
                    raise _EarlyReturnSignal()

                case ReconciliationMode.ENFORCE:
                    # Auto-remediate drift
                    logger.info(
                        "ENFORCE mode: applying drift remediation",
                        extra={
                            "domain": self._config.domain,
                            "change_count": len(significant_changes),
                        },
                    )

            # Legacy dry_run support (deprecated, use OBSERVE mode)
            if self._config.dry_run:
                logger.info(
                    "Dry-run mode (deprecated), skipping apply",
                    extra={"domain": self._config.domain},
                )
                result.changes_applied = 0
                result.end_time = datetime.now(UTC)
                raise _EarlyReturnSignal()

            # GUARDRAIL: Check rate limits before apply
            self._guardrails.check_rate_limit(resource_changes=len(significant_changes))

            # CONCURRENCY: Acquire scope lock and check for active deployments
            scope_type, scope_value = self._get_scope_for_guardrails()
            if scope_value:
                await self._guardrails.acquire_scope_lock(scope_type, scope_value)
                # Check Azure for any in-progress external deployments
                await self._guardrails.check_active_deployments_azure(
                    client=self._client,
                    scope_type=scope_type,
                    scope_value=scope_value,
                    our_deployment_prefix=DEPLOYMENT_NAME_PREFIX,
                )

            try:
                # Apply changes with retry logic
                await self._apply_with_retry(params)

                # Record actual applied count
                result.changes_applied = len(significant_changes)
            finally:
                # CONCURRENCY: Always release scope lock
                if scope_value:
                    self._guardrails.release_scope_lock(scope_type, scope_value)

            # GUARDRAIL: Record changes for rate limiting
            self._guardrails.record_changes(resource_changes=len(significant_changes))

            logger.info(
                "Reconciliation complete",
                extra={
                    "domain": self._config.domain,
                    "changes": len(significant_changes),
                },
            )

        except _EarlyReturnSignal:
            # Normal control flow - not an error, just early exit
            pass
        except SpecLoadError as e:
            logger.error("Failed to load spec", extra={"error": str(e)})
            result.error = e
        except ConcurrencyViolation as e:
            # Concurrency violation - another deployment is in progress
            logger.warning(
                "Concurrency violation, deployment skipped",
                extra={"domain": self._config.domain, "reason": str(e)},
            )
            result.error = e
        except KillSwitchActive as e:
            # Kill switch is not an error - it's intentional blocking
            logger.warning(
                "Kill switch active, apply blocked",
                extra={"domain": self._config.domain},
            )
            result.error = e
        except ScopePauseViolation as e:
            # Pause is not an error - it's intentional per-scope blocking
            logger.warning(
                "Scope/domain paused, apply blocked",
                extra={"domain": self._config.domain, "pause_reason": str(e)},
            )
            result.error = e
        except ScopeViolation as e:
            logger.error("Scope guardrail violation", extra={"error": str(e)})
            result.error = e
        except RateLimitViolation as e:
            logger.warning("Rate limit exceeded", extra={"error": str(e)})
            result.error = e
        except GuardrailViolation as e:
            logger.error("Guardrail violation", extra={"error": str(e)})
            result.error = e
        except HttpResponseError as e:
            logger.error(
                "Azure API error",
                extra={"error": str(e), "status_code": e.status_code},
            )
            result.error = e
        except AzureError as e:
            logger.error("Azure error", extra={"error": str(e)})
            result.error = e
        except Exception as e:
            logger.exception("Unexpected error during reconciliation")
            result.error = e

        if result.end_time is None:
            result.end_time = datetime.now(UTC)

        # PROVENANCE: Complete and log the provenance record
        provenance.drift_detected = result.drift_found
        provenance.changes_applied = result.changes_applied
        provenance.changes_blocked = result.changes_blocked
        provenance.change_summary = change_summary
        provenance.duration_seconds = result.duration_seconds
        if result.error:
            provenance.error = str(result.error)
            provenance.error_type = type(result.error).__name__
        provenance_logger.log_provenance(provenance)

        return result

    async def _detect_drift(self, params: dict[str, Any]) -> list[WhatIfChange]:
        """Detect configuration drift using ARM WhatIf API.

        Args:
            params: ARM template parameters.

        Returns:
            List of detected changes.

        Raises:
            HttpResponseError: If the WhatIf API call fails.
        """
        deployment_name = f"{DEPLOYMENT_NAME_PREFIX}-{self._config.domain}"

        whatif_result: WhatIfOperationResult

        match self._config.scope:
            case DeploymentScope.SUBSCRIPTION:
                whatif_result = await self._whatif_subscription(deployment_name, params)

            case DeploymentScope.MANAGEMENT_GROUP:
                whatif_result = await self._whatif_management_group(deployment_name, params)

            case DeploymentScope.RESOURCE_GROUP:
                whatif_result = await self._whatif_resource_group(deployment_name, params)

            case _:
                raise ValueError(f"Unsupported scope: {self._config.scope}")

        if whatif_result.properties is None or whatif_result.properties.changes is None:
            return []

        changes = whatif_result.properties.changes

        # SECURITY: Bound the number of changes to prevent OOM from unexpectedly large responses
        if len(changes) > MAX_WHATIF_CHANGES:
            raise RuntimeError(
                f"WhatIf returned {len(changes)} changes, exceeding limit of {MAX_WHATIF_CHANGES}. "
                f"This may indicate a misconfiguration or overly broad deployment scope."
            )

        return changes

    async def _whatif_subscription(
        self, deployment_name: str, params: dict[str, Any]
    ) -> WhatIfOperationResult:
        """Execute WhatIf at subscription scope with timeout."""
        whatif = DeploymentWhatIf(
            location=self._config.location,
            properties=DeploymentWhatIfProperties(
                template=self._template,
                parameters=params,
                mode=DeploymentMode.INCREMENTAL,
            ),
        )

        return await self._execute_with_timeout(
            lambda: self._client.deployments.begin_what_if_at_subscription_scope(
                deployment_name, whatif
            ),
            timeout_seconds=self._config.whatif_timeout_seconds,
            operation_name="WhatIf (subscription)",
        )

    async def _whatif_management_group(
        self, deployment_name: str, params: dict[str, Any]
    ) -> WhatIfOperationResult:
        """Execute WhatIf at management group scope with timeout."""
        whatif = ScopedDeploymentWhatIf(
            location=self._config.location,
            properties=DeploymentWhatIfProperties(
                template=self._template,
                parameters=params,
                mode=DeploymentMode.INCREMENTAL,
            ),
        )

        return await self._execute_with_timeout(
            lambda: self._client.deployments.begin_what_if_at_management_group_scope(
                # SAFETY: management_group_id is validated non-None in Config.__post_init__()
                # when scope == DeploymentScope.MANAGEMENT_GROUP (L189-190 in config.py)
                self._config.management_group_id,
                deployment_name,
                whatif,
            ),
            timeout_seconds=self._config.whatif_timeout_seconds,
            operation_name="WhatIf (management group)",
        )

    async def _whatif_resource_group(
        self, deployment_name: str, params: dict[str, Any]
    ) -> WhatIfOperationResult:
        """Execute WhatIf at resource group scope with timeout."""
        whatif = DeploymentWhatIf(
            properties=DeploymentWhatIfProperties(
                template=self._template,
                parameters=params,
                mode=DeploymentMode.INCREMENTAL,
            ),
        )

        return await self._execute_with_timeout(
            lambda: self._client.deployments.begin_what_if(
                # SAFETY: resource_group_name is validated non-None in Config.__post_init__()
                # when scope == DeploymentScope.RESOURCE_GROUP (L192-193 in config.py)
                self._config.resource_group_name,
                deployment_name,
                whatif,
            ),
            timeout_seconds=self._config.whatif_timeout_seconds,
            operation_name="WhatIf (resource group)",
        )

    async def _execute_with_timeout(
        self,
        begin_operation: Any,
        timeout_seconds: int,
        operation_name: str,
    ) -> Any:
        """Execute an Azure SDK poller operation with timeout.

        SECURITY: Enforces timeout to prevent indefinite hangs on Azure API calls.

        Args:
            begin_operation: Callable that returns an LROPoller.
            timeout_seconds: Maximum time to wait for operation completion.
            operation_name: Human-readable name for logging.

        Returns:
            The result of the poller operation.

        Raises:
            asyncio.TimeoutError: If operation exceeds timeout.
            HttpResponseError: If Azure API returns an error.
        """
        loop = asyncio.get_event_loop()

        # Start the long-running operation
        poller = await loop.run_in_executor(None, begin_operation)

        # Wait for result with timeout
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, poller.result),
                timeout=timeout_seconds,
            )
            return result
        except TimeoutError:
            logger.error(
                f"{operation_name} timed out",
                extra={
                    "domain": self._config.domain,
                    "timeout_seconds": timeout_seconds,
                },
            )
            raise

    async def _apply_with_retry(self, params: dict[str, Any]) -> None:
        """Apply deployment with exponential backoff retry.

        Args:
            params: ARM template parameters.

        Raises:
            HttpResponseError: If all retries fail.
        """
        last_error: Exception | None = None

        for attempt in range(1, MAX_DEPLOYMENT_RETRIES + 1):
            try:
                await self._apply(params)
                return
            except HttpResponseError as e:
                last_error = e

                if attempt < MAX_DEPLOYMENT_RETRIES:
                    # Exponential backoff with jitter
                    backoff = RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                    jitter = random.uniform(0, backoff * 0.2)
                    wait_time = backoff + jitter

                    logger.warning(
                        "Deployment failed, retrying",
                        extra={
                            "attempt": attempt,
                            "max_attempts": MAX_DEPLOYMENT_RETRIES,
                            "wait_seconds": wait_time,
                            "error": str(e),
                        },
                    )

                    await asyncio.sleep(wait_time)

        # SAFETY: Loop runs at least once (MAX_DEPLOYMENT_RETRIES >= 1),
        # so last_error is always set to an HttpResponseError before reaching here
        assert last_error is not None, "Retry loop completed without setting last_error"
        raise last_error

    async def _apply(self, params: dict[str, Any]) -> None:
        """Execute the deployment.

        Args:
            params: ARM template parameters.

        Raises:
            HttpResponseError: If the deployment fails.
            asyncio.TimeoutError: If deployment exceeds timeout.
        """
        # SECURITY: Use timestamp + random suffix to prevent deployment name collisions
        timestamp = int(time.time())
        random_suffix = random.randint(1000, 9999)
        # Truncate domain to ensure deployment name fits within ARM limit
        # Format: {prefix}-{domain}-{timestamp}-{suffix}
        # Lengths: prefix + 1 + domain + 1 + 10 + 1 + 4 = prefix + domain + 17
        reserved_len = len(DEPLOYMENT_NAME_PREFIX) + 17
        max_domain_len = MAX_DEPLOYMENT_NAME_LENGTH - reserved_len
        truncated_domain = self._config.domain[:max_domain_len]
        deployment_name = (
            f"{DEPLOYMENT_NAME_PREFIX}-{truncated_domain}-{timestamp}-{random_suffix}"
        )

        # SECURITY: Validate deployment name length against ARM limit
        if len(deployment_name) > MAX_DEPLOYMENT_NAME_LENGTH:
            raise RuntimeError(
                f"Deployment name '{deployment_name}' exceeds maximum length of "
                f"{MAX_DEPLOYMENT_NAME_LENGTH} characters"
            )

        match self._config.scope:
            case DeploymentScope.SUBSCRIPTION:
                await self._deploy_subscription(deployment_name, params)

            case DeploymentScope.MANAGEMENT_GROUP:
                await self._deploy_management_group(deployment_name, params)

            case DeploymentScope.RESOURCE_GROUP:
                await self._deploy_resource_group(deployment_name, params)

            case _:
                raise ValueError(f"Unsupported scope: {self._config.scope}")

    async def _deploy_subscription(self, deployment_name: str, params: dict[str, Any]) -> None:
        """Execute deployment at subscription scope with timeout."""
        deployment = Deployment(
            location=self._config.location,
            properties=DeploymentProperties(
                template=self._template,
                parameters=params,
                mode=DeploymentMode.INCREMENTAL,
            ),
        )

        await self._execute_with_timeout(
            lambda: self._client.deployments.begin_create_or_update_at_subscription_scope(
                deployment_name, deployment
            ),
            timeout_seconds=self._config.deployment_timeout_seconds,
            operation_name="Deployment (subscription)",
        )

    async def _deploy_management_group(self, deployment_name: str, params: dict[str, Any]) -> None:
        """Execute deployment at management group scope with timeout."""
        deployment = ScopedDeployment(
            location=self._config.location,
            properties=DeploymentProperties(
                template=self._template,
                parameters=params,
                mode=DeploymentMode.INCREMENTAL,
            ),
        )

        await self._execute_with_timeout(
            lambda: self._client.deployments.begin_create_or_update_at_management_group_scope(
                # SAFETY: management_group_id is validated non-None in Config.__post_init__()
                # when scope == DeploymentScope.MANAGEMENT_GROUP (L189-190 in config.py)
                self._config.management_group_id,
                deployment_name,
                deployment,
            ),
            timeout_seconds=self._config.deployment_timeout_seconds,
            operation_name="Deployment (management group)",
        )

    async def _deploy_resource_group(self, deployment_name: str, params: dict[str, Any]) -> None:
        """Execute deployment at resource group scope with timeout."""
        deployment = Deployment(
            properties=DeploymentProperties(
                template=self._template,
                parameters=params,
                mode=DeploymentMode.INCREMENTAL,
            ),
        )

        await self._execute_with_timeout(
            lambda: self._client.deployments.begin_create_or_update(
                # SAFETY: resource_group_name is validated non-None in Config.__post_init__()
                # when scope == DeploymentScope.RESOURCE_GROUP (L192-193 in config.py)
                self._config.resource_group_name,
                deployment_name,
                deployment,
            ),
            timeout_seconds=self._config.deployment_timeout_seconds,
            operation_name="Deployment (resource group)",
        )

    def _filter_significant_changes(
        self, changes: list[WhatIfChange], change_summary: ChangeProvenanceSummary | None = None
    ) -> list[WhatIfChange]:
        """Filter out non-significant changes.

        Applies two levels of filtering:
        1. Remove ARM WhatIf noise (NoChange, Ignore types)
        2. Apply ignore rules for known system-managed properties

        Optionally updates a ChangeProvenanceSummary with counts by type.

        Args:
            changes: Raw WhatIf changes.
            change_summary: Optional summary to update with change counts.

        Returns:
            List of changes that require action.
        """
        # First pass: remove ARM-level noise and count by type
        preliminary = []
        for change in changes:
            change_type = change.change_type

            # Update provenance summary with counts
            if change_summary is not None:
                if change_type == ChangeType.CREATE.value:
                    change_summary.create_count += 1
                elif change_type == ChangeType.MODIFY.value:
                    change_summary.modify_count += 1
                elif change_type == ChangeType.DELETE.value:
                    change_summary.delete_count += 1
                elif change_type == ChangeType.NO_CHANGE.value:
                    change_summary.no_change_count += 1

            if change_type not in (
                ChangeType.NO_CHANGE.value,
                ChangeType.IGNORE.value,
            ):
                preliminary.append(change)

        # Second pass: apply ignore rules for property-level filtering
        filtered, ignored_count = self._ignore_rules.filter_whatif_changes(preliminary)

        # Update ignored count in provenance summary
        if change_summary is not None:
            change_summary.ignored_count = ignored_count

        if ignored_count > 0:
            logger.info(
                "Ignore rules filtered changes",
                extra={
                    "domain": self._config.domain,
                    "original_count": len(preliminary),
                    "filtered_count": len(filtered),
                    "ignored_properties": ignored_count,
                },
            )

        return filtered

    def _log_result(self, result: ReconcileResult) -> None:
        """Log reconciliation result with structured data."""
        extra = {
            "domain": result.domain,
            "mode": result.mode.value,
            "duration_seconds": result.duration_seconds,
            "drift_found": result.drift_found,
            "changes_applied": result.changes_applied,
            "changes_blocked": result.changes_blocked,
        }

        if result.error is not None:
            extra["error"] = str(result.error)
            logger.error("Reconciliation failed", extra=extra)
        elif result.changes_blocked > 0:
            logger.warning("Reconciliation: drift blocked (PROTECT mode)", extra=extra)
        else:
            logger.info("Reconciliation result", extra=extra)

    def _log_change_attribution(self, changes: list[ResourceChange]) -> None:
        """Log change attribution for audit purposes.

        When Resource Graph detects external changes, log who made them
        for security audit and compliance tracking.

        Args:
            changes: List of changes detected by Resource Graph.
        """
        for change in changes:
            logger.warning(
                "External change detected",
                extra={
                    "domain": self._config.domain,
                    "resource_id": change.resource_id,
                    "change_type": change.change_type.value,
                    "changed_by": change.changed_by or "unknown",
                    "client_type": change.client_type or "unknown",
                    "timestamp": change.timestamp.isoformat(),
                },
            )
