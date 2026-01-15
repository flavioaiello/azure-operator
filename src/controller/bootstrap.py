"""Bootstrap cascade module for provisioning operator identities.

This module implements the bootstrap cascade pattern where:
1. The bootstrap operator runs first with constrained UAA + MI Contributor
2. It provisions User-Assigned Managed Identities for all downstream operators
3. It assigns RBAC roles to each identity
4. Downstream operators wait for their identity before starting reconciliation

SECURITY CONSIDERATIONS:
- Bootstrap operator requires User Access Administrator (with conditions) + MI Contributor
- UAA condition restricts role assignment to specific least-privilege roles only
- Cannot escalate to Owner or higher-privilege roles
- All created identities use least-privilege RBAC
- Tokens remain ephemeral - only identity infrastructure is provisioned
- RBAC propagation delay is explicitly handled (Entra ID replication)

IMPLEMENTATION NOTE:
Uses ARM deployments for identity provisioning to minimize SDK dependencies.
The azure-mgmt-msi and azure-mgmt-authorization packages are optional.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentMode,
    DeploymentProperties,
    ResourceGroup,
)

from .config import Config
from .models import BootstrapSpec, OperatorIdentityConfig
from .security import get_managed_identity_credential

logger = logging.getLogger(__name__)

# Constants
MAX_IDENTITY_WAIT_SECONDS = 300  # 5 minutes max wait for identity
IDENTITY_POLL_INTERVAL_SECONDS = 10
RBAC_PROPAGATION_DEFAULT_SECONDS = 120
BOOTSTRAP_DEPLOYMENT_TIMEOUT_SECONDS = 600  # 10 minutes for identity + RBAC deployment

# Input validation patterns
VALID_SUBSCRIPTION_ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
VALID_GUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
MAX_RESOURCE_GROUP_NAME_LENGTH = 90


@dataclass
class IdentityProvisionResult:
    """Result of provisioning a single operator identity."""

    operator_name: str
    identity_resource_id: str | None = None
    principal_id: str | None = None
    client_id: str | None = None
    role_assignments_created: int = 0
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return self.error is None and self.identity_resource_id is not None


@dataclass
class BootstrapResult:
    """Result of the bootstrap cascade operation."""

    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    identities_provisioned: list[IdentityProvisionResult] = field(default_factory=list)
    rbac_propagation_waited: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        if self.error:
            return False
        return all(r.success for r in self.identities_provisioned)

    @property
    def duration_seconds(self) -> float:
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()


class BootstrapReconciler:
    """Reconciler for the bootstrap cascade operator.

    This reconciler provisions managed identities and RBAC assignments
    for all downstream operators defined in the BootstrapSpec.
    """

    def __init__(
        self,
        config: Config,
        spec: BootstrapSpec,
    ) -> None:
        """Initialize the bootstrap reconciler.

        Args:
            config: Operator configuration.
            spec: Bootstrap specification with operator definitions.
        """
        self._config = config
        self._spec = spec

        # SECURITY: Secretless architecture - bootstrap uses managed identity only
        # This enforces that no credential secrets are in the environment
        self._credential = get_managed_identity_credential()

        # Initialize resource client
        self._resource_client = ResourceManagementClient(
            credential=self._credential,
            subscription_id=config.subscription_id,
        )

    async def provision_identities(self) -> BootstrapResult:
        """Provision all operator identities defined in the spec.

        Uses ARM deployment for identity provisioning to minimize dependencies.

        Returns:
            BootstrapResult with details of all provisioning operations.
        """
        result = BootstrapResult()

        try:
            # Ensure identity resource group exists
            await self._ensure_resource_group(
                self._spec.identity_resource_group,
                self._spec.location or self._config.location,
            )

            # Provision each operator identity via ARM deployment
            for operator_config in self._spec.operators:
                identity_result = await self._provision_operator_identity(operator_config)
                result.identities_provisioned.append(identity_result)

            # Wait for RBAC propagation
            if self._spec.rbac_propagation_seconds > 0:
                logger.info(
                    f"Waiting {self._spec.rbac_propagation_seconds}s for RBAC propagation..."
                )
                await asyncio.sleep(self._spec.rbac_propagation_seconds)
                result.rbac_propagation_waited = True

        except HttpResponseError as e:
            # SECURITY: Log Azure API errors with status code for audit
            error_code = e.error.code if e.error else None
            logger.error(
                f"Bootstrap failed with Azure API error: {e}",
                extra={"status_code": e.status_code, "error_code": error_code},
            )
            result.error = f"Azure API error ({e.status_code}): {e.message}"
        except AzureError as e:
            # Catch other Azure SDK errors (auth, network, etc.)
            logger.error(f"Bootstrap failed with Azure error: {e}")
            result.error = f"Azure error: {e}"

        result.end_time = datetime.now(UTC)

        # Log summary
        successful = sum(1 for r in result.identities_provisioned if r.success)
        failed = len(result.identities_provisioned) - successful
        logger.info(
            f"Bootstrap complete: {successful} identities provisioned, {failed} failed, "
            f"duration={result.duration_seconds:.1f}s"
        )

        return result

    async def _ensure_resource_group(self, name: str, location: str) -> None:
        """Ensure resource group exists, create if not."""
        try:
            rg = ResourceGroup(
                location=location,
                tags={
                    **self._spec.tags,
                    "managedBy": "azure-operator-bootstrap",
                },
            )
            self._resource_client.resource_groups.create_or_update(
                resource_group_name=name,
                parameters=rg,
            )
            logger.info(f"Resource group '{name}' ensured in {location}")
        except HttpResponseError as e:
            logger.error(f"Failed to create resource group '{name}': {e}")
            raise

    async def _provision_operator_identity(
        self,
        operator_config: OperatorIdentityConfig,
    ) -> IdentityProvisionResult:
        """Provision a single operator's managed identity and RBAC via ARM.

        Uses inline ARM template to create:
        - User-Assigned Managed Identity
        - Role assignments for the identity

        Args:
            operator_config: Configuration for the operator identity.

        Returns:
            IdentityProvisionResult with provisioning details.
        """
        start_time = time.monotonic()
        result = IdentityProvisionResult(operator_name=operator_config.name)
        identity_name = f"uami-operator-{operator_config.name}"

        try:
            # Build ARM template for identity + RBAC
            template = self._build_identity_template(operator_config, identity_name)

            # Deploy via ARM
            deployment_name = f"bootstrap-{operator_config.name}-{int(time.time())}"
            deployment = Deployment(
                properties=DeploymentProperties(
                    mode=DeploymentMode.INCREMENTAL,
                    template=template,
                    parameters={},
                )
            )

            # SECURITY: Execute with timeout to prevent indefinite hangs
            poller = self._resource_client.deployments.begin_create_or_update(
                resource_group_name=self._spec.identity_resource_group,
                deployment_name=deployment_name,
                parameters=deployment,
            )

            # Wait for completion with timeout
            loop = asyncio.get_event_loop()
            deployment_result = await asyncio.wait_for(
                loop.run_in_executor(None, poller.result),
                timeout=BOOTSTRAP_DEPLOYMENT_TIMEOUT_SECONDS,
            )

            # Extract outputs
            if deployment_result.properties.outputs:
                outputs = deployment_result.properties.outputs
                result.identity_resource_id = outputs.get("identityResourceId", {}).get("value")
                result.principal_id = outputs.get("principalId", {}).get("value")
                result.client_id = outputs.get("clientId", {}).get("value")

            # Create RBAC role assignments for this identity
            if result.principal_id:
                await self._create_role_assignments(
                    operator_config, result.principal_id, identity_name
                )
                result.role_assignments_created = len(operator_config.role_assignments)

            logger.info(
                f"Created identity '{identity_name}' with principal_id={result.principal_id}"
            )

        except TimeoutError:
            logger.error(
                f"Timeout deploying identity for '{operator_config.name}' "
                f"after {BOOTSTRAP_DEPLOYMENT_TIMEOUT_SECONDS}s"
            )
            result.error = f"Deployment timeout after {BOOTSTRAP_DEPLOYMENT_TIMEOUT_SECONDS}s"

        except HttpResponseError as e:
            # SECURITY: Log Azure API errors with structured data for audit
            logger.error(
                f"Azure API error provisioning identity for '{operator_config.name}': {e}",
                extra={"status_code": e.status_code, "operator": operator_config.name},
            )
            result.error = f"Azure API error ({e.status_code}): {e.message}"

        except AzureError as e:
            # Catch other Azure SDK errors (auth failures, network issues)
            logger.error(
                f"Azure error provisioning identity for '{operator_config.name}': {e}",
                extra={"operator": operator_config.name},
            )
            result.error = f"Azure error: {e}"

        result.duration_seconds = time.monotonic() - start_time
        return result

    def _build_identity_template(
        self,
        operator_config: OperatorIdentityConfig,
        identity_name: str,
    ) -> dict[str, Any]:
        """Build ARM template for identity and RBAC provisioning.

        Args:
            operator_config: Operator identity configuration.
            identity_name: Name for the UAMI resource.

        Returns:
            ARM template as dict.
        """
        location = self._spec.location or self._config.location

        # Base template with identity resource
        template: dict[str, Any] = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                    "apiVersion": "2023-01-31",
                    "name": identity_name,
                    "location": location,
                    "tags": {
                        **self._spec.tags,
                        "operator": operator_config.name,
                        "managedBy": "azure-operator-bootstrap",
                    },
                }
            ],
            "outputs": {
                "identityResourceId": {
                    "type": "string",
                    "value": (
                        "[resourceId('Microsoft.ManagedIdentity/"
                        f"userAssignedIdentities', '{identity_name}')]"
                    ),
                },
                "principalId": {
                    "type": "string",
                    "value": (
                        "[reference(resourceId('Microsoft.ManagedIdentity/"
                        f"userAssignedIdentities', '{identity_name}')).principalId]"
                    ),
                },
                "clientId": {
                    "type": "string",
                    "value": (
                        "[reference(resourceId('Microsoft.ManagedIdentity/"
                        f"userAssignedIdentities', '{identity_name}')).clientId]"
                    ),
                },
            },
        }

        return template

    async def _create_role_assignments(
        self,
        operator_config: OperatorIdentityConfig,
        principal_id: str,
        identity_name: str,
    ) -> None:
        """Create RBAC role assignments for an operator identity.

        Uses ARM deployment at subscription scope to create role assignments.
        Each role assignment is deployed separately to handle different scopes.

        Args:
            operator_config: Operator identity configuration with role definitions.
            principal_id: The principal ID of the created UAMI.
            identity_name: Name of the identity (for logging).
        """
        import uuid

        for ra in operator_config.role_assignments:
            try:
                # Generate deterministic GUID for role assignment based on identity + role + scope
                # This ensures idempotency - same inputs = same assignment ID
                assignment_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_DNS, f"{principal_id}:{ra.role_definition_name}:{ra.scope}"
                    )
                )

                # Build role assignment ARM template
                template: dict[str, Any] = {
                    "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {},
                    "resources": [
                        {
                            "type": "Microsoft.Authorization/roleAssignments",
                            "apiVersion": "2022-04-01",
                            "name": assignment_id,
                            "properties": {
                                "roleDefinitionId": (
                                    "[subscriptionResourceId("
                                    "'Microsoft.Authorization/roleDefinitions', "
                                    f"'{self._get_role_definition_id(ra.role_definition_name)}')"
                                    "]"
                                ),
                                "principalId": principal_id,
                                "principalType": "ServicePrincipal",
                                "description": (
                                    ra.description
                                    or f"Managed by azure-operator bootstrap "
                                    f"for {operator_config.name}"
                                ),
                            },
                        }
                    ],
                }

                deployment_name = f"rbac-{operator_config.name}-{int(time.time())}"

                # Deploy at subscription scope
                deployment = Deployment(
                    location=self._spec.location or self._config.location,
                    properties=DeploymentProperties(
                        mode=DeploymentMode.INCREMENTAL,
                        template=template,
                        parameters={},
                    ),
                )

                poller = (
                    self._resource_client.deployments.begin_create_or_update_at_subscription_scope(
                        deployment_name=deployment_name,
                        parameters=deployment,
                    )
                )

                # Wait with timeout
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, poller.result),
                    timeout=BOOTSTRAP_DEPLOYMENT_TIMEOUT_SECONDS,
                )

                logger.info(
                    f"Created role assignment: {ra.role_definition_name} "
                    f"for '{identity_name}' at {ra.scope}"
                )

            except TimeoutError:
                logger.error(
                    f"Timeout creating role assignment {ra.role_definition_name} "
                    f"for '{identity_name}'"
                )
                raise
            except HttpResponseError as e:
                # Role assignment may already exist (409 Conflict) - that's OK
                if e.status_code == 409:
                    logger.info(
                        f"Role assignment {ra.role_definition_name} "
                        f"already exists for '{identity_name}'"
                    )
                else:
                    logger.error(f"Failed to create role assignment {ra.role_definition_name}: {e}")
                    raise

    def _get_role_definition_id(self, role_name: str) -> str:
        """Map built-in role names to their GUIDs.

        Azure built-in roles have well-known GUIDs that are the same across all tenants.

        Args:
            role_name: The display name of the role (e.g., "Contributor", "Reader").

        Returns:
            The role definition GUID.
        """
        # Well-known Azure built-in role GUIDs
        BUILTIN_ROLES: dict[str, str] = {
            "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
            "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
            "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
            "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
            "Network Contributor": "4d97b98b-1d4f-4787-a291-c67834d212e7",
            "Security Admin": "fb1c8493-542b-48eb-b624-b4c8fea62acd",
            "Security Reader": "39bc4728-0917-49c7-9d2c-d95423bc2eb4",
            "Log Analytics Contributor": "92aaf0da-9dab-42b6-94a3-d43ce8d16293",
            "Log Analytics Reader": "73c42c96-874c-492b-b04d-ab87d138a893",
            "Monitoring Contributor": "749f88d5-cbae-40b8-bcfc-e573ddc772fa",
            "Key Vault Administrator": "00482a5a-887f-4fb3-b363-3b7fe8e74483",
            "Key Vault Secrets User": "4633458b-17de-408a-b874-0445c86b69e6",
            "Private DNS Zone Contributor": "b12aa53e-6015-4669-85d0-8515ebb3ae7f",
            "Resource Policy Contributor": "36243c78-bf99-498c-9df9-86d9f8d28608",
            "Automation Contributor": "f353d9bd-d4a6-484e-a77a-8050b599b867",
            "Management Group Contributor": "5d58bcaf-24a5-4b20-bdb6-eed9f69fbe4c",
        }

        if role_name in BUILTIN_ROLES:
            return BUILTIN_ROLES[role_name]

        # If not a built-in role, validate it's a valid GUID format
        if not re.match(VALID_GUID_PATTERN, role_name.lower()):
            raise ValueError(
                f"Role '{role_name}' is not a recognized built-in role and is not a valid GUID. "
                f"Custom roles must be specified as GUIDs (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
            )

        logger.info(
            f"Role '{role_name}' not found in built-in roles, using as custom role GUID"
        )
        return role_name


async def wait_for_identity(
    subscription_id: str,
    resource_group: str,
    identity_name: str,
    timeout_seconds: int = MAX_IDENTITY_WAIT_SECONDS,
) -> str | None:
    """Wait for a managed identity to exist and be ready.

    This is used by downstream operators to wait for the bootstrap
    operator to provision their identity before starting reconciliation.

    Uses ARM API to check for identity existence to minimize dependencies.

    SECURITY: Uses system-assigned managed identity of the waiting container.
    The container must have Reader on the identity resource group.

    Args:
        subscription_id: Subscription containing the identity (must be valid GUID).
        resource_group: Resource group containing the identity.
        identity_name: Name of the User-Assigned Managed Identity.
        timeout_seconds: Maximum time to wait.

    Returns:
        The identity's client_id if found, None if timeout.

    Raises:
        ValueError: If subscription_id is not a valid GUID format.
    """

    # SECURITY: Validate subscription_id format at the boundary
    if not re.match(VALID_SUBSCRIPTION_ID_PATTERN, subscription_id.lower()):
        raise ValueError(
            f"Invalid subscription_id format: {subscription_id}. "
            "Must be a valid GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        )

    # Validate resource group name length
    if len(resource_group) > MAX_RESOURCE_GROUP_NAME_LENGTH:
        raise ValueError(
            f"Resource group name exceeds {MAX_RESOURCE_GROUP_NAME_LENGTH} "
            f"characters: {resource_group}"
        )

    # SECURITY: Secretless architecture - use managed identity for polling
    credential = get_managed_identity_credential()
    resource_client = ResourceManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    identity_resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identity_name}"
    )

    start_time = time.monotonic()

    while (time.monotonic() - start_time) < timeout_seconds:
        try:
            # Check if identity exists via generic ARM resource get
            identity = resource_client.resources.get_by_id(
                resource_id=identity_resource_id,
                api_version="2023-01-31",
            )

            if identity and identity.properties:
                client_id = identity.properties.get("clientId")
                if client_id:
                    logger.info(f"Identity '{identity_name}' found with client_id={client_id}")
                    return client_id

        except ResourceNotFoundError:
            logger.debug(f"Identity '{identity_name}' not yet available, waiting...")
        except AzureError as e:
            # Log Azure errors but continue polling - transient failures are expected
            logger.warning(
                f"Azure error checking identity '{identity_name}': {e}",
                extra={"identity_name": identity_name, "error_type": type(e).__name__},
            )

        await asyncio.sleep(IDENTITY_POLL_INTERVAL_SECONDS)

    logger.error(f"Timeout waiting for identity '{identity_name}' after {timeout_seconds}s")
    return None


def is_bootstrap_operator(domain: str) -> bool:
    """Check if the current operator is the bootstrap operator."""
    return domain == "bootstrap"
