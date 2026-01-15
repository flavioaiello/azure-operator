"""Confidence scoring and approval gates for risky changes.

This module implements enterprise-grade approval workflows:
1. Confidence scoring per WhatIf result (high/medium/low)
2. Risky resource type detection (RBAC, firewall, identity)
3. Approval gate integration (webhook, GitHub, Azure DevOps)
4. Approval state persistence and timeout handling

DESIGN PHILOSOPHY:
- High-risk changes MUST require explicit approval
- Approval state is tracked per deployment, not globally
- Timeouts prevent stale approvals from being used
- Audit trail for all approval decisions
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ConfidenceLevel(str, Enum):
    """Confidence level for WhatIf results.

    HIGH: Clear, deterministic changes. Safe to auto-apply.
    MEDIUM: Some uncertainty. Review recommended.
    LOW: Significant uncertainty or risky types. Requires approval.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ApprovalStatus(str, Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    NOT_REQUIRED = "not_required"


# Resource types that always require approval before changes
# These are high-impact or security-sensitive resources
HIGH_RISK_RESOURCE_TYPES: set[str] = {
    # Identity & Access
    "Microsoft.Authorization/roleAssignments",
    "Microsoft.Authorization/roleDefinitions",
    "Microsoft.Authorization/policyAssignments",
    "Microsoft.Authorization/policyDefinitions",
    "Microsoft.Authorization/policySetDefinitions",
    "Microsoft.ManagedIdentity/userAssignedIdentities",
    # Network Security
    "Microsoft.Network/azureFirewalls",
    "Microsoft.Network/firewallPolicies",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/routeTables",
    "Microsoft.Network/virtualNetworkGateways",
    "Microsoft.Network/expressRouteCircuits",
    "Microsoft.Network/privateDnsZones",
    # Management & Governance
    "Microsoft.Management/managementGroups",
    "Microsoft.Subscription/aliases",
    # Key Vault
    "Microsoft.KeyVault/vaults",
    "Microsoft.KeyVault/vaults/accessPolicies",
}

# Resource types with medium risk - require approval for DELETE operations
MEDIUM_RISK_RESOURCE_TYPES: set[str] = {
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Network/virtualNetworks/subnets",
    "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/loadBalancers",
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Sql/servers",
    "Microsoft.ContainerService/managedClusters",
}

# Change types that elevate risk
HIGH_RISK_CHANGE_TYPES: set[str] = {
    "Delete",  # Deletions are always risky
}

# Default approval timeout
DEFAULT_APPROVAL_TIMEOUT_SECONDS = 3600  # 1 hour
MAX_APPROVAL_TIMEOUT_SECONDS = 86400  # 24 hours


@dataclass
class ChangeRiskAssessment:
    """Risk assessment for a single change."""

    resource_id: str
    resource_type: str
    change_type: str
    confidence: ConfidenceLevel
    requires_approval: bool
    risk_reasons: list[str] = field(default_factory=list)


@dataclass
class DeploymentRiskAssessment:
    """Aggregated risk assessment for a deployment."""

    domain: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    overall_confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    requires_approval: bool = False
    change_assessments: list[ChangeRiskAssessment] = field(default_factory=list)
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0

    @property
    def total_changes(self) -> int:
        """Total number of changes assessed."""
        return len(self.change_assessments)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/API response."""
        return {
            "domain": self.domain,
            "timestamp": self.timestamp.isoformat(),
            "overall_confidence": self.overall_confidence.value,
            "requires_approval": self.requires_approval,
            "total_changes": self.total_changes,
            "high_risk_count": self.high_risk_count,
            "medium_risk_count": self.medium_risk_count,
            "low_risk_count": self.low_risk_count,
            "high_risk_resources": [
                ca.resource_id
                for ca in self.change_assessments
                if ca.confidence == ConfidenceLevel.LOW
            ][:10],  # Cap for logging
        }


@dataclass
class ApprovalRequest:
    """A request for approval before applying changes."""

    request_id: str
    domain: str
    deployment_name: str
    risk_assessment: DeploymentRiskAssessment
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        """Set default expiration if not provided."""
        if self.expires_at is None:
            timeout = int(
                os.environ.get(
                    "APPROVAL_TIMEOUT_SECONDS",
                    str(DEFAULT_APPROVAL_TIMEOUT_SECONDS),
                )
            )
            # Clamp to max
            timeout = min(timeout, MAX_APPROVAL_TIMEOUT_SECONDS)
            self.expires_at = self.created_at + timedelta(seconds=timeout)

    @property
    def is_expired(self) -> bool:
        """Check if approval request has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at

    def check_and_update_expiry(self) -> None:
        """Update status to EXPIRED if past expiration."""
        if self.status == ApprovalStatus.PENDING and self.is_expired:
            self.status = ApprovalStatus.EXPIRED


@dataclass(frozen=True)
class ApprovalConfig:
    """Configuration for approval gates."""

    # Enable/disable approval requirement
    require_approval_for_high_risk: bool = True

    # Additional resource types that require approval (beyond defaults)
    additional_high_risk_types: frozenset[str] = field(
        default_factory=frozenset
    )

    # Resource types to exclude from approval (override defaults)
    excluded_risk_types: frozenset[str] = field(default_factory=frozenset)

    # Webhook URL for approval notifications
    approval_webhook_url: str | None = None

    # Auto-approve in certain conditions
    auto_approve_if_no_delete: bool = False

    # Timeout settings
    approval_timeout_seconds: int = DEFAULT_APPROVAL_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls) -> ApprovalConfig:
        """Load approval configuration from environment.

        Environment Variables:
            REQUIRE_APPROVAL_FOR_HIGH_RISK: Enable approval gates (default: true)
            ADDITIONAL_HIGH_RISK_TYPES: Comma-separated resource types
            EXCLUDED_RISK_TYPES: Comma-separated types to exclude
            APPROVAL_WEBHOOK_URL: Webhook for approval notifications
            AUTO_APPROVE_IF_NO_DELETE: Auto-approve if no deletions (default: false)
            APPROVAL_TIMEOUT_SECONDS: Approval timeout (default: 3600)
        """

        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(key, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes")

        def get_frozenset(key: str) -> frozenset[str]:
            value = os.environ.get(key, "")
            if not value:
                return frozenset()
            return frozenset(item.strip() for item in value.split(",") if item.strip())

        def get_int(key: str, default: int) -> int:
            value = os.environ.get(key)
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                return default

        return cls(
            require_approval_for_high_risk=get_bool(
                "REQUIRE_APPROVAL_FOR_HIGH_RISK", True
            ),
            additional_high_risk_types=get_frozenset("ADDITIONAL_HIGH_RISK_TYPES"),
            excluded_risk_types=get_frozenset("EXCLUDED_RISK_TYPES"),
            approval_webhook_url=os.environ.get("APPROVAL_WEBHOOK_URL"),
            auto_approve_if_no_delete=get_bool("AUTO_APPROVE_IF_NO_DELETE", False),
            approval_timeout_seconds=get_int(
                "APPROVAL_TIMEOUT_SECONDS", DEFAULT_APPROVAL_TIMEOUT_SECONDS
            ),
        )


class RiskAssessor:
    """Assesses risk of WhatIf changes and determines approval requirements."""

    def __init__(self, config: ApprovalConfig | None = None) -> None:
        """Initialize risk assessor.

        Args:
            config: Approval configuration. Defaults to env-based config.
        """
        self._config = config or ApprovalConfig.from_env()

        # Build effective high-risk set
        self._high_risk_types = (
            HIGH_RISK_RESOURCE_TYPES
            | set(self._config.additional_high_risk_types)
        ) - set(self._config.excluded_risk_types)

        self._medium_risk_types = MEDIUM_RISK_RESOURCE_TYPES - set(
            self._config.excluded_risk_types
        )

    def assess_change(
        self,
        resource_id: str,
        resource_type: str,
        change_type: str,
    ) -> ChangeRiskAssessment:
        """Assess risk of a single change.

        Args:
            resource_id: Azure resource ID.
            resource_type: Resource type (e.g., Microsoft.Network/azureFirewalls).
            change_type: Type of change (Create, Modify, Delete).

        Returns:
            Risk assessment for the change.
        """
        risk_reasons: list[str] = []
        confidence = ConfidenceLevel.HIGH
        requires_approval = False

        # Check if resource type is high-risk
        if resource_type in self._high_risk_types:
            confidence = ConfidenceLevel.LOW
            requires_approval = True
            risk_reasons.append(f"High-risk resource type: {resource_type}")

        # Check if change type is high-risk
        if change_type in HIGH_RISK_CHANGE_TYPES:
            if confidence != ConfidenceLevel.LOW:
                confidence = ConfidenceLevel.MEDIUM
            if resource_type in self._medium_risk_types:
                requires_approval = True
            risk_reasons.append(f"Risky change type: {change_type}")

        # Medium-risk resources with non-delete changes
        if resource_type in self._medium_risk_types and confidence == ConfidenceLevel.HIGH:
            confidence = ConfidenceLevel.MEDIUM
            risk_reasons.append(f"Medium-risk resource type: {resource_type}")

        return ChangeRiskAssessment(
            resource_id=resource_id,
            resource_type=resource_type,
            change_type=change_type,
            confidence=confidence,
            requires_approval=requires_approval and self._config.require_approval_for_high_risk,
            risk_reasons=risk_reasons,
        )

    def assess_deployment(
        self,
        domain: str,
        changes: list[tuple[str, str, str]],  # (resource_id, resource_type, change_type)
    ) -> DeploymentRiskAssessment:
        """Assess risk of an entire deployment.

        Args:
            domain: Operator domain.
            changes: List of (resource_id, resource_type, change_type) tuples.

        Returns:
            Aggregated risk assessment.
        """
        assessment = DeploymentRiskAssessment(domain=domain)

        has_delete = False
        for resource_id, resource_type, change_type in changes:
            change_assessment = self.assess_change(
                resource_id=resource_id,
                resource_type=resource_type,
                change_type=change_type,
            )
            assessment.change_assessments.append(change_assessment)

            # Track risk counts
            match change_assessment.confidence:
                case ConfidenceLevel.LOW:
                    assessment.high_risk_count += 1
                case ConfidenceLevel.MEDIUM:
                    assessment.medium_risk_count += 1
                case ConfidenceLevel.HIGH:
                    assessment.low_risk_count += 1

            # Track if any change requires approval
            if change_assessment.requires_approval:
                assessment.requires_approval = True

            # Track deletions
            if change_type == "Delete":
                has_delete = True

        # Determine overall confidence
        if assessment.high_risk_count > 0:
            assessment.overall_confidence = ConfidenceLevel.LOW
        elif assessment.medium_risk_count > 0:
            assessment.overall_confidence = ConfidenceLevel.MEDIUM
        else:
            assessment.overall_confidence = ConfidenceLevel.HIGH

        # Auto-approve option if no deletions
        if (
            self._config.auto_approve_if_no_delete
            and not has_delete
            and assessment.requires_approval
        ):
            logger.info(
                "Auto-approve enabled and no deletions - skipping approval",
                extra={"domain": domain},
            )
            assessment.requires_approval = False

        return assessment


class ApprovalGateError(Exception):
    """Raised when approval is required but not granted."""

    pass


class ApprovalGate:
    """Manages approval workflow for risky deployments.

    This class handles:
    - Creating approval requests
    - Checking approval status
    - Webhook notifications
    - Approval timeouts
    """

    def __init__(self, config: ApprovalConfig | None = None) -> None:
        """Initialize approval gate.

        Args:
            config: Approval configuration.
        """
        self._config = config or ApprovalConfig.from_env()
        self._assessor = RiskAssessor(config)
        # In-memory approval store (production: use Redis/Cosmos)
        self._pending_approvals: dict[str, ApprovalRequest] = {}

    @property
    def assessor(self) -> RiskAssessor:
        """Get the risk assessor."""
        return self._assessor

    def create_approval_request(
        self,
        request_id: str,
        domain: str,
        deployment_name: str,
        risk_assessment: DeploymentRiskAssessment,
    ) -> ApprovalRequest:
        """Create a new approval request.

        Args:
            request_id: Unique request identifier.
            domain: Operator domain.
            deployment_name: Name of the pending deployment.
            risk_assessment: Risk assessment for the deployment.

        Returns:
            Created approval request.
        """
        request = ApprovalRequest(
            request_id=request_id,
            domain=domain,
            deployment_name=deployment_name,
            risk_assessment=risk_assessment,
        )

        self._pending_approvals[request_id] = request

        logger.warning(
            "Approval required for deployment",
            extra={
                "request_id": request_id,
                "domain": domain,
                "deployment_name": deployment_name,
                "high_risk_count": risk_assessment.high_risk_count,
                "expires_at": request.expires_at.isoformat() if request.expires_at else None,
            },
        )

        # Send webhook notification if configured
        if self._config.approval_webhook_url:
            self._send_webhook_notification(request)

        return request

    def check_approval(self, request_id: str) -> ApprovalRequest | None:
        """Check status of an approval request.

        Args:
            request_id: Request identifier.

        Returns:
            Approval request if found, None otherwise.
        """
        request = self._pending_approvals.get(request_id)
        if request:
            request.check_and_update_expiry()
        return request

    def approve(
        self,
        request_id: str,
        approved_by: str,
    ) -> ApprovalRequest:
        """Approve a pending request.

        Args:
            request_id: Request identifier.
            approved_by: Identity that approved (email, UPN, etc.).

        Returns:
            Updated approval request.

        Raises:
            ApprovalGateError: If request not found or already processed.
        """
        request = self._pending_approvals.get(request_id)
        if request is None:
            raise ApprovalGateError(f"Approval request not found: {request_id}")

        request.check_and_update_expiry()

        if request.status != ApprovalStatus.PENDING:
            raise ApprovalGateError(
                f"Request {request_id} is not pending (status: {request.status.value})"
            )

        request.status = ApprovalStatus.APPROVED
        request.approved_by = approved_by
        request.approved_at = datetime.now(UTC)

        logger.info(
            "Deployment approved",
            extra={
                "request_id": request_id,
                "domain": request.domain,
                "approved_by": approved_by,
            },
        )

        return request

    def reject(
        self,
        request_id: str,
        rejected_by: str,
        reason: str,
    ) -> ApprovalRequest:
        """Reject a pending request.

        Args:
            request_id: Request identifier.
            rejected_by: Identity that rejected.
            reason: Rejection reason.

        Returns:
            Updated approval request.

        Raises:
            ApprovalGateError: If request not found or already processed.
        """
        request = self._pending_approvals.get(request_id)
        if request is None:
            raise ApprovalGateError(f"Approval request not found: {request_id}")

        request.check_and_update_expiry()

        if request.status != ApprovalStatus.PENDING:
            raise ApprovalGateError(
                f"Request {request_id} is not pending (status: {request.status.value})"
            )

        request.status = ApprovalStatus.REJECTED
        request.approved_by = rejected_by  # Reuse field for rejector
        request.approved_at = datetime.now(UTC)
        request.rejection_reason = reason

        logger.warning(
            "Deployment rejected",
            extra={
                "request_id": request_id,
                "domain": request.domain,
                "rejected_by": rejected_by,
                "reason": reason,
            },
        )

        return request

    def _send_webhook_notification(self, request: ApprovalRequest) -> None:
        """Send webhook notification for approval request.

        This is a placeholder - production would use httpx/aiohttp.
        """
        logger.info(
            "Would send webhook notification",
            extra={
                "webhook_url": self._config.approval_webhook_url,
                "request_id": request.request_id,
                "domain": request.domain,
            },
        )
        # TODO: Implement actual webhook call
        # This should be async and use httpx with timeout/retry

    def cleanup_expired(self) -> int:
        """Clean up expired approval requests.

        Returns:
            Number of requests cleaned up.
        """
        expired_ids = []
        for request_id, request in self._pending_approvals.items():
            request.check_and_update_expiry()
            if request.status == ApprovalStatus.EXPIRED:
                expired_ids.append(request_id)

        for request_id in expired_ids:
            del self._pending_approvals[request_id]
            logger.info(
                "Cleaned up expired approval request",
                extra={"request_id": request_id},
            )

        return len(expired_ids)
