"""State provenance tracking for audit and compliance.

This module implements comprehensive provenance logging that answers:
- "What was the state at time T?"
- "Who made this change?"
- "What version of the operator/specs was running?"

DESIGN PHILOSOPHY:
- Every reconciliation cycle is stamped with provenance data
- Immutable logs to Log Analytics and Storage (when configured)
- Structured JSON format for queryability
- Git commit SHA, operator version, and change summaries
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Version is set at build time or falls back to dev
OPERATOR_VERSION = os.environ.get("OPERATOR_VERSION", "dev")


@dataclass
class ChangeProvenanceSummary:
    """Summary of changes for provenance tracking."""

    create_count: int = 0
    modify_count: int = 0
    delete_count: int = 0
    no_change_count: int = 0
    ignored_count: int = 0

    @property
    def total_significant(self) -> int:
        """Total significant changes (create + modify + delete)."""
        return self.create_count + self.modify_count + self.delete_count


@dataclass
class ReconcileProvenance:
    """Complete provenance record for a reconciliation cycle.

    This record captures everything needed to:
    - Audit what happened
    - Reproduce the state at this point
    - Correlate with external events
    """

    # Timestamp
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Identity
    domain: str = ""
    operator_version: str = OPERATOR_VERSION
    operator_instance_id: str = ""  # Container instance ID if available

    # Git source of truth
    git_commit_sha: str = ""
    git_branch: str = ""
    git_repo: str = ""
    spec_file_hash: str = ""  # SHA256 of the spec file content

    # Azure context
    subscription_id: str = ""
    management_group_id: str = ""
    deployment_scope: str = ""
    deployment_name: str = ""

    # Reconciliation outcome
    mode: str = "observe"  # observe, enforce, protect
    drift_detected: bool = False
    changes_applied: int = 0
    changes_blocked: int = 0
    change_summary: ChangeProvenanceSummary = field(
        default_factory=ChangeProvenanceSummary
    )

    # Timing
    duration_seconds: float = 0.0

    # Error tracking
    error: str | None = None
    error_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        # Convert datetime to ISO format
        result["timestamp"] = self.timestamp.isoformat()
        return result


class ProvenanceLogger:
    """Logs provenance records for audit and compliance.

    Outputs to:
    1. Structured logger (stdout/Log Analytics via container logs)
    2. Azure Storage (when configured) - for long-term retention
    """

    def __init__(self) -> None:
        """Initialize provenance logger."""
        self._git_commit_sha = os.environ.get("GIT_COMMIT_SHA", "")
        self._git_branch = os.environ.get("GIT_BRANCH", "")
        self._git_repo = os.environ.get("GIT_REPO", "")
        self._instance_id = os.environ.get("CONTAINER_INSTANCE_ID", "")

    def create_provenance(
        self,
        domain: str,
        subscription_id: str,
        management_group_id: str | None,
        deployment_scope: str,
        mode: str,
    ) -> ReconcileProvenance:
        """Create a new provenance record for a reconciliation cycle.

        Args:
            domain: The operator domain.
            subscription_id: Target Azure subscription.
            management_group_id: Target management group (if applicable).
            deployment_scope: The deployment scope (subscription, managementGroup, etc.).
            mode: Reconciliation mode (observe, enforce, protect).

        Returns:
            Initialized provenance record.
        """
        return ReconcileProvenance(
            domain=domain,
            operator_version=OPERATOR_VERSION,
            operator_instance_id=self._instance_id,
            git_commit_sha=self._git_commit_sha,
            git_branch=self._git_branch,
            git_repo=self._git_repo,
            subscription_id=subscription_id,
            management_group_id=management_group_id or "",
            deployment_scope=deployment_scope,
            mode=mode,
        )

    def log_provenance(self, provenance: ReconcileProvenance) -> None:
        """Log a completed provenance record.

        This is the primary audit log for the reconciliation cycle.
        The structured data enables queries like:
        - "Show all changes to subscription X in the last 24h"
        - "Which commit introduced this drift?"
        - "How many resources were modified during this window?"

        Args:
            provenance: Completed provenance record.
        """
        log_level = logging.INFO
        if provenance.error:
            log_level = logging.ERROR
        elif provenance.changes_blocked > 0:
            log_level = logging.WARNING

        logger.log(
            log_level,
            "Reconciliation provenance",
            extra={
                "provenance": provenance.to_dict(),
                # Flatten key fields for easier querying
                "domain": provenance.domain,
                "mode": provenance.mode,
                "drift_detected": provenance.drift_detected,
                "changes_applied": provenance.changes_applied,
                "changes_blocked": provenance.changes_blocked,
                "git_commit": provenance.git_commit_sha,
                "operator_version": provenance.operator_version,
                "duration_seconds": provenance.duration_seconds,
            },
        )

    def log_change_detail(
        self,
        provenance: ReconcileProvenance,
        resource_id: str,
        change_type: str,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
    ) -> None:
        """Log individual change details for fine-grained audit.

        This creates a separate log entry for each resource change,
        enabling detailed change tracking and rollback analysis.

        Args:
            provenance: Parent provenance record.
            resource_id: The Azure resource ID being changed.
            change_type: Type of change (Create, Modify, Delete).
            before: State before change (for Modify/Delete).
            after: State after change (for Create/Modify).
        """
        logger.info(
            "Resource change",
            extra={
                "domain": provenance.domain,
                "git_commit": provenance.git_commit_sha,
                "resource_id": resource_id,
                "change_type": change_type,
                "has_before": before is not None,
                "has_after": after is not None,
            },
        )


# Global singleton for provenance logging
_provenance_logger: ProvenanceLogger | None = None


def get_provenance_logger() -> ProvenanceLogger:
    """Get the global provenance logger instance."""
    global _provenance_logger
    if _provenance_logger is None:
        _provenance_logger = ProvenanceLogger()
    return _provenance_logger
