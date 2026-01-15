"""Tests for state provenance tracking."""

from __future__ import annotations

from datetime import UTC
from unittest.mock import patch

import pytest

from controller.provenance import (
    OPERATOR_VERSION,
    ChangeProvenanceSummary,
    ProvenanceLogger,
    ReconcileProvenance,
    get_provenance_logger,
)


class TestChangeProvenanceSummary:
    """Tests for ChangeProvenanceSummary dataclass."""

    def test_total_significant_empty(self) -> None:
        """Empty summary has zero significant changes."""
        summary = ChangeProvenanceSummary()
        assert summary.total_significant == 0

    def test_total_significant_all_types(self) -> None:
        """Total is sum of create + modify + delete."""
        summary = ChangeProvenanceSummary(
            create_count=5,
            modify_count=3,
            delete_count=2,
            no_change_count=10,
            ignored_count=1,
        )
        assert summary.total_significant == 10

    def test_no_change_not_counted(self) -> None:
        """no_change and ignored are not counted as significant."""
        summary = ChangeProvenanceSummary(
            create_count=0,
            modify_count=0,
            delete_count=0,
            no_change_count=100,
            ignored_count=50,
        )
        assert summary.total_significant == 0


class TestReconcileProvenance:
    """Tests for ReconcileProvenance dataclass."""

    def test_default_values(self) -> None:
        """Default provenance has expected values."""
        provenance = ReconcileProvenance()
        assert provenance.domain == ""
        assert provenance.operator_version == OPERATOR_VERSION
        assert provenance.mode == "observe"
        assert provenance.drift_detected is False
        assert provenance.changes_applied == 0
        assert provenance.error is None

    def test_timestamp_is_utc(self) -> None:
        """Timestamp uses UTC timezone."""
        provenance = ReconcileProvenance()
        assert provenance.timestamp.tzinfo is UTC

    def test_to_dict(self) -> None:
        """to_dict converts to serializable dictionary."""
        provenance = ReconcileProvenance(
            domain="firewall",
            subscription_id="sub-123",
            mode="enforce",
            drift_detected=True,
            changes_applied=5,
        )
        result = provenance.to_dict()

        assert isinstance(result, dict)
        assert result["domain"] == "firewall"
        assert result["subscription_id"] == "sub-123"
        assert result["mode"] == "enforce"
        assert result["drift_detected"] is True
        assert result["changes_applied"] == 5
        # Timestamp should be ISO format string
        assert isinstance(result["timestamp"], str)

    def test_to_dict_with_error(self) -> None:
        """to_dict includes error information."""
        provenance = ReconcileProvenance(
            domain="hub-network",
            error="Connection timeout",
            error_type="HttpResponseError",
        )
        result = provenance.to_dict()

        assert result["error"] == "Connection timeout"
        assert result["error_type"] == "HttpResponseError"


class TestProvenanceLogger:
    """Tests for ProvenanceLogger class."""

    def test_create_provenance_basic(self) -> None:
        """create_provenance creates record with provided values."""
        logger = ProvenanceLogger()
        provenance = logger.create_provenance(
            domain="dns",
            subscription_id="sub-abc",
            management_group_id="mg-001",
            deployment_scope="subscription",
            mode="observe",
        )

        assert provenance.domain == "dns"
        assert provenance.subscription_id == "sub-abc"
        assert provenance.management_group_id == "mg-001"
        assert provenance.deployment_scope == "subscription"
        assert provenance.mode == "observe"
        assert provenance.operator_version == OPERATOR_VERSION

    def test_create_provenance_none_management_group(self) -> None:
        """create_provenance handles None management_group_id."""
        logger = ProvenanceLogger()
        provenance = logger.create_provenance(
            domain="policy",
            subscription_id="sub-xyz",
            management_group_id=None,
            deployment_scope="subscription",
            mode="enforce",
        )

        assert provenance.management_group_id == ""

    @patch.dict(
        "os.environ",
        {
            "GIT_COMMIT_SHA": "abc123def456",
            "GIT_BRANCH": "main",
            "GIT_REPO": "org/repo",
            "CONTAINER_INSTANCE_ID": "container-001",
        },
    )
    def test_create_provenance_with_git_info(self) -> None:
        """create_provenance includes git info from environment."""
        # Create new logger to pick up env vars
        logger = ProvenanceLogger()
        provenance = logger.create_provenance(
            domain="firewall",
            subscription_id="sub-123",
            management_group_id=None,
            deployment_scope="subscription",
            mode="observe",
        )

        assert provenance.git_commit_sha == "abc123def456"
        assert provenance.git_branch == "main"
        assert provenance.git_repo == "org/repo"
        assert provenance.operator_instance_id == "container-001"

    def test_log_provenance_success(self, caplog: pytest.LogCaptureFixture) -> None:
        """log_provenance logs info level for successful reconciliation."""
        logger = ProvenanceLogger()
        provenance = ReconcileProvenance(
            domain="hub-network",
            mode="observe",
            drift_detected=True,
            changes_applied=0,
        )

        with caplog.at_level("INFO"):
            logger.log_provenance(provenance)

        assert "Reconciliation provenance" in caplog.text

    def test_log_provenance_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """log_provenance logs error level when error present."""
        logger = ProvenanceLogger()
        provenance = ReconcileProvenance(
            domain="firewall",
            error="Something failed",
            error_type="RuntimeError",
        )

        with caplog.at_level("ERROR"):
            logger.log_provenance(provenance)

        assert len(caplog.records) > 0
        assert caplog.records[-1].levelname == "ERROR"

    def test_log_provenance_blocked(self, caplog: pytest.LogCaptureFixture) -> None:
        """log_provenance logs warning level when changes blocked."""
        logger = ProvenanceLogger()
        provenance = ReconcileProvenance(
            domain="policy",
            mode="protect",
            drift_detected=True,
            changes_blocked=3,
        )

        with caplog.at_level("WARNING"):
            logger.log_provenance(provenance)

        assert len(caplog.records) > 0
        assert caplog.records[-1].levelname == "WARNING"

    def test_log_change_detail(self, caplog: pytest.LogCaptureFixture) -> None:
        """log_change_detail logs individual resource changes."""
        logger = ProvenanceLogger()
        provenance = ReconcileProvenance(domain="dns", git_commit_sha="abc123")

        with caplog.at_level("INFO"):
            logger.log_change_detail(
                provenance=provenance,
                resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
                change_type="Create",
            )

        assert "Resource change" in caplog.text


class TestGetProvenanceLogger:
    """Tests for get_provenance_logger singleton function."""

    def test_returns_logger(self) -> None:
        """get_provenance_logger returns a ProvenanceLogger."""
        logger = get_provenance_logger()
        assert isinstance(logger, ProvenanceLogger)

    def test_singleton_pattern(self) -> None:
        """get_provenance_logger returns same instance on multiple calls."""
        logger1 = get_provenance_logger()
        logger2 = get_provenance_logger()
        assert logger1 is logger2
