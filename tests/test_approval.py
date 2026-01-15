"""Tests for approval gate and confidence scoring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from controller.approval import (
    DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    HIGH_RISK_CHANGE_TYPES,
    HIGH_RISK_RESOURCE_TYPES,
    MAX_APPROVAL_TIMEOUT_SECONDS,
    MEDIUM_RISK_RESOURCE_TYPES,
    ApprovalConfig,
    ApprovalGate,
    ApprovalGateError,
    ApprovalRequest,
    ApprovalStatus,
    ChangeRiskAssessment,
    ConfidenceLevel,
    DeploymentRiskAssessment,
    RiskAssessor,
)


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""

    def test_values(self) -> None:
        """Test enum values."""
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"

    def test_string_enum(self) -> None:
        """Test enum value access."""
        assert ConfidenceLevel.HIGH.value == "high"


class TestApprovalStatus:
    """Tests for ApprovalStatus enum."""

    def test_values(self) -> None:
        """Test enum values."""
        assert ApprovalStatus.PENDING.value == "pending"
        assert ApprovalStatus.APPROVED.value == "approved"
        assert ApprovalStatus.REJECTED.value == "rejected"
        assert ApprovalStatus.EXPIRED.value == "expired"
        assert ApprovalStatus.NOT_REQUIRED.value == "not_required"


class TestHighRiskResourceTypes:
    """Tests for high-risk resource types set."""

    def test_contains_role_assignments(self) -> None:
        """Test role assignments are high-risk."""
        assert "Microsoft.Authorization/roleAssignments" in HIGH_RISK_RESOURCE_TYPES

    def test_contains_firewall(self) -> None:
        """Test firewalls are high-risk."""
        assert "Microsoft.Network/azureFirewalls" in HIGH_RISK_RESOURCE_TYPES

    def test_contains_management_groups(self) -> None:
        """Test management groups are high-risk."""
        assert "Microsoft.Management/managementGroups" in HIGH_RISK_RESOURCE_TYPES

    def test_contains_key_vault(self) -> None:
        """Test key vaults are high-risk."""
        assert "Microsoft.KeyVault/vaults" in HIGH_RISK_RESOURCE_TYPES

    def test_contains_route_tables(self) -> None:
        """Test route tables are high-risk."""
        assert "Microsoft.Network/routeTables" in HIGH_RISK_RESOURCE_TYPES

    def test_contains_nsg(self) -> None:
        """Test NSGs are high-risk."""
        assert "Microsoft.Network/networkSecurityGroups" in HIGH_RISK_RESOURCE_TYPES


class TestMediumRiskResourceTypes:
    """Tests for medium-risk resource types set."""

    def test_contains_virtual_networks(self) -> None:
        """Test virtual networks are medium-risk."""
        assert "Microsoft.Network/virtualNetworks" in MEDIUM_RISK_RESOURCE_TYPES

    def test_contains_storage_accounts(self) -> None:
        """Test storage accounts are medium-risk."""
        assert "Microsoft.Storage/storageAccounts" in MEDIUM_RISK_RESOURCE_TYPES

    def test_contains_vms(self) -> None:
        """Test VMs are medium-risk."""
        assert "Microsoft.Compute/virtualMachines" in MEDIUM_RISK_RESOURCE_TYPES


class TestHighRiskChangeTypes:
    """Tests for high-risk change types."""

    def test_contains_delete(self) -> None:
        """Test Delete is high-risk."""
        assert "Delete" in HIGH_RISK_CHANGE_TYPES


class TestApprovalConfig:
    """Tests for ApprovalConfig."""

    def test_defaults(self) -> None:
        """Test default configuration values."""
        config = ApprovalConfig()
        assert config.require_approval_for_high_risk is True
        assert config.additional_high_risk_types == frozenset()
        assert config.excluded_risk_types == frozenset()
        assert config.approval_webhook_url is None
        assert config.auto_approve_if_no_delete is False
        assert config.approval_timeout_seconds == DEFAULT_APPROVAL_TIMEOUT_SECONDS

    def test_from_env_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with empty environment."""
        # Clear all relevant env vars
        for var in [
            "REQUIRE_APPROVAL_FOR_HIGH_RISK",
            "ADDITIONAL_HIGH_RISK_TYPES",
            "EXCLUDED_RISK_TYPES",
            "APPROVAL_WEBHOOK_URL",
            "AUTO_APPROVE_IF_NO_DELETE",
            "APPROVAL_TIMEOUT_SECONDS",
        ]:
            monkeypatch.delenv(var, raising=False)

        config = ApprovalConfig.from_env()
        assert config.require_approval_for_high_risk is True  # Default
        assert config.additional_high_risk_types == frozenset()

    def test_from_env_disable_approval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test disabling approval via environment."""
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR_HIGH_RISK", "false")
        config = ApprovalConfig.from_env()
        assert config.require_approval_for_high_risk is False

    def test_from_env_additional_types(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test adding additional high-risk types."""
        monkeypatch.setenv(
            "ADDITIONAL_HIGH_RISK_TYPES",
            "Microsoft.Sql/servers,Microsoft.DocumentDb/databaseAccounts",
        )
        config = ApprovalConfig.from_env()
        assert "Microsoft.Sql/servers" in config.additional_high_risk_types
        assert "Microsoft.DocumentDb/databaseAccounts" in config.additional_high_risk_types

    def test_from_env_excluded_types(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test excluding types from high-risk."""
        monkeypatch.setenv("EXCLUDED_RISK_TYPES", "Microsoft.Network/routeTables")
        config = ApprovalConfig.from_env()
        assert "Microsoft.Network/routeTables" in config.excluded_risk_types

    def test_from_env_webhook_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test webhook URL configuration."""
        monkeypatch.setenv("APPROVAL_WEBHOOK_URL", "https://example.com/webhook")
        config = ApprovalConfig.from_env()
        assert config.approval_webhook_url == "https://example.com/webhook"

    def test_from_env_auto_approve(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test auto-approve if no delete."""
        monkeypatch.setenv("AUTO_APPROVE_IF_NO_DELETE", "true")
        config = ApprovalConfig.from_env()
        assert config.auto_approve_if_no_delete is True

    def test_from_env_custom_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test custom timeout."""
        monkeypatch.setenv("APPROVAL_TIMEOUT_SECONDS", "7200")
        config = ApprovalConfig.from_env()
        assert config.approval_timeout_seconds == 7200

    def test_from_env_invalid_timeout_uses_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test invalid timeout falls back to default."""
        monkeypatch.setenv("APPROVAL_TIMEOUT_SECONDS", "invalid")
        config = ApprovalConfig.from_env()
        assert config.approval_timeout_seconds == DEFAULT_APPROVAL_TIMEOUT_SECONDS


class TestRiskAssessor:
    """Tests for RiskAssessor."""

    @pytest.fixture
    def assessor(self) -> RiskAssessor:
        """Create a default risk assessor."""
        return RiskAssessor(ApprovalConfig())

    @pytest.fixture
    def assessor_no_approval(self) -> RiskAssessor:
        """Create an assessor with approval disabled."""
        return RiskAssessor(ApprovalConfig(require_approval_for_high_risk=False))

    def test_assess_high_risk_resource(self, assessor: RiskAssessor) -> None:
        """Test assessing high-risk resource type."""
        result = assessor.assess_change(
            resource_id="/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/ra1",
            resource_type="Microsoft.Authorization/roleAssignments",
            change_type="Create",
        )
        assert result.confidence == ConfidenceLevel.LOW
        assert result.requires_approval is True
        assert "High-risk resource type" in result.risk_reasons[0]

    def test_assess_medium_risk_resource_create(self, assessor: RiskAssessor) -> None:
        """Test assessing medium-risk resource with Create."""
        result = assessor.assess_change(
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
            resource_type="Microsoft.Network/virtualNetworks",
            change_type="Create",
        )
        assert result.confidence == ConfidenceLevel.MEDIUM
        assert result.requires_approval is False  # Only high-risk needs approval

    def test_assess_medium_risk_resource_delete(self, assessor: RiskAssessor) -> None:
        """Test assessing medium-risk resource with Delete."""
        result = assessor.assess_change(
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
            resource_type="Microsoft.Network/virtualNetworks",
            change_type="Delete",
        )
        assert result.confidence == ConfidenceLevel.MEDIUM
        assert result.requires_approval is True  # Delete on medium-risk needs approval

    def test_assess_low_risk_resource(self, assessor: RiskAssessor) -> None:
        """Test assessing low-risk resource type."""
        result = assessor.assess_change(
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
            resource_type="Microsoft.Web/sites",
            change_type="Create",
        )
        assert result.confidence == ConfidenceLevel.HIGH
        assert result.requires_approval is False

    def test_assess_delete_elevates_risk(self, assessor: RiskAssessor) -> None:
        """Test that Delete elevates risk level."""
        result = assessor.assess_change(
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
            resource_type="Microsoft.Web/sites",
            change_type="Delete",
        )
        assert result.confidence == ConfidenceLevel.MEDIUM
        assert "Risky change type" in result.risk_reasons[0]

    def test_assess_with_approval_disabled(
        self, assessor_no_approval: RiskAssessor
    ) -> None:
        """Test that approval can be disabled."""
        result = assessor_no_approval.assess_change(
            resource_id="/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/ra1",
            resource_type="Microsoft.Authorization/roleAssignments",
            change_type="Create",
        )
        assert result.confidence == ConfidenceLevel.LOW  # Still low confidence
        assert result.requires_approval is False  # But no approval required

    def test_assess_deployment_aggregates_risk(self, assessor: RiskAssessor) -> None:
        """Test deployment assessment aggregates change risks."""
        changes = [
            ("/sub/providers/Microsoft.Authorization/roleAssignments/ra1",
             "Microsoft.Authorization/roleAssignments", "Create"),
            ("/sub/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
             "Microsoft.Network/virtualNetworks", "Create"),
            ("/sub/rg/providers/Microsoft.Web/sites/app1",
             "Microsoft.Web/sites", "Create"),
        ]
        result = assessor.assess_deployment("test-domain", changes)

        assert result.overall_confidence == ConfidenceLevel.LOW
        assert result.requires_approval is True
        assert result.high_risk_count == 1
        assert result.medium_risk_count == 1
        assert result.low_risk_count == 1  # Note: this is actually HIGH confidence count
        assert result.total_changes == 3

    def test_assess_deployment_no_high_risk(self, assessor: RiskAssessor) -> None:
        """Test deployment with no high-risk changes."""
        changes = [
            ("/sub/rg/providers/Microsoft.Web/sites/app1",
             "Microsoft.Web/sites", "Create"),
            ("/sub/rg/providers/Microsoft.Web/sites/app2",
             "Microsoft.Web/sites", "Modify"),
        ]
        result = assessor.assess_deployment("test-domain", changes)

        assert result.overall_confidence == ConfidenceLevel.HIGH
        assert result.requires_approval is False

    def test_assess_deployment_auto_approve_no_delete(self) -> None:
        """Test auto-approve when no deletions."""
        config = ApprovalConfig(auto_approve_if_no_delete=True)
        assessor = RiskAssessor(config)

        changes = [
            ("/sub/providers/Microsoft.Authorization/roleAssignments/ra1",
             "Microsoft.Authorization/roleAssignments", "Create"),
        ]
        result = assessor.assess_deployment("test-domain", changes)

        # High-risk but no delete, should be auto-approved
        assert result.overall_confidence == ConfidenceLevel.LOW
        assert result.requires_approval is False  # Auto-approved

    def test_assess_deployment_no_auto_approve_with_delete(self) -> None:
        """Test no auto-approve when deletions present."""
        config = ApprovalConfig(auto_approve_if_no_delete=True)
        assessor = RiskAssessor(config)

        changes = [
            ("/sub/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
             "Microsoft.Network/virtualNetworks", "Delete"),
        ]
        result = assessor.assess_deployment("test-domain", changes)

        # Medium-risk with delete - still requires approval
        assert result.requires_approval is True


class TestApprovalRequest:
    """Tests for ApprovalRequest."""

    def test_default_expiry(self) -> None:
        """Test default expiry is set."""
        request = ApprovalRequest(
            request_id="test-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=DeploymentRiskAssessment(domain="test"),
        )
        assert request.expires_at is not None
        expected_expiry = request.created_at + timedelta(
            seconds=DEFAULT_APPROVAL_TIMEOUT_SECONDS
        )
        # Allow 1 second tolerance
        assert abs((request.expires_at - expected_expiry).total_seconds()) < 1

    def test_custom_expiry_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test custom expiry from environment."""
        monkeypatch.setenv("APPROVAL_TIMEOUT_SECONDS", "1800")
        request = ApprovalRequest(
            request_id="test-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=DeploymentRiskAssessment(domain="test"),
        )
        expected_expiry = request.created_at + timedelta(seconds=1800)
        assert abs((request.expires_at - expected_expiry).total_seconds()) < 1

    def test_max_expiry_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test expiry is clamped to maximum."""
        # Set to 48 hours
        monkeypatch.setenv("APPROVAL_TIMEOUT_SECONDS", "172800")
        request = ApprovalRequest(
            request_id="test-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=DeploymentRiskAssessment(domain="test"),
        )
        expected_expiry = request.created_at + timedelta(
            seconds=MAX_APPROVAL_TIMEOUT_SECONDS  # Should be clamped to 24h
        )
        assert abs((request.expires_at - expected_expiry).total_seconds()) < 1

    def test_is_expired_false(self) -> None:
        """Test is_expired when not expired."""
        request = ApprovalRequest(
            request_id="test-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=DeploymentRiskAssessment(domain="test"),
        )
        assert request.is_expired is False

    def test_is_expired_true(self) -> None:
        """Test is_expired when expired."""
        past_time = datetime.now(UTC) - timedelta(hours=2)
        request = ApprovalRequest(
            request_id="test-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=DeploymentRiskAssessment(domain="test"),
            created_at=past_time,
            expires_at=past_time + timedelta(seconds=1),  # Expired 2 hours ago
        )
        assert request.is_expired is True

    def test_check_and_update_expiry(self) -> None:
        """Test check_and_update_expiry updates status."""
        past_time = datetime.now(UTC) - timedelta(hours=2)
        request = ApprovalRequest(
            request_id="test-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=DeploymentRiskAssessment(domain="test"),
            created_at=past_time,
            expires_at=past_time + timedelta(seconds=1),
        )
        assert request.status == ApprovalStatus.PENDING

        request.check_and_update_expiry()
        assert request.status == ApprovalStatus.EXPIRED


class TestApprovalGate:
    """Tests for ApprovalGate."""

    @pytest.fixture
    def gate(self) -> ApprovalGate:
        """Create a default approval gate."""
        return ApprovalGate(ApprovalConfig())

    @pytest.fixture
    def risk_assessment(self) -> DeploymentRiskAssessment:
        """Create a sample risk assessment."""
        return DeploymentRiskAssessment(
            domain="test",
            overall_confidence=ConfidenceLevel.LOW,
            requires_approval=True,
            high_risk_count=2,
        )

    def test_create_approval_request(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test creating an approval request."""
        request = gate.create_approval_request(
            request_id="test-req-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
        )
        assert request.request_id == "test-req-1"
        assert request.status == ApprovalStatus.PENDING
        assert request.domain == "test"

    def test_check_approval_found(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test checking approval status."""
        gate.create_approval_request(
            request_id="test-req-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
        )
        result = gate.check_approval("test-req-1")
        assert result is not None
        assert result.status == ApprovalStatus.PENDING

    def test_check_approval_not_found(self, gate: ApprovalGate) -> None:
        """Test checking non-existent approval."""
        result = gate.check_approval("non-existent")
        assert result is None

    def test_approve_success(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test approving a request."""
        gate.create_approval_request(
            request_id="test-req-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
        )
        result = gate.approve("test-req-1", approved_by="admin@example.com")

        assert result.status == ApprovalStatus.APPROVED
        assert result.approved_by == "admin@example.com"
        assert result.approved_at is not None

    def test_approve_not_found(self, gate: ApprovalGate) -> None:
        """Test approving non-existent request."""
        with pytest.raises(ApprovalGateError, match="not found"):
            gate.approve("non-existent", approved_by="admin@example.com")

    def test_approve_already_approved(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test approving already approved request."""
        gate.create_approval_request(
            request_id="test-req-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
        )
        gate.approve("test-req-1", approved_by="admin@example.com")

        with pytest.raises(ApprovalGateError, match="not pending"):
            gate.approve("test-req-1", approved_by="admin2@example.com")

    def test_reject_success(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test rejecting a request."""
        gate.create_approval_request(
            request_id="test-req-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
        )
        result = gate.reject(
            "test-req-1",
            rejected_by="security@example.com",
            reason="Changes violate policy",
        )

        assert result.status == ApprovalStatus.REJECTED
        assert result.approved_by == "security@example.com"  # Reused field
        assert result.rejection_reason == "Changes violate policy"

    def test_reject_not_found(self, gate: ApprovalGate) -> None:
        """Test rejecting non-existent request."""
        with pytest.raises(ApprovalGateError, match="not found"):
            gate.reject("non-existent", rejected_by="admin", reason="test")

    def test_reject_expired(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test rejecting expired request."""
        # Create with past expiry
        past_time = datetime.now(UTC) - timedelta(hours=2)
        request = ApprovalRequest(
            request_id="test-req-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
            created_at=past_time,
            expires_at=past_time + timedelta(seconds=1),
        )
        gate._pending_approvals["test-req-1"] = request

        with pytest.raises(ApprovalGateError, match="not pending"):
            gate.reject("test-req-1", rejected_by="admin", reason="test")

    def test_cleanup_expired(
        self, gate: ApprovalGate, risk_assessment: DeploymentRiskAssessment
    ) -> None:
        """Test cleanup of expired requests."""
        # Create expired request
        past_time = datetime.now(UTC) - timedelta(hours=2)
        expired_request = ApprovalRequest(
            request_id="expired-1",
            domain="test",
            deployment_name="deploy-1",
            risk_assessment=risk_assessment,
            created_at=past_time,
            expires_at=past_time + timedelta(seconds=1),
        )
        gate._pending_approvals["expired-1"] = expired_request

        # Create valid request
        gate.create_approval_request(
            request_id="valid-1",
            domain="test",
            deployment_name="deploy-2",
            risk_assessment=risk_assessment,
        )

        cleaned = gate.cleanup_expired()
        assert cleaned == 1
        assert "expired-1" not in gate._pending_approvals
        assert "valid-1" in gate._pending_approvals

    def test_assessor_property(self, gate: ApprovalGate) -> None:
        """Test assessor property."""
        assessor = gate.assessor
        assert isinstance(assessor, RiskAssessor)


class TestDeploymentRiskAssessment:
    """Tests for DeploymentRiskAssessment."""

    def test_total_changes(self) -> None:
        """Test total changes calculation."""
        assessment = DeploymentRiskAssessment(domain="test")
        assessment.change_assessments = [
            ChangeRiskAssessment(
                resource_id="r1",
                resource_type="t1",
                change_type="Create",
                confidence=ConfidenceLevel.HIGH,
                requires_approval=False,
            ),
            ChangeRiskAssessment(
                resource_id="r2",
                resource_type="t2",
                change_type="Create",
                confidence=ConfidenceLevel.LOW,
                requires_approval=True,
            ),
        ]
        assert assessment.total_changes == 2

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        assessment = DeploymentRiskAssessment(
            domain="test",
            overall_confidence=ConfidenceLevel.LOW,
            requires_approval=True,
            high_risk_count=1,
            medium_risk_count=2,
        )
        result = assessment.to_dict()

        assert result["domain"] == "test"
        assert result["overall_confidence"] == "low"
        assert result["requires_approval"] is True
        assert result["high_risk_count"] == 1
        assert result["medium_risk_count"] == 2
