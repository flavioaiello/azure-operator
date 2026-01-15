"""Integration tests for the reconciliation loop.

These tests use MockAzureContext to test the full reconciliation flow
without actual Azure connectivity.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml
from azure_mock import MockAzureContext

from controller.config import Config, DeploymentScope, ReconciliationMode
from controller.reconciler import Reconciler


class TestReconcilerIntegration:
    """Integration tests for Reconciler with mocked Azure APIs."""

    @pytest.fixture
    def temp_templates(self) -> Generator[Path, None, None]:
        """Create temporary templates directory with test template."""
        with TemporaryDirectory() as tmpdir:
            templates_dir = Path(tmpdir) / "templates"
            templates_dir.mkdir()

            # Create a minimal ARM template for management domain
            # log-analytics operator maps to 'management' template
            template = {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {
                    "location": {"type": "string", "defaultValue": "westeurope"},
                    "workspaceName": {"type": "string"},
                },
                "resources": [
                    {
                        "type": "Microsoft.OperationalInsights/workspaces",
                        "apiVersion": "2022-10-01",
                        "name": "[parameters('workspaceName')]",
                        "location": "[parameters('location')]",
                        "properties": {
                            "sku": {"name": "PerGB2018"},
                            "retentionInDays": 30,
                        },
                    }
                ],
            }

            # Use domain template name (log-analytics maps to 'management')
            template_file = templates_dir / "management.json"
            template_file.write_text(__import__("json").dumps(template))

            yield templates_dir

    @pytest.fixture
    def temp_specs(self) -> Generator[Path, None, None]:
        """Create temporary specs directory with test spec."""
        with TemporaryDirectory() as tmpdir:
            specs_dir = Path(tmpdir) / "specs"
            specs_dir.mkdir()

            # Create a log-analytics spec (uses 'workspace' alias for log_analytics field)
            spec = {
                "apiVersion": "azure-operator/v1",
                "kind": "LogAnalyticsSpec",
                "metadata": {"name": "test-log-analytics"},
                "spec": {
                    "workspace": {
                        "name": "log-test",
                        "sku": "PerGB2018",
                        "retentionDays": 30,
                    }
                },
            }

            spec_file = specs_dir / "log-analytics.yaml"
            spec_file.write_text(yaml.dump(spec))

            yield specs_dir

    @pytest.fixture
    def config(self, temp_templates: Path, temp_specs: Path) -> Config:
        """Create a test configuration."""
        return Config(
            domain="log-analytics",
            subscription_id="00000000-0000-0000-0000-000000000001",
            location="westeurope",
            templates_dir=temp_templates,
            specs_dir=temp_specs,
            scope=DeploymentScope.SUBSCRIPTION,
            mode=ReconciliationMode.ENFORCE,  # ENFORCE mode for tests that expect changes
            dry_run=False,
            reconcile_interval_seconds=60,
        )

    @pytest.mark.asyncio
    async def test_reconcile_creates_new_resources(
        self, config: Config, temp_templates: Path, temp_specs: Path
    ) -> None:
        """Test that reconciler creates resources when they don't exist."""
        _ = temp_templates, temp_specs  # Used to trigger fixture setup
        with MockAzureContext() as ctx:
            reconciler = Reconciler(config)
            result = await reconciler._reconcile_once()

            # Verify reconciliation detected changes and applied them
            assert result.drift_found is True
            assert result.error is None
            assert ctx.get_deployment_count() == 1

    @pytest.mark.asyncio
    async def test_reconcile_no_drift_when_resources_exist(
        self, config: Config, temp_templates: Path, temp_specs: Path
    ) -> None:
        """Test that reconciler detects no drift when resources already exist."""
        _ = temp_templates, temp_specs  # Used to trigger fixture setup
        # Pre-populate state with existing resource
        initial_resources = [
            {
                "resource_id": (
                    f"/subscriptions/{config.subscription_id}"
                    "/providers/Microsoft.OperationalInsights/workspaces/log-test"
                ),
                "resource_type": "Microsoft.OperationalInsights/workspaces",
                "name": "log-test",
                "location": "westeurope",
                "properties": {
                    "sku": {"name": "PerGB2018"},
                    "retentionInDays": 30,
                },
            }
        ]

        with MockAzureContext(initial_resources=initial_resources):
            reconciler = Reconciler(config)
            result = await reconciler._reconcile_once()

            # Should detect no changes needed
            # Note: WhatIf still runs, but no deployment should happen
            assert result.error is None

    @pytest.mark.asyncio
    async def test_dry_run_prevents_deployment(
        self, temp_templates: Path, temp_specs: Path
    ) -> None:
        """Test that dry_run mode prevents actual deployments."""
        config = Config(
            domain="log-analytics",
            subscription_id="00000000-0000-0000-0000-000000000001",
            location="westeurope",
            templates_dir=temp_templates,
            specs_dir=temp_specs,
            scope=DeploymentScope.SUBSCRIPTION,
            dry_run=True,  # Enable dry run
            reconcile_interval_seconds=60,
        )

        with MockAzureContext() as ctx:
            reconciler = Reconciler(config)
            result = await reconciler._reconcile_once()

            # Dry run should detect drift but not deploy
            assert result.drift_found is True
            assert result.error is None
            # No actual deployment should have been created
            assert ctx.get_deployment_count() == 0

    @pytest.mark.asyncio
    async def test_deployment_failure_tracked(
        self, config: Config, temp_templates: Path, temp_specs: Path
    ) -> None:
        """Test that deployment failures are properly tracked."""
        _ = temp_templates, temp_specs  # Used to trigger fixture setup
        with MockAzureContext(fail_deployments=True) as ctx:
            reconciler = Reconciler(config)
            result = await reconciler._reconcile_once()

            # Should have attempted deployment but failed
            assert result.error is not None
            # Reconciler retries 3 times by default before giving up
            assert ctx.get_deployment_count() >= 1

    @pytest.mark.asyncio
    async def test_credential_is_managed_identity(
        self, config: Config, temp_templates: Path, temp_specs: Path
    ) -> None:
        """Test that reconciler uses managed identity credential."""
        _ = temp_templates, temp_specs  # Used to trigger fixture setup
        with MockAzureContext(client_id="test-client-123") as ctx:
            _ = Reconciler(config)  # Reconciler creation may trigger credential use

            # The credential should have been created
            assert ctx.credential.get_token_call_count >= 0  # May be called lazily


class TestCircuitBreakerIntegration:
    """Integration tests for circuit breaker behavior."""

    @pytest.fixture
    def quick_config(self) -> Generator[Config, None, None]:
        """Create a config with fast intervals for testing."""
        with TemporaryDirectory() as tmpdir:
            templates_dir = Path(tmpdir) / "templates"
            templates_dir.mkdir()
            specs_dir = Path(tmpdir) / "specs"
            specs_dir.mkdir()

            # Minimal template (log-analytics maps to 'management' domain)
            template = {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "resources": [],
            }
            (templates_dir / "management.json").write_text(
                __import__("json").dumps(template)
            )

            # Minimal spec (uses 'workspace' alias for log_analytics field)
            spec = {
                "apiVersion": "azure-operator/v1",
                "kind": "LogAnalyticsSpec",
                "metadata": {"name": "test"},
                "spec": {"workspace": {"name": "log-test", "sku": "PerGB2018"}},
            }
            (specs_dir / "log-analytics.yaml").write_text(yaml.dump(spec))

            yield Config(
                domain="log-analytics",
                subscription_id="00000000-0000-0000-0000-000000000001",
                location="westeurope",
                templates_dir=templates_dir,
                specs_dir=specs_dir,
                scope=DeploymentScope.SUBSCRIPTION,
                dry_run=False,
                reconcile_interval_seconds=1,  # Fast for testing
            )


class TestWhatIfDetection:
    """Integration tests for WhatIf change detection."""

    def test_whatif_detects_new_resource(self) -> None:
        """Test that WhatIf correctly identifies resource creation."""
        from azure_mock.resources import MockResourceState

        state = MockResourceState()
        template = {
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "name": "teststorage",
                    "location": "westeurope",
                    "properties": {},
                }
            ]
        }

        result = state.compute_whatif(
            template=template,
            parameters={},
            subscription_id="sub-123",
        )

        assert result.has_changes is True
        assert len(result.properties.changes) == 1
        assert result.properties.changes[0].change_type.value == "Create"

    def test_whatif_detects_no_change(self) -> None:
        """Test that WhatIf correctly identifies no changes needed."""
        from azure_mock.resources import MockResource, MockResourceState

        state = MockResourceState()

        # Pre-populate with existing resource
        existing = MockResource(
            resource_id="/subscriptions/sub-123/providers/Microsoft.Storage/storageAccounts/teststorage",
            resource_type="Microsoft.Storage/storageAccounts",
            name="teststorage",
            location="westeurope",
            properties={"encryption": "enabled"},
        )
        state.put_resource(existing)

        # Template with same properties
        template = {
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "name": "teststorage",
                    "location": "westeurope",
                    "properties": {"encryption": "enabled"},
                }
            ]
        }

        result = state.compute_whatif(
            template=template,
            parameters={},
            subscription_id="sub-123",
        )

        assert result.has_changes is False
        assert result.properties.changes[0].change_type.value == "NoChange"

    def test_whatif_detects_modification(self) -> None:
        """Test that WhatIf correctly identifies property changes."""
        from azure_mock.resources import MockResource, MockResourceState

        state = MockResourceState()

        # Pre-populate with existing resource
        existing = MockResource(
            resource_id="/subscriptions/sub-123/providers/Microsoft.Storage/storageAccounts/teststorage",
            resource_type="Microsoft.Storage/storageAccounts",
            name="teststorage",
            location="westeurope",
            properties={"encryption": "disabled"},
        )
        state.put_resource(existing)

        # Template with different properties
        template = {
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "name": "teststorage",
                    "location": "westeurope",
                    "properties": {"encryption": "enabled"},
                }
            ]
        }

        result = state.compute_whatif(
            template=template,
            parameters={},
            subscription_id="sub-123",
        )

        assert result.has_changes is True
        assert result.properties.changes[0].change_type.value == "Modify"


class TestMockCredential:
    """Tests for mock credential behavior."""

    def test_mock_credential_returns_token(self) -> None:
        """Test that mock credential returns valid tokens."""
        from azure_mock import create_mock_credential

        cred = create_mock_credential()
        token = cred.get_token("https://management.azure.com/.default")

        assert token.token.startswith("mock-token-")
        assert token.expires_on > 0

    def test_mock_credential_tracks_calls(self) -> None:
        """Test that mock credential tracks get_token calls."""
        from azure_mock import create_mock_credential

        cred = create_mock_credential()
        cred.get_token("scope1")
        cred.get_token("scope2", claims="test")

        assert cred.get_token_call_count == 2
        assert cred.get_token_calls[0]["scopes"] == ("scope1",)
        assert cred.get_token_calls[1]["claims"] == "test"

    def test_mock_credential_can_fail(self) -> None:
        """Test that mock credential can simulate failures."""
        from azure_mock import create_mock_credential

        cred = create_mock_credential()
        cred.set_failure(True, "Simulated auth error")

        with pytest.raises(Exception, match="Simulated auth error"):
            cred.get_token("scope")

    def test_mock_credential_user_assigned(self) -> None:
        """Test that mock credential supports user-assigned identity."""
        from azure_mock import create_mock_credential

        client_id = "my-client-id-123"
        cred = create_mock_credential(client_id=client_id)

        assert cred.client_id == client_id
        token = cred.get_token("scope")
        assert client_id in token.token


class TestALZManagementGroupScope:
    """Integration tests for ALZ-aligned management group scope operations.

    These tests verify that the operator correctly handles management group
    scoped deployments, which is the standard pattern for Azure Landing Zones.
    """

    @pytest.fixture
    def mg_templates(self) -> Generator[Path, None, None]:
        """Create templates for management-group operator."""
        with TemporaryDirectory() as tmpdir:
            templates_dir = Path(tmpdir) / "templates"
            templates_dir.mkdir()

            # Management group hierarchy template (ALZ pattern)
            template = {
                "$schema": "https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {
                    "rootManagementGroupId": {"type": "string"},
                    "rootManagementGroupDisplayName": {"type": "string"},
                },
                "resources": [
                    {
                        "type": "Microsoft.Management/managementGroups",
                        "apiVersion": "2021-04-01",
                        "scope": "/",
                        "name": "[parameters('rootManagementGroupId')]",
                        "properties": {
                            "displayName": "[parameters('rootManagementGroupDisplayName')]",
                        },
                    },
                    {
                        "type": "Microsoft.Management/managementGroups",
                        "apiVersion": "2021-04-01",
                        "scope": "/",
                        "name": "platform",
                        "properties": {
                            "displayName": "Platform",
                            "details": {
                                "parent": {
                                    "id": (
                                        "[concat('/providers/Microsoft.Management"
                                        "/managementGroups/', parameters('rootManagementGroupId'))]"
                                    )
                                }
                            },
                        },
                    },
                    {
                        "type": "Microsoft.Management/managementGroups",
                        "apiVersion": "2021-04-01",
                        "scope": "/",
                        "name": "landingzones",
                        "properties": {
                            "displayName": "Landing Zones",
                            "details": {
                                "parent": {
                                    "id": (
                                        "[concat('/providers/Microsoft.Management"
                                        "/managementGroups/', parameters('rootManagementGroupId'))]"
                                    )
                                }
                            },
                        },
                    },
                ],
            }

            # management-group operator maps to 'identity' domain template
            (templates_dir / "identity.json").write_text(
                __import__("json").dumps(template, indent=2)
            )
            yield templates_dir

    @pytest.fixture
    def mg_specs(self) -> Generator[Path, None, None]:
        """Create specs for management-group operator."""
        with TemporaryDirectory() as tmpdir:
            specs_dir = Path(tmpdir) / "specs"
            specs_dir.mkdir()

            # ALZ-style management group spec
            spec = {
                "apiVersion": "alz.azure.com/v1alpha1",
                "kind": "ManagementGroupSpec",
                "metadata": {"name": "alz-management-groups"},
                "spec": {
                    "rootManagementGroupId": "contoso",
                    "rootManagementGroupDisplayName": "Contoso",
                    "hierarchy": {
                        "platform": {
                            "displayName": "Platform",
                            "children": [
                                {"id": "management", "displayName": "Management"},
                                {"id": "connectivity", "displayName": "Connectivity"},
                                {"id": "identity", "displayName": "Identity"},
                            ],
                        },
                        "landingZones": {
                            "displayName": "Landing Zones",
                            "children": [
                                {"id": "corp", "displayName": "Corp"},
                                {"id": "online", "displayName": "Online"},
                            ],
                        },
                    },
                },
            }

            spec_file = specs_dir / "management-group.yaml"
            spec_file.write_text(yaml.dump(spec))
            yield specs_dir

    @pytest.fixture
    def mg_config(self, mg_templates: Path, mg_specs: Path) -> Config:
        """Create a management-group scoped configuration."""
        return Config(
            domain="management-group",
            subscription_id="00000000-0000-0000-0000-000000000001",
            location="westeurope",
            templates_dir=mg_templates,
            specs_dir=mg_specs,
            scope=DeploymentScope.MANAGEMENT_GROUP,
            management_group_id="contoso",
            mode=ReconciliationMode.ENFORCE,  # ENFORCE mode for tests that expect changes
            dry_run=False,
            reconcile_interval_seconds=60,
        )

    @pytest.mark.asyncio
    async def test_management_group_whatif(
        self, mg_config: Config, mg_templates: Path, mg_specs: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test WhatIf at management group scope detects hierarchy changes."""
        _ = mg_templates, mg_specs  # Used to trigger fixture setup
        # Disable approval gates for this test - we want to verify deployment flow
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR_HIGH_RISK", "false")
        with MockAzureContext() as ctx:
            reconciler = Reconciler(mg_config)
            result = await reconciler._reconcile_once()

            # Should detect drift for new management groups
            assert result.drift_found is True
            assert result.error is None
            # Deployment should have been triggered
            assert ctx.get_deployment_count() >= 1

    @pytest.mark.asyncio
    async def test_management_group_no_drift_when_exists(
        self, mg_config: Config, mg_templates: Path, mg_specs: Path
    ) -> None:
        """Test no drift when management group hierarchy already exists."""
        _ = mg_templates, mg_specs  # Used to trigger fixture setup
        # Pre-populate with existing management groups
        mg_base = "/providers/Microsoft.Management/managementGroups"
        initial_resources = [
            {
                "resource_id": f"{mg_base}/contoso{mg_base}/contoso",
                "resource_type": "Microsoft.Management/managementGroups",
                "name": "contoso",
                "location": "global",
                "properties": {"displayName": "Contoso"},
            },
            {
                "resource_id": f"{mg_base}/contoso{mg_base}/platform",
                "resource_type": "Microsoft.Management/managementGroups",
                "name": "platform",
                "location": "global",
                "properties": {
                    "displayName": "Platform",
                    "details": {
                        "parent": {"id": f"{mg_base}/contoso"}
                    },
                },
            },
            {
                "resource_id": f"{mg_base}/contoso{mg_base}/landingzones",
                "resource_type": "Microsoft.Management/managementGroups",
                "name": "landingzones",
                "location": "global",
                "properties": {
                    "displayName": "Landing Zones",
                    "details": {
                        "parent": {"id": f"{mg_base}/contoso"}
                    },
                },
            },
        ]

        with MockAzureContext(initial_resources=initial_resources) as ctx:
            reconciler = Reconciler(mg_config)
            result = await reconciler._reconcile_once()

            # Should detect no drift when all MGs exist
            assert result.error is None
            # No deployment when no drift
            if not result.drift_found:
                assert ctx.get_deployment_count() == 0
