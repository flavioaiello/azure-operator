"""Tests for Resource Graph module."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from azure_mock import (
    MockGraphChange,
    MockGraphResource,
    create_mock_credential,
    create_mock_graph_client,
)

from controller.config import Config, DeploymentScope
from controller.resource_graph import (
    GraphChangeType,
    GraphQueryResult,
    ResourceChange,
    ResourceGraphQuerier,
    ResourceInfo,
)


@pytest.fixture
def test_config(tmp_path: Path) -> Config:
    """Create test configuration."""
    specs_dir = tmp_path / "specs"
    specs_dir.mkdir()
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    return Config(
        domain="connectivity",
        subscription_id="00000000-0000-0000-0000-000000000000",
        location="westeurope",
        specs_dir=specs_dir,
        templates_dir=templates_dir,
        scope=DeploymentScope.SUBSCRIPTION,
        enable_graph_check=True,
    )


@pytest.fixture
def mock_graph_client() -> MagicMock:
    """Create mock Resource Graph client."""
    return create_mock_graph_client()


class TestResourceChange:
    """Tests for ResourceChange dataclass."""

    def test_create_resource_change(self) -> None:
        """Test creating a ResourceChange."""
        timestamp = datetime.now(UTC)
        change = ResourceChange(
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
            change_type=GraphChangeType.UPDATE,
            timestamp=timestamp,
            changed_by="admin@contoso.com",
            client_type="Azure Portal",
        )

        assert change.resource_id.endswith("vnet")
        assert change.change_type == GraphChangeType.UPDATE
        assert change.changed_by == "admin@contoso.com"
        assert change.client_type == "Azure Portal"

    def test_change_type_enum(self) -> None:
        """Test GraphChangeType enum values."""
        assert GraphChangeType.CREATE.value == "Create"
        assert GraphChangeType.UPDATE.value == "Update"
        assert GraphChangeType.DELETE.value == "Delete"


class TestResourceInfo:
    """Tests for ResourceInfo dataclass."""

    def test_create_resource_info(self) -> None:
        """Test creating a ResourceInfo."""
        info = ResourceInfo(
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
            name="vnet",
            type="microsoft.network/virtualnetworks",
            location="westeurope",
            resource_group="rg",
            subscription_id="sub",
            tags={"Environment": "Production"},
        )

        assert info.name == "vnet"
        assert info.type == "microsoft.network/virtualnetworks"
        assert info.tags is not None
        assert info.tags["Environment"] == "Production"


class TestResourceGraphQuerier:
    """Tests for ResourceGraphQuerier class."""

    @pytest.mark.asyncio
    async def test_check_for_changes_no_changes(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test checking for changes when none exist."""
        credential = create_mock_credential()

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            result = await querier.check_for_changes()

        assert result.has_changes is False
        assert len(result.recent_changes) == 0
        assert result.query_time_seconds >= 0

    @pytest.mark.asyncio
    async def test_check_for_changes_with_changes(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test checking for changes when changes exist."""
        credential = create_mock_credential()

        # Add a mock change
        mock_graph_client.add_change(
            MockGraphChange(
                resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
                change_type="Update",
                changed_by="admin@contoso.com",
                client_type="Azure Portal",
            )
        )

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            result = await querier.check_for_changes()

        assert result.has_changes is True
        assert len(result.recent_changes) == 1
        assert result.recent_changes[0].changed_by == "admin@contoso.com"

    @pytest.mark.asyncio
    async def test_check_for_changes_returns_resources(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test that check_for_changes returns current resources."""
        credential = create_mock_credential()

        # Add a mock resource
        mock_graph_client.add_resource(
            MockGraphResource(
                resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
                name="vnet",
                type="microsoft.network/virtualnetworks",
            )
        )

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            result = await querier.check_for_changes()

        assert len(result.resources) == 1
        assert result.resources[0].name == "vnet"

    @pytest.mark.asyncio
    async def test_check_for_changes_with_resource_type_filter(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test filtering by resource type."""
        credential = create_mock_credential()

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            result = await querier.check_for_changes(
                resource_types=["microsoft.network/virtualnetworks"]
            )

        # Query should have been executed
        assert mock_graph_client.query_count >= 1
        assert isinstance(result, GraphQueryResult)

    @pytest.mark.asyncio
    async def test_get_change_attribution(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test getting change attribution for a specific resource."""
        credential = create_mock_credential()
        resource_id = (
            "/subscriptions/sub/resourceGroups/rg/"
            "providers/Microsoft.Network/virtualNetworks/vnet"
        )

        # Add change for specific resource
        mock_graph_client.add_change(
            MockGraphChange(
                resource_id=resource_id,
                change_type="Update",
                changed_by="security-team@contoso.com",
                client_type="Azure CLI",
            )
        )

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            changes = await querier.get_change_attribution(resource_id)

        assert len(changes) == 1
        assert changes[0].changed_by == "security-team@contoso.com"
        assert changes[0].client_type == "Azure CLI"

    @pytest.mark.asyncio
    async def test_find_orphans(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test finding orphan resources."""
        credential = create_mock_credential()

        # Add resources - one expected, one orphan
        expected_id = (
            "/subscriptions/sub/resourceGroups/rg/"
            "providers/Microsoft.Network/virtualNetworks/expected-vnet"
        )
        orphan_id = (
            "/subscriptions/sub/resourceGroups/rg/"
            "providers/Microsoft.Network/virtualNetworks/orphan-vnet"
        )

        mock_graph_client.add_resource(
            MockGraphResource(
                resource_id=expected_id,
                name="expected-vnet",
                type="microsoft.network/virtualnetworks",
            )
        )
        mock_graph_client.add_resource(
            MockGraphResource(
                resource_id=orphan_id,
                name="orphan-vnet",
                type="microsoft.network/virtualnetworks",
            )
        )

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            orphans = await querier.find_orphans([expected_id])

        assert len(orphans) == 1
        assert orphans[0].name == "orphan-vnet"

    @pytest.mark.asyncio
    async def test_query_timeout_handling(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test handling of query timeout."""
        from azure.core.exceptions import HttpResponseError

        credential = create_mock_credential()

        mock_graph_client.set_should_fail(True, "Query timed out")

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)

            with pytest.raises(HttpResponseError):
                await querier.check_for_changes()

    @pytest.mark.asyncio
    async def test_scope_filter_subscription(
        self, test_config: Config, mock_graph_client: MagicMock
    ) -> None:
        """Test scope filter for subscription scope."""
        credential = create_mock_credential()

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, test_config)
            scope_filter = querier._build_scope_filter()

        assert test_config.subscription_id in scope_filter

    @pytest.mark.asyncio
    async def test_scope_filter_resource_group(
        self, tmp_path: Path, mock_graph_client: MagicMock
    ) -> None:
        """Test scope filter for resource group scope."""
        specs_dir = tmp_path / "specs"
        specs_dir.mkdir()
        templates_dir = tmp_path / "templates"
        templates_dir.mkdir()

        config = Config(
            domain="connectivity",
            subscription_id="00000000-0000-0000-0000-000000000000",
            location="westeurope",
            specs_dir=specs_dir,
            templates_dir=templates_dir,
            scope=DeploymentScope.RESOURCE_GROUP,
            resource_group_name="rg-connectivity",
            enable_graph_check=True,
        )

        credential = create_mock_credential()

        with patch(
            "controller.resource_graph.ResourceGraphClient",
            return_value=mock_graph_client,
        ):
            querier = ResourceGraphQuerier(credential, config)
            scope_filter = querier._build_scope_filter()

        assert "rg-connectivity" in scope_filter


class TestGraphChangeTypeParsing:
    """Tests for parsing change types from Graph responses."""

    def test_parse_create(self) -> None:
        """Test parsing Create change type."""
        change_type = GraphChangeType("Create")
        assert change_type == GraphChangeType.CREATE

    def test_parse_update(self) -> None:
        """Test parsing Update change type."""
        change_type = GraphChangeType("Update")
        assert change_type == GraphChangeType.UPDATE

    def test_parse_delete(self) -> None:
        """Test parsing Delete change type."""
        change_type = GraphChangeType("Delete")
        assert change_type == GraphChangeType.DELETE

    def test_parse_invalid_falls_back(self) -> None:
        """Test that invalid change types raise ValueError."""
        with pytest.raises(ValueError):
            GraphChangeType("InvalidType")
