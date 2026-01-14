"""Tests for configuration loading."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from controller.config import Config, ConfigurationError, DeploymentScope


class TestConfig:
    """Tests for Config class."""

    def test_valid_config(self, tmp_path: Path) -> None:
        """Test creating a valid configuration."""
        specs_dir = tmp_path / "specs"
        templates_dir = tmp_path / "templates"
        specs_dir.mkdir()
        templates_dir.mkdir()

        config = Config(
            domain="management",
            subscription_id="12345678-1234-1234-1234-123456789012",
            location="westeurope",
            specs_dir=specs_dir,
            templates_dir=templates_dir,
        )

        assert config.domain == "management"
        assert config.scope == DeploymentScope.SUBSCRIPTION
        assert config.dry_run is False

    def test_missing_domain(self, tmp_path: Path) -> None:
        """Test that missing domain raises error."""
        specs_dir = tmp_path / "specs"
        templates_dir = tmp_path / "templates"
        specs_dir.mkdir()
        templates_dir.mkdir()

        with pytest.raises(ConfigurationError) as exc_info:
            Config(
                domain="",
                subscription_id="12345678-1234-1234-1234-123456789012",
                location="westeurope",
                specs_dir=specs_dir,
                templates_dir=templates_dir,
            )

        assert "DOMAIN" in str(exc_info.value)

    def test_management_group_scope_requires_id(self, tmp_path: Path) -> None:
        """Test that management group scope requires management_group_id."""
        specs_dir = tmp_path / "specs"
        templates_dir = tmp_path / "templates"
        specs_dir.mkdir()
        templates_dir.mkdir()

        with pytest.raises(ConfigurationError) as exc_info:
            Config(
                domain="policy",
                subscription_id="12345678-1234-1234-1234-123456789012",
                location="westeurope",
                scope=DeploymentScope.MANAGEMENT_GROUP,
                specs_dir=specs_dir,
                templates_dir=templates_dir,
            )

        assert "MANAGEMENT_GROUP_ID" in str(exc_info.value)

    def test_invalid_reconcile_interval(self, tmp_path: Path) -> None:
        """Test that out-of-range reconcile interval raises error."""
        specs_dir = tmp_path / "specs"
        templates_dir = tmp_path / "templates"
        specs_dir.mkdir()
        templates_dir.mkdir()

        with pytest.raises(ConfigurationError) as exc_info:
            Config(
                domain="management",
                subscription_id="12345678-1234-1234-1234-123456789012",
                location="westeurope",
                reconcile_interval_seconds=10,  # Too low
                specs_dir=specs_dir,
                templates_dir=templates_dir,
            )

        assert "RECONCILE_INTERVAL" in str(exc_info.value)

    def test_from_env(self, tmp_path: Path) -> None:
        """Test loading configuration from environment."""
        specs_dir = tmp_path / "specs"
        templates_dir = tmp_path / "templates"
        specs_dir.mkdir()
        templates_dir.mkdir()

        env = {
            "DOMAIN": "connectivity",
            "AZURE_SUBSCRIPTION_ID": "12345678-1234-1234-1234-123456789012",
            "AZURE_LOCATION": "northeurope",
            "SPECS_DIR": str(specs_dir),
            "TEMPLATES_DIR": str(templates_dir),
            "DRY_RUN": "true",
        }

        with patch.dict(os.environ, env, clear=True):
            config = Config.from_env()

        assert config.domain == "connectivity"
        assert config.location == "northeurope"
        assert config.dry_run is True
