"""Tests for secretless architecture enforcement.

These tests verify that the operator correctly enforces
the secretless security model and rejects any credential
environment variables.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from controller.security import (
    FORBIDDEN_CREDENTIAL_ENV_VARS,
    SecretlessViolationError,
    enforce_secretless_architecture,
    get_managed_identity_credential,
)


class TestSecretlessEnforcement:
    """Tests for secretless architecture enforcement."""

    def test_clean_environment_passes(self) -> None:
        """Test that enforcement passes with no credential env vars."""
        # Ensure all forbidden vars are unset
        with mock.patch.dict(os.environ, {}, clear=True):
            # Should not raise
            enforce_secretless_architecture()

    @pytest.mark.parametrize("env_var", FORBIDDEN_CREDENTIAL_ENV_VARS)
    def test_forbidden_env_var_raises(self, env_var: str) -> None:
        """Test that each forbidden env var raises SecretlessViolationError."""
        with mock.patch.dict(os.environ, {env_var: "some-secret-value"}):
            with pytest.raises(SecretlessViolationError) as exc_info:
                enforce_secretless_architecture()

            # Verify error message mentions the env var
            assert env_var in str(exc_info.value)

    def test_azure_client_secret_rejected(self) -> None:
        """Test AZURE_CLIENT_SECRET specifically is rejected."""
        with mock.patch.dict(os.environ, {"AZURE_CLIENT_SECRET": "my-secret"}):
            with pytest.raises(SecretlessViolationError) as exc_info:
                enforce_secretless_architecture()

            assert "AZURE_CLIENT_SECRET" in str(exc_info.value)
            assert "SECURITY VIOLATION" in str(exc_info.value)

    def test_azure_password_rejected(self) -> None:
        """Test AZURE_PASSWORD is rejected."""
        with mock.patch.dict(os.environ, {"AZURE_PASSWORD": "my-password"}):
            with pytest.raises(SecretlessViolationError) as exc_info:
                enforce_secretless_architecture()

            assert "AZURE_PASSWORD" in str(exc_info.value)

    def test_certificate_password_rejected(self) -> None:
        """Test certificate password is rejected."""
        with mock.patch.dict(os.environ, {"AZURE_CLIENT_CERTIFICATE_PASSWORD": "cert-pass"}):
            with pytest.raises(SecretlessViolationError) as exc_info:
                enforce_secretless_architecture()

            assert "AZURE_CLIENT_CERTIFICATE_PASSWORD" in str(exc_info.value)


class TestGetManagedIdentityCredential:
    """Tests for managed identity credential getter."""

    def test_rejects_secret_env_var(self) -> None:
        """Test that get_managed_identity_credential enforces secretless."""
        with mock.patch.dict(os.environ, {"AZURE_CLIENT_SECRET": "secret"}):
            with pytest.raises(SecretlessViolationError):
                get_managed_identity_credential()

    @mock.patch("controller.security.ManagedIdentityCredential")
    def test_returns_system_assigned_by_default(self, mock_credential_class: mock.Mock) -> None:
        """Test that system-assigned MI is used when no client_id."""
        mock_credential = mock.Mock()
        mock_credential_class.return_value = mock_credential

        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_managed_identity_credential()

        mock_credential_class.assert_called_once_with()
        assert result is mock_credential

    @mock.patch("controller.security.ManagedIdentityCredential")
    def test_returns_user_assigned_with_client_id(self, mock_credential_class: mock.Mock) -> None:
        """Test that user-assigned MI is used when client_id provided."""
        mock_credential = mock.Mock()
        mock_credential_class.return_value = mock_credential
        client_id = "test-client-id-12345"

        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_managed_identity_credential(client_id=client_id)

        mock_credential_class.assert_called_once_with(client_id=client_id)
        assert result is mock_credential


class TestForbiddenEnvVarsList:
    """Tests for the forbidden environment variables list."""

    def test_contains_azure_client_secret(self) -> None:
        """Test that AZURE_CLIENT_SECRET is in the forbidden list."""
        assert "AZURE_CLIENT_SECRET" in FORBIDDEN_CREDENTIAL_ENV_VARS

    def test_contains_certificate_credentials(self) -> None:
        """Test that certificate-based credentials are forbidden."""
        assert "AZURE_CLIENT_CERTIFICATE_PATH" in FORBIDDEN_CREDENTIAL_ENV_VARS
        assert "AZURE_CLIENT_CERTIFICATE_PASSWORD" in FORBIDDEN_CREDENTIAL_ENV_VARS

    def test_contains_password_credentials(self) -> None:
        """Test that password-based credentials are forbidden."""
        assert "AZURE_USERNAME" in FORBIDDEN_CREDENTIAL_ENV_VARS
        assert "AZURE_PASSWORD" in FORBIDDEN_CREDENTIAL_ENV_VARS

    def test_list_is_tuple(self) -> None:
        """Test that the list is immutable (tuple, not list)."""
        assert isinstance(FORBIDDEN_CREDENTIAL_ENV_VARS, tuple)
