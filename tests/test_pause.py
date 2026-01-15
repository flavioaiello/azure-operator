"""Tests for time-bound pause management."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from controller.pause import (
    MAX_EMERGENCY_WINDOW_SECONDS,
    MAX_PAUSE_DURATION_SECONDS,
    MIN_PAUSE_DURATION_SECONDS,
    EmergencyWindow,
    PauseConfig,
    PauseEntry,
    PauseManager,
    PauseReason,
    PauseStatus,
    check_pause_with_manager,
)


class TestPauseEntry:
    """Tests for PauseEntry dataclass."""

    def test_is_active_when_not_expired(self) -> None:
        """Test pause is active before expiry."""
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now,
            expires_at=now + timedelta(hours=1),
            initiated_by="admin",
        )
        assert entry.is_active() is True

    def test_is_not_active_when_expired(self) -> None:
        """Test pause is not active after expiry."""
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),  # Already expired
            initiated_by="admin",
        )
        assert entry.is_active() is False

    def test_is_not_active_when_resumed(self) -> None:
        """Test pause is not active when resumed."""
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now,
            expires_at=now + timedelta(hours=1),
            initiated_by="admin",
            status=PauseStatus.RESUMED,
        )
        assert entry.is_active() is False

    def test_remaining_seconds(self) -> None:
        """Test remaining seconds calculation."""
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now,
            expires_at=now + timedelta(seconds=3600),
            initiated_by="admin",
        )
        remaining = entry.remaining_seconds()
        assert 3590 < remaining <= 3600  # Allow some margin

    def test_remaining_seconds_zero_when_expired(self) -> None:
        """Test remaining seconds is zero when expired."""
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            initiated_by="admin",
        )
        assert entry.remaining_seconds() == 0.0

    def test_to_dict_and_from_dict(self) -> None:
        """Test serialization round-trip."""
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now,
            expires_at=now + timedelta(hours=1),
            initiated_by="admin",
            notes="Test notes",
        )
        data = entry.to_dict()
        restored = PauseEntry.from_dict(data)

        assert restored.scope == entry.scope
        assert restored.reason == entry.reason
        assert restored.initiated_by == entry.initiated_by
        assert restored.notes == entry.notes
        assert restored.status == entry.status


class TestPauseConfig:
    """Tests for PauseConfig."""

    def test_defaults(self) -> None:
        """Test default configuration."""
        config = PauseConfig()
        assert config.max_pause_duration_seconds == MAX_PAUSE_DURATION_SECONDS
        assert config.default_pause_duration_seconds == 3600
        assert config.require_reason is True
        assert config.audit_log_enabled is True

    def test_from_env_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with empty environment."""
        for var in [
            "MAX_PAUSE_DURATION_SECONDS",
            "DEFAULT_PAUSE_DURATION_SECONDS",
            "PAUSE_REQUIRE_REASON",
            "PAUSE_AUDIT_LOG",
        ]:
            monkeypatch.delenv(var, raising=False)

        config = PauseConfig.from_env()
        assert config.max_pause_duration_seconds == MAX_PAUSE_DURATION_SECONDS

    def test_from_env_custom_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with custom values."""
        monkeypatch.setenv("MAX_PAUSE_DURATION_SECONDS", "7200")
        monkeypatch.setenv("PAUSE_REQUIRE_REASON", "false")

        config = PauseConfig.from_env()
        assert config.max_pause_duration_seconds == 7200
        assert config.require_reason is False


class TestPauseManager:
    """Tests for PauseManager."""

    @pytest.fixture
    def manager(self) -> PauseManager:
        """Create a pause manager with default config."""
        return PauseManager(PauseConfig(require_reason=False))

    def test_create_pause(self, manager: PauseManager) -> None:
        """Test creating a pause."""
        entry = manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
            initiated_by="admin@example.com",
        )

        assert entry.scope == "domain:firewall"
        assert entry.reason == PauseReason.MAINTENANCE
        assert entry.status == PauseStatus.ACTIVE
        assert entry.is_active() is True

    def test_create_pause_invalid_scope_format(self, manager: PauseManager) -> None:
        """Test invalid scope format raises error."""
        with pytest.raises(ValueError, match="Invalid scope format"):
            manager.create_pause(scope="firewall", duration_seconds=3600)

    def test_create_pause_invalid_scope_type(self, manager: PauseManager) -> None:
        """Test invalid scope type raises error."""
        with pytest.raises(ValueError, match="Invalid scope type"):
            manager.create_pause(scope="invalid:firewall", duration_seconds=3600)

    def test_create_pause_empty_scope_value(self, manager: PauseManager) -> None:
        """Test empty scope value raises error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.create_pause(scope="domain:", duration_seconds=3600)

    def test_create_pause_duration_clamped_to_max(self, manager: PauseManager) -> None:
        """Test duration is clamped to maximum."""
        entry = manager.create_pause(
            scope="domain:firewall",
            duration_seconds=999999,  # Way over max
            reason=PauseReason.MAINTENANCE,
        )

        # Duration should be clamped
        expected_expiry = entry.started_at + timedelta(
            seconds=manager.config.max_pause_duration_seconds
        )
        assert entry.expires_at == expected_expiry

    def test_create_pause_duration_clamped_to_min(self, manager: PauseManager) -> None:
        """Test duration is clamped to minimum."""
        entry = manager.create_pause(
            scope="domain:firewall",
            duration_seconds=1,  # Under minimum
            reason=PauseReason.MAINTENANCE,
        )

        expected_expiry = entry.started_at + timedelta(seconds=MIN_PAUSE_DURATION_SECONDS)
        assert entry.expires_at == expected_expiry

    def test_is_paused_active(self, manager: PauseManager) -> None:
        """Test is_paused returns True for active pause."""
        manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )

        assert manager.is_paused("domain", "firewall") is True
        assert manager.is_paused("domain", "dns") is False

    def test_is_paused_auto_expires(self, manager: PauseManager) -> None:
        """Test is_paused auto-expires old pauses."""
        now = datetime.now(UTC)

        # Manually create an expired pause
        entry = PauseEntry(
            scope="domain:firewall",
            reason=PauseReason.MAINTENANCE,
            started_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            initiated_by="admin",
        )
        manager._pauses["domain:firewall"] = entry

        # Check should auto-expire
        assert manager.is_paused("domain", "firewall") is False
        assert entry.status == PauseStatus.EXPIRED

    def test_resume(self, manager: PauseManager) -> None:
        """Test manual resume before expiry."""
        manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )

        assert manager.is_paused("domain", "firewall") is True

        result = manager.resume(
            scope="domain:firewall",
            resumed_by="admin@example.com",
        )

        assert result is True
        assert manager.is_paused("domain", "firewall") is False

    def test_resume_no_active_pause(self, manager: PauseManager) -> None:
        """Test resume with no active pause."""
        result = manager.resume(scope="domain:firewall")
        assert result is False

    def test_extend_pause(self, manager: PauseManager) -> None:
        """Test extending a pause."""
        entry = manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )
        original_expiry = entry.expires_at

        extended = manager.extend_pause(
            scope="domain:firewall",
            additional_seconds=1800,
            extended_by="admin",
        )

        assert extended is not None
        assert extended.expires_at == original_expiry + timedelta(seconds=1800)

    def test_extend_pause_capped_at_max(self, manager: PauseManager) -> None:
        """Test extension is capped at max duration from start."""
        entry = manager.create_pause(
            scope="domain:firewall",
            duration_seconds=manager.config.max_pause_duration_seconds - 100,
            reason=PauseReason.MAINTENANCE,
        )

        # Try to extend way beyond max
        extended = manager.extend_pause(
            scope="domain:firewall",
            additional_seconds=999999,
            extended_by="admin",
        )

        # Should be capped at max duration from original start
        max_expiry = entry.started_at + timedelta(
            seconds=manager.config.max_pause_duration_seconds
        )
        assert extended is not None
        assert extended.expires_at == max_expiry

    def test_get_active_pauses(self, manager: PauseManager) -> None:
        """Test getting active pauses."""
        manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )
        manager.create_pause(
            scope="domain:dns",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )

        active = manager.get_active_pauses()
        assert len(active) == 2

    def test_audit_log(self, manager: PauseManager) -> None:
        """Test audit log is populated."""
        manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
            initiated_by="admin",
        )
        manager.resume(scope="domain:firewall", resumed_by="admin")

        log = manager.get_audit_log()
        assert len(log) >= 2
        assert log[0]["event_type"] == "PAUSE_RESUMED"
        assert log[1]["event_type"] == "PAUSE_CREATED"


class TestEmergencyWindow:
    """Tests for emergency change windows."""

    @pytest.fixture
    def manager(self) -> PauseManager:
        """Create a pause manager."""
        return PauseManager(PauseConfig())

    def test_is_active(self) -> None:
        """Test emergency window is_active."""
        now = datetime.now(UTC)
        window = EmergencyWindow(
            scope="domain:firewall",
            started_at=now,
            expires_at=now + timedelta(hours=1),
            initiated_by="admin",
            reason="Critical fix",
            ticket_id="INC001",
            approved_by="manager",
        )
        assert window.is_active() is True

    def test_create_emergency_window(self, manager: PauseManager) -> None:
        """Test creating emergency window."""
        window = manager.create_emergency_window(
            scope="domain:firewall",
            duration_seconds=1800,
            initiated_by="admin",
            reason="Critical security fix",
            ticket_id="INC001",
            approved_by="manager",
        )

        assert window.scope == "domain:firewall"
        assert window.ticket_id == "INC001"
        assert window.is_active() is True

    def test_emergency_window_requires_ticket(self, manager: PauseManager) -> None:
        """Test emergency window requires ticket ID."""
        with pytest.raises(ValueError, match="require a ticket ID"):
            manager.create_emergency_window(
                scope="domain:firewall",
                duration_seconds=1800,
                initiated_by="admin",
                reason="Fix",
                ticket_id="",
                approved_by="manager",
            )

    def test_emergency_window_requires_approver(self, manager: PauseManager) -> None:
        """Test emergency window requires approver."""
        with pytest.raises(ValueError, match="require secondary approval"):
            manager.create_emergency_window(
                scope="domain:firewall",
                duration_seconds=1800,
                initiated_by="admin",
                reason="Fix",
                ticket_id="INC001",
                approved_by="",
            )

    def test_emergency_window_duration_capped(self, manager: PauseManager) -> None:
        """Test emergency window duration is capped."""
        window = manager.create_emergency_window(
            scope="domain:firewall",
            duration_seconds=99999,  # Way over max
            initiated_by="admin",
            reason="Fix",
            ticket_id="INC001",
            approved_by="manager",
        )

        expected_expiry = window.started_at + timedelta(seconds=MAX_EMERGENCY_WINDOW_SECONDS)
        assert window.expires_at == expected_expiry

    def test_is_emergency_window_active(self, manager: PauseManager) -> None:
        """Test checking if emergency window is active."""
        manager.create_emergency_window(
            scope="domain:firewall",
            duration_seconds=1800,
            initiated_by="admin",
            reason="Fix",
            ticket_id="INC001",
            approved_by="manager",
        )

        assert manager.is_emergency_window_active("domain:firewall") is True
        assert manager.is_emergency_window_active("domain:dns") is False


class TestCheckPauseWithManager:
    """Tests for check_pause_with_manager helper."""

    @pytest.fixture
    def manager(self) -> PauseManager:
        """Create a pause manager."""
        return PauseManager(PauseConfig(require_reason=False))

    def test_domain_pause_detected(self, manager: PauseManager) -> None:
        """Test domain pause is detected."""
        manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )

        is_paused, entry = check_pause_with_manager(
            manager, domain="firewall", scope_type="subscription", scope_value="sub-1"
        )

        assert is_paused is True
        assert entry is not None
        assert entry.scope == "domain:firewall"

    def test_subscription_pause_detected(self, manager: PauseManager) -> None:
        """Test subscription pause is detected."""
        manager.create_pause(
            scope="subscription:sub-1",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
        )

        is_paused, entry = check_pause_with_manager(
            manager, domain="firewall", scope_type="subscription", scope_value="sub-1"
        )

        assert is_paused is True
        assert entry is not None
        assert entry.scope == "subscription:sub-1"

    def test_not_paused(self, manager: PauseManager) -> None:
        """Test when nothing is paused."""
        is_paused, entry = check_pause_with_manager(
            manager, domain="firewall", scope_type="subscription", scope_value="sub-1"
        )

        assert is_paused is False
        assert entry is None
