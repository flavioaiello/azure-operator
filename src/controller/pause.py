"""Time-bound pause and emergency change window management.

This module implements time-based pausing with automatic resume,
supporting maintenance windows and emergency change windows.

DESIGN PHILOSOPHY:
- Pauses are ALWAYS time-bound to prevent forgotten pauses
- Auto-resume ensures operator eventually resumes normal operation
- All pause/resume events are logged for audit
- Emergency change windows allow temporary ENFORCE mode overrides

SECURITY CONSIDERATIONS:
- Pauses cannot bypass kill switch (kill switch > pause)
- Maximum pause duration is bounded to prevent indefinite pauses
- All pause operations require explicit reason
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# SECURITY: Maximum pause duration to prevent forgotten pauses
# Default: 24 hours. Can be reduced via environment variable.
MAX_PAUSE_DURATION_SECONDS: int = 86400  # 24 hours
MIN_PAUSE_DURATION_SECONDS: int = 60  # 1 minute minimum

# SECURITY: Maximum emergency window duration
MAX_EMERGENCY_WINDOW_SECONDS: int = 3600  # 1 hour

# Pattern for valid pause scope formats
VALID_PAUSE_SCOPE_PATTERN = r"^(domain|subscription|management_group|resource_group):[a-zA-Z0-9_\-]+$"


class PauseReason(str, Enum):
    """Standard reasons for pausing operations."""

    MAINTENANCE = "maintenance"
    INCIDENT = "incident"
    INVESTIGATION = "investigation"
    DEPLOYMENT_FREEZE = "deployment_freeze"
    CHANGE_WINDOW = "change_window"
    EMERGENCY = "emergency"
    MANUAL = "manual"


class PauseStatus(str, Enum):
    """Status of a pause."""

    ACTIVE = "active"
    EXPIRED = "expired"
    RESUMED = "resumed"
    CANCELLED = "cancelled"


@dataclass
class PauseEntry:
    """A single pause entry with time bounds and metadata.

    Attributes:
        scope: The pause scope (e.g., "domain:firewall", "subscription:xxx")
        reason: Why the pause was initiated
        started_at: When the pause started
        expires_at: When the pause automatically expires
        initiated_by: Identity that initiated the pause
        notes: Optional notes about the pause
        resumed_at: When the pause was manually resumed (None if auto-expired)
        status: Current status of the pause
    """

    scope: str
    reason: PauseReason
    started_at: datetime
    expires_at: datetime
    initiated_by: str
    notes: str = ""
    resumed_at: datetime | None = None
    status: PauseStatus = PauseStatus.ACTIVE

    def is_active(self) -> bool:
        """Check if pause is currently active."""
        if self.status != PauseStatus.ACTIVE:
            return False
        now = datetime.now(UTC)
        return now < self.expires_at

    def remaining_seconds(self) -> float:
        """Get remaining seconds until pause expires."""
        if not self.is_active():
            return 0.0
        now = datetime.now(UTC)
        return max(0.0, (self.expires_at - now).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "scope": self.scope,
            "reason": self.reason.value,
            "started_at": self.started_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "initiated_by": self.initiated_by,
            "notes": self.notes,
            "resumed_at": self.resumed_at.isoformat() if self.resumed_at else None,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PauseEntry:
        """Create from dictionary."""
        return cls(
            scope=data["scope"],
            reason=PauseReason(data["reason"]),
            started_at=datetime.fromisoformat(data["started_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            initiated_by=data["initiated_by"],
            notes=data.get("notes", ""),
            resumed_at=(
                datetime.fromisoformat(data["resumed_at"])
                if data.get("resumed_at")
                else None
            ),
            status=PauseStatus(data.get("status", "active")),
        )


@dataclass
class EmergencyWindow:
    """Emergency change window allowing temporary ENFORCE mode.

    During an emergency window, the operator can apply changes that would
    normally require approval or be blocked by guardrails.

    SECURITY: Emergency windows are logged, time-bounded, and limited.
    """

    scope: str
    started_at: datetime
    expires_at: datetime
    initiated_by: str
    reason: str
    ticket_id: str  # REQUIRED: Must reference an incident ticket
    approved_by: str  # REQUIRED: Must have secondary approval

    def is_active(self) -> bool:
        """Check if emergency window is currently active."""
        now = datetime.now(UTC)
        return self.started_at <= now < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "scope": self.scope,
            "started_at": self.started_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "initiated_by": self.initiated_by,
            "reason": self.reason,
            "ticket_id": self.ticket_id,
            "approved_by": self.approved_by,
        }


@dataclass
class PauseConfig:
    """Configuration for pause management.

    Attributes:
        max_pause_duration_seconds: Maximum allowed pause duration
        default_pause_duration_seconds: Default pause duration if not specified
        require_reason: Whether pause reason is required
        audit_log_enabled: Whether to log pause/resume events
        persistent_storage_enabled: Whether to persist pauses to storage
    """

    max_pause_duration_seconds: int = MAX_PAUSE_DURATION_SECONDS
    default_pause_duration_seconds: int = 3600  # 1 hour
    require_reason: bool = True
    audit_log_enabled: bool = True
    persistent_storage_enabled: bool = False  # Future: persist to blob storage

    @classmethod
    def from_env(cls) -> PauseConfig:
        """Load configuration from environment variables."""

        def get_int(key: str, default: int, min_val: int, max_val: int) -> int:
            value = os.environ.get(key)
            if value is None:
                return default
            try:
                parsed = int(value)
                return max(min_val, min(max_val, parsed))
            except ValueError:
                logger.warning(
                    f"Invalid integer for {key}: {value}, using default {default}"
                )
                return default

        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(key, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes")

        return cls(
            max_pause_duration_seconds=get_int(
                "MAX_PAUSE_DURATION_SECONDS",
                MAX_PAUSE_DURATION_SECONDS,
                MIN_PAUSE_DURATION_SECONDS,
                MAX_PAUSE_DURATION_SECONDS,
            ),
            default_pause_duration_seconds=get_int(
                "DEFAULT_PAUSE_DURATION_SECONDS",
                3600,
                MIN_PAUSE_DURATION_SECONDS,
                MAX_PAUSE_DURATION_SECONDS,
            ),
            require_reason=get_bool("PAUSE_REQUIRE_REASON", True),
            audit_log_enabled=get_bool("PAUSE_AUDIT_LOG", True),
            persistent_storage_enabled=get_bool("PAUSE_PERSISTENT_STORAGE", False),
        )


class PauseManager:
    """Manages time-bound pauses with automatic resume.

    This class replaces the simple PAUSED_SCOPES string list with a proper
    pause management system that supports:
    - Time-bound pauses with automatic expiry
    - Audit logging of all pause/resume events
    - Emergency change windows
    - Manual resume before expiry

    Thread Safety:
        This class is NOT thread-safe. In production, use with asyncio.Lock
        or external synchronization.

    Usage:
        manager = PauseManager(PauseConfig.from_env())

        # Create a time-bound pause
        entry = manager.create_pause(
            scope="domain:firewall",
            duration_seconds=3600,
            reason=PauseReason.MAINTENANCE,
            initiated_by="admin@example.com",
            notes="Monthly maintenance window"
        )

        # Check if scope is paused
        if manager.is_paused("domain", "firewall"):
            # Skip deployment

        # Resume early
        manager.resume("domain:firewall", resumed_by="admin@example.com")
    """

    def __init__(self, config: PauseConfig | None = None) -> None:
        """Initialize pause manager.

        Args:
            config: Pause configuration. If None, loads from environment.
        """
        self._config = config or PauseConfig.from_env()
        self._pauses: dict[str, PauseEntry] = {}
        self._emergency_windows: dict[str, EmergencyWindow] = {}
        self._audit_log: list[dict[str, Any]] = []

    @property
    def config(self) -> PauseConfig:
        """Get pause configuration."""
        return self._config

    def _log_audit(
        self,
        event_type: str,
        scope: str,
        identity: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log an audit event."""
        if not self._config.audit_log_enabled:
            return

        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "scope": scope,
            "identity": identity,
            "details": details or {},
        }
        self._audit_log.append(event)

        # Also log to structured logger
        logger.info(
            f"AUDIT: {event_type}",
            extra={
                "event_type": event_type,
                "scope": scope,
                "identity": identity,
                "details": details,
            },
        )

    def create_pause(
        self,
        scope: str,
        duration_seconds: int | None = None,
        reason: PauseReason = PauseReason.MANUAL,
        initiated_by: str = "unknown",
        notes: str = "",
    ) -> PauseEntry:
        """Create a time-bound pause for a scope.

        Args:
            scope: The scope to pause (e.g., "domain:firewall")
            duration_seconds: How long to pause. If None, uses default.
            reason: Why the pause is being initiated.
            initiated_by: Identity creating the pause.
            notes: Optional notes about the pause.

        Returns:
            The created PauseEntry.

        Raises:
            ValueError: If scope format is invalid or duration exceeds maximum.
        """
        # Validate scope format
        if ":" not in scope:
            raise ValueError(
                f"Invalid scope format: {scope}. "
                "Expected 'type:value' (e.g., 'domain:firewall')"
            )

        scope_type, scope_value = scope.split(":", 1)
        valid_types = {"domain", "subscription", "management_group", "resource_group"}
        if scope_type.lower() not in valid_types:
            raise ValueError(
                f"Invalid scope type: {scope_type}. Must be one of {valid_types}"
            )

        if not scope_value.strip():
            raise ValueError("Scope value cannot be empty")

        # Validate and clamp duration
        if duration_seconds is None:
            duration_seconds = self._config.default_pause_duration_seconds

        if duration_seconds < MIN_PAUSE_DURATION_SECONDS:
            logger.warning(
                f"Pause duration {duration_seconds}s is below minimum "
                f"{MIN_PAUSE_DURATION_SECONDS}s, using minimum"
            )
            duration_seconds = MIN_PAUSE_DURATION_SECONDS

        if duration_seconds > self._config.max_pause_duration_seconds:
            logger.warning(
                f"Pause duration {duration_seconds}s exceeds maximum "
                f"{self._config.max_pause_duration_seconds}s, clamping"
            )
            duration_seconds = self._config.max_pause_duration_seconds

        # Validate reason
        if self._config.require_reason and reason == PauseReason.MANUAL and not notes:
            raise ValueError(
                "Pause reason or notes required when reason is MANUAL"
            )

        # Create pause entry
        now = datetime.now(UTC)
        entry = PauseEntry(
            scope=scope,
            reason=reason,
            started_at=now,
            expires_at=now + timedelta(seconds=duration_seconds),
            initiated_by=initiated_by,
            notes=notes,
            status=PauseStatus.ACTIVE,
        )

        # Store pause (overwrites any existing pause for same scope)
        old_pause = self._pauses.get(scope)
        if old_pause and old_pause.is_active():
            logger.warning(
                f"Overwriting active pause for {scope}",
                extra={"old_expires_at": old_pause.expires_at.isoformat()},
            )

        self._pauses[scope] = entry

        # Audit log
        self._log_audit(
            event_type="PAUSE_CREATED",
            scope=scope,
            identity=initiated_by,
            details={
                "reason": reason.value,
                "duration_seconds": duration_seconds,
                "expires_at": entry.expires_at.isoformat(),
                "notes": notes,
            },
        )

        logger.info(
            f"Pause created for {scope}",
            extra={
                "scope": scope,
                "reason": reason.value,
                "expires_at": entry.expires_at.isoformat(),
                "duration_seconds": duration_seconds,
            },
        )

        return entry

    def resume(
        self,
        scope: str,
        resumed_by: str = "unknown",
        notes: str = "",
    ) -> bool:
        """Manually resume a paused scope before expiry.

        Args:
            scope: The scope to resume.
            resumed_by: Identity resuming the pause.
            notes: Optional notes about the resume.

        Returns:
            True if pause was found and resumed, False if no active pause.
        """
        entry = self._pauses.get(scope)
        if entry is None or not entry.is_active():
            logger.warning(f"No active pause found for {scope}")
            return False

        # Update entry
        entry.status = PauseStatus.RESUMED
        entry.resumed_at = datetime.now(UTC)

        # Audit log
        self._log_audit(
            event_type="PAUSE_RESUMED",
            scope=scope,
            identity=resumed_by,
            details={
                "original_expires_at": entry.expires_at.isoformat(),
                "resumed_early_by_seconds": entry.remaining_seconds(),
                "notes": notes,
            },
        )

        logger.info(
            f"Pause resumed for {scope}",
            extra={
                "scope": scope,
                "resumed_by": resumed_by,
                "original_expires_at": entry.expires_at.isoformat(),
            },
        )

        return True

    def extend_pause(
        self,
        scope: str,
        additional_seconds: int,
        extended_by: str = "unknown",
        notes: str = "",
    ) -> PauseEntry | None:
        """Extend an active pause.

        Args:
            scope: The scope to extend.
            additional_seconds: How many seconds to add.
            extended_by: Identity extending the pause.
            notes: Optional notes.

        Returns:
            Updated PauseEntry, or None if no active pause.
        """
        entry = self._pauses.get(scope)
        if entry is None or not entry.is_active():
            logger.warning(f"No active pause found for {scope}")
            return None

        # Calculate new expiry (capped at max duration from original start)
        max_expiry = entry.started_at + timedelta(
            seconds=self._config.max_pause_duration_seconds
        )
        new_expiry = entry.expires_at + timedelta(seconds=additional_seconds)

        if new_expiry > max_expiry:
            logger.warning(
                f"Extension would exceed max duration, capping at {max_expiry}"
            )
            new_expiry = max_expiry

        old_expiry = entry.expires_at
        entry.expires_at = new_expiry

        # Audit log
        self._log_audit(
            event_type="PAUSE_EXTENDED",
            scope=scope,
            identity=extended_by,
            details={
                "old_expires_at": old_expiry.isoformat(),
                "new_expires_at": new_expiry.isoformat(),
                "additional_seconds": additional_seconds,
                "notes": notes,
            },
        )

        return entry

    def is_paused(self, scope_type: str, scope_value: str) -> bool:
        """Check if a scope is currently paused.

        This performs auto-expiry: if a pause has expired, it updates the
        status to EXPIRED before returning.

        Args:
            scope_type: The scope type (domain, subscription, etc.)
            scope_value: The scope value.

        Returns:
            True if scope is actively paused.
        """
        scope = f"{scope_type}:{scope_value}"
        entry = self._pauses.get(scope)

        if entry is None:
            return False

        if entry.status != PauseStatus.ACTIVE:
            return False

        # Check for auto-expiry
        now = datetime.now(UTC)
        if now >= entry.expires_at:
            # Auto-resume: pause has expired
            entry.status = PauseStatus.EXPIRED
            self._log_audit(
                event_type="PAUSE_EXPIRED",
                scope=scope,
                identity="system",
                details={"expired_at": entry.expires_at.isoformat()},
            )
            logger.info(
                f"Pause auto-expired for {scope}",
                extra={"scope": scope, "expired_at": entry.expires_at.isoformat()},
            )
            return False

        return True

    def get_pause(self, scope: str) -> PauseEntry | None:
        """Get pause entry for a scope, if any.

        Args:
            scope: The full scope string (e.g., "domain:firewall")

        Returns:
            PauseEntry if exists, None otherwise.
        """
        return self._pauses.get(scope)

    def get_active_pauses(self) -> list[PauseEntry]:
        """Get all currently active pauses.

        Returns:
            List of active pause entries.
        """
        active = []
        for entry in self._pauses.values():
            if entry.is_active():
                active.append(entry)
            elif entry.status == PauseStatus.ACTIVE:
                # Auto-expire
                entry.status = PauseStatus.EXPIRED
        return active

    def get_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent audit log entries.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of audit log entries, most recent first.
        """
        return list(reversed(self._audit_log[-limit:]))

    def clear_expired(self) -> int:
        """Clear expired pause entries from memory.

        Returns:
            Number of entries cleared.
        """
        now = datetime.now(UTC)
        expired_scopes = []

        for scope, entry in self._pauses.items():
            if entry.status != PauseStatus.ACTIVE:
                expired_scopes.append(scope)
            elif now >= entry.expires_at:
                entry.status = PauseStatus.EXPIRED
                expired_scopes.append(scope)

        # Keep entries for audit but could clean up after longer period
        return len(expired_scopes)

    def create_emergency_window(
        self,
        scope: str,
        duration_seconds: int,
        initiated_by: str,
        reason: str,
        ticket_id: str,
        approved_by: str,
    ) -> EmergencyWindow:
        """Create an emergency change window.

        Emergency windows allow temporary bypass of certain guardrails.
        They require:
        - A ticket ID (incident number)
        - Secondary approval
        - Short duration (max 1 hour)

        Args:
            scope: The scope for emergency changes.
            duration_seconds: Window duration (max 1 hour).
            initiated_by: Identity creating the window.
            reason: Why emergency access is needed.
            ticket_id: Incident ticket reference.
            approved_by: Secondary approver.

        Returns:
            The created EmergencyWindow.

        Raises:
            ValueError: If required fields are missing or duration exceeds max.
        """
        if not ticket_id.strip():
            raise ValueError("Emergency windows require a ticket ID")

        if not approved_by.strip():
            raise ValueError("Emergency windows require secondary approval")

        if duration_seconds > MAX_EMERGENCY_WINDOW_SECONDS:
            logger.warning(
                f"Emergency window duration {duration_seconds}s exceeds max "
                f"{MAX_EMERGENCY_WINDOW_SECONDS}s, clamping"
            )
            duration_seconds = MAX_EMERGENCY_WINDOW_SECONDS

        now = datetime.now(UTC)
        window = EmergencyWindow(
            scope=scope,
            started_at=now,
            expires_at=now + timedelta(seconds=duration_seconds),
            initiated_by=initiated_by,
            reason=reason,
            ticket_id=ticket_id,
            approved_by=approved_by,
        )

        self._emergency_windows[scope] = window

        # Audit log - CRITICAL event
        self._log_audit(
            event_type="EMERGENCY_WINDOW_CREATED",
            scope=scope,
            identity=initiated_by,
            details={
                "reason": reason,
                "ticket_id": ticket_id,
                "approved_by": approved_by,
                "duration_seconds": duration_seconds,
                "expires_at": window.expires_at.isoformat(),
            },
        )

        logger.warning(
            f"EMERGENCY WINDOW CREATED for {scope}",
            extra={
                "scope": scope,
                "ticket_id": ticket_id,
                "approved_by": approved_by,
                "expires_at": window.expires_at.isoformat(),
            },
        )

        return window

    def is_emergency_window_active(self, scope: str) -> bool:
        """Check if an emergency window is active for scope.

        Args:
            scope: The scope to check.

        Returns:
            True if emergency window is active.
        """
        window = self._emergency_windows.get(scope)
        if window is None:
            return False
        return window.is_active()

    def get_emergency_window(self, scope: str) -> EmergencyWindow | None:
        """Get emergency window for scope, if any."""
        return self._emergency_windows.get(scope)


def check_pause_with_manager(
    manager: PauseManager,
    domain: str,
    scope_type: str,
    scope_value: str,
) -> tuple[bool, PauseEntry | None]:
    """Check if scope is paused using PauseManager.

    This is a convenience function that checks multiple pause patterns:
    1. Direct domain pause (domain:X)
    2. Scope pause (subscription:X, management_group:X)

    Args:
        manager: The PauseManager instance.
        domain: Operator domain.
        scope_type: Scope type.
        scope_value: Scope value.

    Returns:
        Tuple of (is_paused, pause_entry).
    """
    # Check domain pause first
    if manager.is_paused("domain", domain):
        return True, manager.get_pause(f"domain:{domain}")

    # Check scope pause
    if manager.is_paused(scope_type, scope_value):
        return True, manager.get_pause(f"{scope_type}:{scope_value}")

    return False, None
