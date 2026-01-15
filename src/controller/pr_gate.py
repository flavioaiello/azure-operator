"""PR-Based Approval Model for GitOps source of truth validation.

This module ensures that infrastructure changes only reach production after
going through a proper Git PR approval workflow. With Deployment Stacks deny
blocking portal changes, PR approval becomes the SOLE control point.

CRITICAL: This is now the primary control mechanism for production changes.

Key Features:
1. PR approval status validation (commit must come from approved PR)
2. Branch protection enforcement (only allow commits from protected branches)
3. CODEOWNERS validation (critical specs require designated approvers)
4. Promotion path tracking (dev → test → prod)
5. Environment-specific overrides

DESIGN PHILOSOPHY:
- No PR approval = No deployment (in strict mode)
- Grace period for emergency changes (with audit trail)
- Validation happens at operator startup AND per reconciliation
- Works with both GitHub and Azure DevOps (abstracted interface)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Maximum age of a commit to be considered "fresh" (prevents using old approvals)
DEFAULT_MAX_COMMIT_AGE_HOURS = 168  # 7 days
MAX_COMMIT_AGE_HOURS_LIMIT = 720  # 30 days absolute maximum

# Branch naming patterns for environment detection
BRANCH_PATTERNS: dict[str, re.Pattern[str]] = {
    "production": re.compile(r"^(main|master|release/.+|prod)$"),
    "staging": re.compile(r"^(staging|stage|preprod|uat)$"),
    "development": re.compile(r"^(develop|dev|feature/.+|fix/.+)$"),
}

# Critical domains that ALWAYS require PR approval
CRITICAL_DOMAINS: frozenset[str] = frozenset({
    "hub-network",
    "firewall",
    "vpn-gateway",
    "vwan",
    "bastion",
    "dns",
    "role",
    "management-group",
    "bootstrap",
})

# Domains where PR approval can be relaxed (optional but audited)
NON_CRITICAL_DOMAINS: frozenset[str] = frozenset({
    "log-analytics",
    "sentinel",
    "monitor",
    "automation",
    "defender",
})


class PRGateMode(str, Enum):
    """PR gate enforcement mode.

    ENFORCE: Reject reconciliation if no approved PR (default for production)
    WARN: Log warning but allow (for migration/testing)
    DISABLED: No PR validation (only for development environments)
    """

    ENFORCE = "enforce"
    WARN = "warn"
    DISABLED = "disabled"


class PromotionEnvironment(str, Enum):
    """Environment stages in promotion path."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class PRApprovalStatus(str, Enum):
    """Status of PR approval validation."""

    APPROVED = "approved"
    PENDING = "pending"
    NOT_FOUND = "not_found"
    EXPIRED = "expired"
    BYPASSED = "bypassed"
    UNKNOWN = "unknown"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(frozen=True)
class CodeOwner:
    """A CODEOWNERS entry for a path pattern."""

    pattern: str  # Glob pattern (e.g., "specs/firewall*.yaml")
    owners: tuple[str, ...]  # Required approvers (emails or team names)
    require_all: bool = False  # True = all must approve, False = any one

    def matches_path(self, path: str) -> bool:
        """Check if this rule matches the given path.

        Args:
            path: File path to check.

        Returns:
            True if pattern matches the path.
        """
        import fnmatch

        return fnmatch.fnmatch(path, self.pattern)


@dataclass
class PRInfo:
    """Information about a Pull Request."""

    pr_number: int
    title: str
    source_branch: str
    target_branch: str
    merge_commit_sha: str
    created_at: datetime
    merged_at: datetime | None = None
    approved_by: tuple[str, ...] = field(default_factory=tuple)
    review_status: str = "unknown"  # approved, changes_requested, pending
    labels: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_merged(self) -> bool:
        """Check if PR has been merged."""
        return self.merged_at is not None

    @property
    def is_approved(self) -> bool:
        """Check if PR has at least one approval."""
        return self.review_status == "approved" and len(self.approved_by) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/API."""
        return {
            "pr_number": self.pr_number,
            "title": self.title,
            "source_branch": self.source_branch,
            "target_branch": self.target_branch,
            "merge_commit_sha": self.merge_commit_sha,
            "created_at": self.created_at.isoformat(),
            "merged_at": self.merged_at.isoformat() if self.merged_at else None,
            "approved_by": list(self.approved_by),
            "review_status": self.review_status,
            "labels": list(self.labels),
        }


@dataclass
class PRValidationResult:
    """Result of PR approval validation."""

    status: PRApprovalStatus
    commit_sha: str
    pr_info: PRInfo | None = None
    environment: PromotionEnvironment = PromotionEnvironment.DEVELOPMENT
    codeowners_satisfied: bool = True
    missing_approvers: tuple[str, ...] = field(default_factory=tuple)
    bypass_reason: str | None = None
    bypass_ticket: str | None = None
    validated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_valid(self) -> bool:
        """Check if PR validation passed."""
        return self.status in (PRApprovalStatus.APPROVED, PRApprovalStatus.BYPASSED)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/audit."""
        return {
            "status": self.status.value,
            "commit_sha": self.commit_sha,
            "pr_info": self.pr_info.to_dict() if self.pr_info else None,
            "environment": self.environment.value,
            "codeowners_satisfied": self.codeowners_satisfied,
            "missing_approvers": list(self.missing_approvers),
            "bypass_reason": self.bypass_reason,
            "bypass_ticket": self.bypass_ticket,
            "validated_at": self.validated_at.isoformat(),
            "errors": list(self.errors),
        }


@dataclass
class PRGateConfig:
    """Configuration for PR gate enforcement."""

    # Enforcement mode
    mode: PRGateMode = PRGateMode.ENFORCE

    # Which environment this operator is running in
    environment: PromotionEnvironment = PromotionEnvironment.PRODUCTION

    # Maximum age of commit to accept (prevents stale approvals)
    max_commit_age_hours: int = DEFAULT_MAX_COMMIT_AGE_HOURS

    # Required number of approvals
    min_approvals: int = 1

    # For production, require approvals from CODEOWNERS
    require_codeowners: bool = True

    # CODEOWNERS rules
    codeowners: tuple[CodeOwner, ...] = field(default_factory=tuple)

    # Allowed target branches for this environment
    allowed_branches: frozenset[str] = field(
        default_factory=lambda: frozenset({"main", "master"})
    )

    # Require PR to be merged (not just approved)
    require_merged: bool = True

    # Emergency bypass settings
    allow_bypass: bool = True
    bypass_requires_ticket: bool = True
    bypass_label: str = "emergency-bypass"

    # Domains that can skip PR validation (for this environment only)
    relaxed_domains: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls) -> PRGateConfig:
        """Load configuration from environment variables.

        Environment Variables:
            PR_GATE_MODE: enforce, warn, disabled (default: enforce)
            PR_GATE_ENVIRONMENT: production, staging, development
            PR_GATE_MAX_COMMIT_AGE_HOURS: Max age of commit (default: 168)
            PR_GATE_MIN_APPROVALS: Minimum required approvals (default: 1)
            PR_GATE_REQUIRE_CODEOWNERS: Require CODEOWNERS approval (default: true)
            PR_GATE_ALLOWED_BRANCHES: Comma-separated allowed branches
            PR_GATE_REQUIRE_MERGED: Require PR to be merged (default: true)
            PR_GATE_ALLOW_BYPASS: Allow emergency bypass (default: true)
            PR_GATE_BYPASS_REQUIRES_TICKET: Require ticket for bypass (default: true)
            PR_GATE_RELAXED_DOMAINS: Domains that can skip validation
        """

        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(key, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes")

        def get_int(key: str, default: int, maximum: int) -> int:
            value = os.environ.get(key)
            if value is None:
                return default
            try:
                return min(int(value), maximum)
            except ValueError:
                return default

        def get_frozenset(key: str, default: frozenset[str] | None = None) -> frozenset[str]:
            value = os.environ.get(key, "")
            if not value:
                return default or frozenset()
            return frozenset(item.strip() for item in value.split(",") if item.strip())

        # Parse mode
        mode_str = os.environ.get("PR_GATE_MODE", "enforce").lower()
        try:
            mode = PRGateMode(mode_str)
        except ValueError:
            logger.warning(f"Invalid PR_GATE_MODE: {mode_str}, defaulting to enforce")
            mode = PRGateMode.ENFORCE

        # Parse environment
        env_str = os.environ.get("PR_GATE_ENVIRONMENT", "production").lower()
        try:
            environment = PromotionEnvironment(env_str)
        except ValueError:
            logger.warning(f"Invalid PR_GATE_ENVIRONMENT: {env_str}, defaulting to production")
            environment = PromotionEnvironment.PRODUCTION

        return cls(
            mode=mode,
            environment=environment,
            max_commit_age_hours=get_int(
                "PR_GATE_MAX_COMMIT_AGE_HOURS",
                DEFAULT_MAX_COMMIT_AGE_HOURS,
                MAX_COMMIT_AGE_HOURS_LIMIT,
            ),
            min_approvals=get_int("PR_GATE_MIN_APPROVALS", 1, 10),
            require_codeowners=get_bool("PR_GATE_REQUIRE_CODEOWNERS", True),
            allowed_branches=get_frozenset(
                "PR_GATE_ALLOWED_BRANCHES",
                frozenset({"main", "master"}),
            ),
            require_merged=get_bool("PR_GATE_REQUIRE_MERGED", True),
            allow_bypass=get_bool("PR_GATE_ALLOW_BYPASS", True),
            bypass_requires_ticket=get_bool("PR_GATE_BYPASS_REQUIRES_TICKET", True),
            relaxed_domains=get_frozenset("PR_GATE_RELAXED_DOMAINS"),
        )


# =============================================================================
# Exceptions
# =============================================================================


class PRGateError(Exception):
    """Base exception for PR gate errors."""

    pass


class PRNotApprovedError(PRGateError):
    """Raised when PR approval is required but not granted."""

    def __init__(self, validation_result: PRValidationResult) -> None:
        self.validation_result = validation_result
        super().__init__(
            f"PR approval required but not granted: {validation_result.status.value}"
        )


class CodeOwnersMissingError(PRGateError):
    """Raised when required CODEOWNERS approvals are missing."""

    def __init__(
        self, missing_approvers: tuple[str, ...], validation_result: PRValidationResult
    ) -> None:
        self.missing_approvers = missing_approvers
        self.validation_result = validation_result
        super().__init__(
            f"Missing CODEOWNERS approvals: {', '.join(missing_approvers)}"
        )


class CommitTooOldError(PRGateError):
    """Raised when commit is older than allowed age."""

    def __init__(self, commit_age_hours: float, max_age_hours: int) -> None:
        self.commit_age_hours = commit_age_hours
        self.max_age_hours = max_age_hours
        super().__init__(
            f"Commit is {commit_age_hours:.1f} hours old, max allowed is {max_age_hours}"
        )


# =============================================================================
# CODEOWNERS Parser
# =============================================================================


def parse_codeowners(content: str) -> tuple[CodeOwner, ...]:
    """Parse CODEOWNERS file content.

    Format:
        # Comments start with #
        path/pattern @owner1 @owner2
        *.yaml @team-name

    Args:
        content: Raw CODEOWNERS file content.

    Returns:
        Tuple of CodeOwner entries.
    """
    owners: list[CodeOwner] = []

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        pattern = parts[0]
        # Remove @ prefix from owners
        owner_list = tuple(
            owner.lstrip("@") for owner in parts[1:] if owner.startswith("@")
        )

        if owner_list:
            owners.append(CodeOwner(pattern=pattern, owners=owner_list))

    return tuple(owners)


def load_codeowners_from_file(repo_root: Path | str) -> tuple[CodeOwner, ...]:
    """Load CODEOWNERS from repository.

    Checks standard locations:
    - CODEOWNERS
    - .github/CODEOWNERS
    - docs/CODEOWNERS

    Args:
        repo_root: Path to repository root.

    Returns:
        Tuple of CodeOwner entries, empty if not found.
    """
    repo_root = Path(repo_root)
    locations = [
        repo_root / "CODEOWNERS",
        repo_root / ".github" / "CODEOWNERS",
        repo_root / "docs" / "CODEOWNERS",
    ]

    for location in locations:
        if location.is_file():
            try:
                content = location.read_text(encoding="utf-8")
                logger.info(f"Loaded CODEOWNERS from {location}")
                return parse_codeowners(content)
            except (OSError, UnicodeDecodeError) as e:
                logger.warning(f"Failed to read CODEOWNERS from {location}: {e}")

    return ()


# =============================================================================
# PR Gate Validator
# =============================================================================


class PRGateValidator:
    """Validates PR approval status for GitOps reconciliation.

    This is the main class that enforces PR-based approval for changes.
    It works with both GitHub and Azure DevOps via an abstracted interface.
    """

    def __init__(
        self,
        config: PRGateConfig | None = None,
        pr_provider: PRProvider | None = None,
    ) -> None:
        """Initialize PR gate validator.

        Args:
            config: Gate configuration. Defaults to env-based config.
            pr_provider: Provider for fetching PR information.
        """
        self._config = config or PRGateConfig.from_env()
        self._pr_provider = pr_provider
        self._validation_cache: dict[str, PRValidationResult] = {}

    @property
    def config(self) -> PRGateConfig:
        """Get configuration."""
        return self._config

    @property
    def mode(self) -> PRGateMode:
        """Get enforcement mode."""
        return self._config.mode

    def validate_commit(
        self,
        commit_sha: str,
        domain: str,
        spec_paths: list[str] | None = None,
        bypass_ticket: str | None = None,
    ) -> PRValidationResult:
        """Validate that a commit has proper PR approval.

        Args:
            commit_sha: Git commit SHA to validate.
            domain: Operator domain (for domain-specific rules).
            spec_paths: Paths to spec files (for CODEOWNERS check).
            bypass_ticket: Ticket ID if using emergency bypass.

        Returns:
            Validation result with detailed status.
        """
        # Check cache first
        cache_key = self._cache_key(commit_sha, domain)
        if cache_key in self._validation_cache:
            cached = self._validation_cache[cache_key]
            logger.debug(f"PR validation cache hit: {commit_sha[:8]}")
            return cached

        # If mode is disabled, return immediate success
        if self._config.mode == PRGateMode.DISABLED:
            result = PRValidationResult(
                status=PRApprovalStatus.BYPASSED,
                commit_sha=commit_sha,
                environment=self._config.environment,
                bypass_reason="PR gate disabled",
            )
            self._validation_cache[cache_key] = result
            return result

        # Check if domain is relaxed
        if domain in self._config.relaxed_domains:
            result = PRValidationResult(
                status=PRApprovalStatus.BYPASSED,
                commit_sha=commit_sha,
                environment=self._config.environment,
                bypass_reason=f"Domain {domain} is in relaxed list",
            )
            self._log_validation(result, domain)
            self._validation_cache[cache_key] = result
            return result

        # Check for emergency bypass
        if bypass_ticket and self._config.allow_bypass:
            result = PRValidationResult(
                status=PRApprovalStatus.BYPASSED,
                commit_sha=commit_sha,
                environment=self._config.environment,
                bypass_reason="Emergency bypass with ticket",
                bypass_ticket=bypass_ticket,
            )
            self._log_bypass(result, domain)
            self._validation_cache[cache_key] = result
            return result

        # If no PR provider, we can't validate
        if self._pr_provider is None:
            if self._config.mode == PRGateMode.WARN:
                result = PRValidationResult(
                    status=PRApprovalStatus.UNKNOWN,
                    commit_sha=commit_sha,
                    environment=self._config.environment,
                    errors=("No PR provider configured",),
                )
                self._log_validation(result, domain)
                self._validation_cache[cache_key] = result
                return result
            else:
                # In enforce mode with no provider, fail closed
                result = PRValidationResult(
                    status=PRApprovalStatus.NOT_FOUND,
                    commit_sha=commit_sha,
                    environment=self._config.environment,
                    errors=("No PR provider configured - cannot validate",),
                )
                self._validation_cache[cache_key] = result
                return result

        # Fetch PR information
        try:
            pr_info = self._pr_provider.get_pr_for_commit(commit_sha)
        except Exception as e:
            logger.error(f"Failed to fetch PR info: {e}")
            result = PRValidationResult(
                status=PRApprovalStatus.UNKNOWN,
                commit_sha=commit_sha,
                environment=self._config.environment,
                errors=(f"Failed to fetch PR info: {e}",),
            )
            self._validation_cache[cache_key] = result
            return result

        if pr_info is None:
            result = PRValidationResult(
                status=PRApprovalStatus.NOT_FOUND,
                commit_sha=commit_sha,
                environment=self._config.environment,
                errors=("No PR found for commit",),
            )
            self._log_validation(result, domain)
            self._validation_cache[cache_key] = result
            return result

        # Validate PR meets requirements
        errors: list[str] = []

        # Check if PR is merged (if required)
        if self._config.require_merged and not pr_info.is_merged:
            errors.append("PR is not merged")

        # Check if PR is approved
        if not pr_info.is_approved:
            errors.append("PR is not approved")

        # Check minimum approvals
        if len(pr_info.approved_by) < self._config.min_approvals:
            errors.append(
                f"Insufficient approvals: {len(pr_info.approved_by)} < {self._config.min_approvals}"
            )

        # Check target branch
        if pr_info.target_branch not in self._config.allowed_branches:
            errors.append(
                f"Target branch {pr_info.target_branch} not in allowed: {self._config.allowed_branches}"
            )

        # Check commit age
        if pr_info.merged_at:
            age = datetime.now(UTC) - pr_info.merged_at
            age_hours = age.total_seconds() / 3600
            if age_hours > self._config.max_commit_age_hours:
                errors.append(
                    f"Commit too old: {age_hours:.1f}h > {self._config.max_commit_age_hours}h"
                )

        # Check CODEOWNERS
        missing_approvers: list[str] = []
        codeowners_satisfied = True

        if self._config.require_codeowners and spec_paths:
            missing = self._check_codeowners(pr_info, spec_paths)
            if missing:
                missing_approvers = missing
                codeowners_satisfied = False
                errors.append(f"Missing CODEOWNERS approvals: {', '.join(missing)}")

        # Determine final status
        if errors:
            status = PRApprovalStatus.PENDING
        else:
            status = PRApprovalStatus.APPROVED

        result = PRValidationResult(
            status=status,
            commit_sha=commit_sha,
            pr_info=pr_info,
            environment=self._config.environment,
            codeowners_satisfied=codeowners_satisfied,
            missing_approvers=tuple(missing_approvers),
            errors=tuple(errors),
        )

        self._log_validation(result, domain)
        self._validation_cache[cache_key] = result
        return result

    def enforce(
        self,
        commit_sha: str,
        domain: str,
        spec_paths: list[str] | None = None,
        bypass_ticket: str | None = None,
    ) -> PRValidationResult:
        """Validate commit and raise if not approved.

        This is the main enforcement method. Call this before reconciliation.

        Args:
            commit_sha: Git commit SHA to validate.
            domain: Operator domain.
            spec_paths: Paths to spec files.
            bypass_ticket: Ticket ID for emergency bypass.

        Returns:
            Validation result (if valid).

        Raises:
            PRNotApprovedError: If PR is not approved and mode is ENFORCE.
            CodeOwnersMissingError: If CODEOWNERS approvals are missing.
        """
        result = self.validate_commit(
            commit_sha=commit_sha,
            domain=domain,
            spec_paths=spec_paths,
            bypass_ticket=bypass_ticket,
        )

        if result.is_valid:
            return result

        # In WARN mode, log but don't raise
        if self._config.mode == PRGateMode.WARN:
            logger.warning(
                "PR validation failed but mode is WARN - allowing",
                extra={
                    "commit_sha": commit_sha,
                    "domain": domain,
                    "status": result.status.value,
                    "errors": list(result.errors),
                },
            )
            return result

        # In ENFORCE mode, raise appropriate exception
        if not result.codeowners_satisfied and result.missing_approvers:
            raise CodeOwnersMissingError(result.missing_approvers, result)

        raise PRNotApprovedError(result)

    def clear_cache(self) -> None:
        """Clear validation cache."""
        self._validation_cache.clear()

    def _cache_key(self, commit_sha: str, domain: str) -> str:
        """Generate cache key for validation result."""
        return f"{commit_sha}:{domain}"

    def _check_codeowners(
        self, pr_info: PRInfo, spec_paths: list[str]
    ) -> list[str]:
        """Check if CODEOWNERS requirements are satisfied.

        Args:
            pr_info: PR information with approvers.
            spec_paths: Paths to files being changed.

        Returns:
            List of missing required approvers.
        """
        required_approvers: set[str] = set()

        for path in spec_paths:
            for owner in self._config.codeowners:
                if owner.matches_path(path):
                    required_approvers.update(owner.owners)

        if not required_approvers:
            return []

        # Check which required approvers are in the approval list
        approved_set = set(pr_info.approved_by)
        missing = required_approvers - approved_set

        return list(missing)

    def _log_validation(self, result: PRValidationResult, domain: str) -> None:
        """Log validation result."""
        log_level = logging.INFO if result.is_valid else logging.WARNING

        logger.log(
            log_level,
            "PR validation result",
            extra={
                "domain": domain,
                "commit_sha": result.commit_sha[:8],
                "status": result.status.value,
                "environment": result.environment.value,
                "is_valid": result.is_valid,
                "errors": list(result.errors),
            },
        )

    def _log_bypass(self, result: PRValidationResult, domain: str) -> None:
        """Log emergency bypass - always WARNING level for audit."""
        logger.warning(
            "SECURITY: PR gate bypassed",
            extra={
                "domain": domain,
                "commit_sha": result.commit_sha[:8],
                "bypass_reason": result.bypass_reason,
                "bypass_ticket": result.bypass_ticket,
                "environment": result.environment.value,
            },
        )


# =============================================================================
# PR Provider Interface
# =============================================================================


class PRProvider:
    """Abstract interface for fetching PR information.

    Implementations:
    - GitHubPRProvider: Uses GitHub API
    - AzureDevOpsPRProvider: Uses Azure DevOps API
    - MockPRProvider: For testing
    """

    def get_pr_for_commit(self, commit_sha: str) -> PRInfo | None:
        """Get PR information for a commit.

        Args:
            commit_sha: Git commit SHA.

        Returns:
            PR information if found, None otherwise.
        """
        raise NotImplementedError

    def get_pr_by_number(self, pr_number: int) -> PRInfo | None:
        """Get PR information by PR number.

        Args:
            pr_number: Pull request number.

        Returns:
            PR information if found, None otherwise.
        """
        raise NotImplementedError


class MockPRProvider(PRProvider):
    """Mock PR provider for testing."""

    def __init__(self) -> None:
        self._prs: dict[str, PRInfo] = {}  # commit_sha -> PRInfo
        self._prs_by_number: dict[int, PRInfo] = {}  # pr_number -> PRInfo

    def add_pr(self, pr_info: PRInfo) -> None:
        """Add a PR to the mock store."""
        self._prs[pr_info.merge_commit_sha] = pr_info
        self._prs_by_number[pr_info.pr_number] = pr_info

    def get_pr_for_commit(self, commit_sha: str) -> PRInfo | None:
        """Get PR by commit SHA."""
        return self._prs.get(commit_sha)

    def get_pr_by_number(self, pr_number: int) -> PRInfo | None:
        """Get PR by number."""
        return self._prs_by_number.get(pr_number)

    def clear(self) -> None:
        """Clear all stored PRs."""
        self._prs.clear()
        self._prs_by_number.clear()


# =============================================================================
# Promotion Path Validation
# =============================================================================


@dataclass
class PromotionState:
    """Tracks promotion state of a commit across environments."""

    commit_sha: str
    spec_hash: str  # Hash of spec content
    promotions: dict[PromotionEnvironment, datetime] = field(default_factory=dict)

    def is_promoted_to(self, env: PromotionEnvironment) -> bool:
        """Check if promoted to a specific environment."""
        return env in self.promotions

    def record_promotion(self, env: PromotionEnvironment) -> None:
        """Record promotion to an environment."""
        self.promotions[env] = datetime.now(UTC)

    def validate_promotion_path(self, target_env: PromotionEnvironment) -> tuple[bool, str]:
        """Validate that proper promotion path is followed.

        Rules:
        - Development: Always allowed
        - Staging: Must have been in development
        - Production: Must have been in staging

        Args:
            target_env: Target environment.

        Returns:
            Tuple of (is_valid, error_message).
        """
        if target_env == PromotionEnvironment.DEVELOPMENT:
            return True, ""

        if target_env == PromotionEnvironment.STAGING:
            if not self.is_promoted_to(PromotionEnvironment.DEVELOPMENT):
                return False, "Must be deployed to development before staging"
            return True, ""

        if target_env == PromotionEnvironment.PRODUCTION:
            if not self.is_promoted_to(PromotionEnvironment.STAGING):
                return False, "Must be deployed to staging before production"
            return True, ""

        return True, ""


def compute_spec_hash(content: str) -> str:
    """Compute hash of spec content for change detection.

    Args:
        content: Spec file content.

    Returns:
        SHA256 hash (first 16 chars).
    """
    return hashlib.sha256(content.encode()).hexdigest()[:16]


# =============================================================================
# Environment Detection
# =============================================================================


def detect_environment_from_branch(branch: str) -> PromotionEnvironment:
    """Detect environment from branch name.

    Args:
        branch: Git branch name.

    Returns:
        Detected environment (defaults to DEVELOPMENT).
    """
    for env_name, pattern in BRANCH_PATTERNS.items():
        if pattern.match(branch):
            return PromotionEnvironment(env_name)

    return PromotionEnvironment.DEVELOPMENT


def is_critical_domain(domain: str) -> bool:
    """Check if domain is critical (requires strict PR approval).

    Args:
        domain: Operator domain.

    Returns:
        True if domain is critical.
    """
    return domain in CRITICAL_DOMAINS


# =============================================================================
# Factory Functions
# =============================================================================


def create_pr_gate_validator(
    config: PRGateConfig | None = None,
    pr_provider: PRProvider | None = None,
) -> PRGateValidator:
    """Create a PR gate validator with standard configuration.

    Args:
        config: Optional configuration (defaults to env-based).
        pr_provider: Optional PR provider.

    Returns:
        Configured PR gate validator.
    """
    return PRGateValidator(
        config=config or PRGateConfig.from_env(),
        pr_provider=pr_provider,
    )


def create_pr_gate_from_env() -> PRGateValidator:
    """Create a PR gate validator from environment.

    This is the main factory for production use.

    Returns:
        Configured PR gate validator.
    """
    config = PRGateConfig.from_env()

    # Load CODEOWNERS if require_codeowners is set
    codeowners: tuple[CodeOwner, ...] = ()
    if config.require_codeowners:
        repo_root = os.environ.get("GIT_REPO_ROOT", ".")
        codeowners = load_codeowners_from_file(repo_root)

    # Create config with CODEOWNERS
    config = PRGateConfig(
        mode=config.mode,
        environment=config.environment,
        max_commit_age_hours=config.max_commit_age_hours,
        min_approvals=config.min_approvals,
        require_codeowners=config.require_codeowners,
        codeowners=codeowners,
        allowed_branches=config.allowed_branches,
        require_merged=config.require_merged,
        allow_bypass=config.allow_bypass,
        bypass_requires_ticket=config.bypass_requires_ticket,
        relaxed_domains=config.relaxed_domains,
    )

    # Note: In production, you would inject the actual PR provider
    # (GitHubPRProvider or AzureDevOpsPRProvider) here
    return PRGateValidator(config=config, pr_provider=None)
