"""Tests for PR-based approval gate (pr_gate.py).

Tests cover:
1. PRGateConfig from environment
2. CODEOWNERS parsing
3. PRGateValidator - approval validation
4. PRGateValidator - CODEOWNERS enforcement
5. PRGateValidator - bypass handling
6. Promotion path validation
7. Environment detection
8. Error conditions
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from controller.pr_gate import (
    CRITICAL_DOMAINS,
    CodeOwner,
    CodeOwnersMissingError,
    CommitTooOldError,
    MockPRProvider,
    PRApprovalStatus,
    PRGateConfig,
    PRGateMode,
    PRGateValidator,
    PRInfo,
    PRNotApprovedError,
    PRValidationResult,
    PromotionEnvironment,
    PromotionState,
    compute_spec_hash,
    create_pr_gate_validator,
    detect_environment_from_branch,
    is_critical_domain,
    load_codeowners_from_file,
    parse_codeowners,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_provider() -> MockPRProvider:
    """Create a mock PR provider."""
    return MockPRProvider()


@pytest.fixture
def approved_pr() -> PRInfo:
    """Create an approved and merged PR."""
    return PRInfo(
        pr_number=42,
        title="Add hub-network configuration",
        source_branch="feature/hub-network",
        target_branch="main",
        merge_commit_sha="abc123def456",
        created_at=datetime.now(UTC) - timedelta(hours=2),
        merged_at=datetime.now(UTC) - timedelta(hours=1),
        approved_by=("reviewer1@example.com", "reviewer2@example.com"),
        review_status="approved",
        labels=("infrastructure", "approved"),
    )


@pytest.fixture
def pending_pr() -> PRInfo:
    """Create a PR pending approval."""
    return PRInfo(
        pr_number=43,
        title="Update firewall rules",
        source_branch="feature/firewall-update",
        target_branch="main",
        merge_commit_sha="def456ghi789",
        created_at=datetime.now(UTC) - timedelta(hours=1),
        merged_at=None,
        approved_by=(),
        review_status="pending",
        labels=(),
    )


@pytest.fixture
def basic_config() -> PRGateConfig:
    """Create a basic config for testing."""
    return PRGateConfig(
        mode=PRGateMode.ENFORCE,
        environment=PromotionEnvironment.PRODUCTION,
        min_approvals=1,
        require_codeowners=False,
        allowed_branches=frozenset({"main", "master"}),
    )


# =============================================================================
# PRGateConfig Tests
# =============================================================================


class TestPRGateConfig:
    """Tests for PRGateConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = PRGateConfig()
        assert config.mode == PRGateMode.ENFORCE
        assert config.environment == PromotionEnvironment.PRODUCTION
        assert config.min_approvals == 1
        assert config.require_codeowners is True
        assert config.require_merged is True
        assert config.allow_bypass is True
        assert config.bypass_requires_ticket is True
        assert "main" in config.allowed_branches

    def test_from_env_enforce_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading ENFORCE mode from environment."""
        monkeypatch.setenv("PR_GATE_MODE", "enforce")
        monkeypatch.setenv("PR_GATE_ENVIRONMENT", "production")
        config = PRGateConfig.from_env()
        assert config.mode == PRGateMode.ENFORCE
        assert config.environment == PromotionEnvironment.PRODUCTION

    def test_from_env_warn_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading WARN mode from environment."""
        monkeypatch.setenv("PR_GATE_MODE", "warn")
        monkeypatch.setenv("PR_GATE_ENVIRONMENT", "staging")
        config = PRGateConfig.from_env()
        assert config.mode == PRGateMode.WARN
        assert config.environment == PromotionEnvironment.STAGING

    def test_from_env_disabled_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading DISABLED mode from environment."""
        monkeypatch.setenv("PR_GATE_MODE", "disabled")
        monkeypatch.setenv("PR_GATE_ENVIRONMENT", "development")
        config = PRGateConfig.from_env()
        assert config.mode == PRGateMode.DISABLED
        assert config.environment == PromotionEnvironment.DEVELOPMENT

    def test_from_env_invalid_mode_defaults_to_enforce(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that invalid mode defaults to enforce."""
        monkeypatch.setenv("PR_GATE_MODE", "invalid")
        config = PRGateConfig.from_env()
        assert config.mode == PRGateMode.ENFORCE

    def test_from_env_min_approvals(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test min approvals configuration."""
        monkeypatch.setenv("PR_GATE_MIN_APPROVALS", "2")
        config = PRGateConfig.from_env()
        assert config.min_approvals == 2

    def test_from_env_max_commit_age_clamped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test max commit age is clamped to limit."""
        monkeypatch.setenv("PR_GATE_MAX_COMMIT_AGE_HOURS", "9999")
        config = PRGateConfig.from_env()
        assert config.max_commit_age_hours == 720  # MAX_COMMIT_AGE_HOURS_LIMIT

    def test_from_env_allowed_branches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test allowed branches from comma-separated list."""
        monkeypatch.setenv("PR_GATE_ALLOWED_BRANCHES", "main,release/v1,prod")
        config = PRGateConfig.from_env()
        assert config.allowed_branches == frozenset({"main", "release/v1", "prod"})

    def test_from_env_relaxed_domains(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test relaxed domains configuration."""
        monkeypatch.setenv("PR_GATE_RELAXED_DOMAINS", "log-analytics,monitor")
        config = PRGateConfig.from_env()
        assert "log-analytics" in config.relaxed_domains
        assert "monitor" in config.relaxed_domains

    def test_from_env_boolean_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test boolean environment variable parsing."""
        monkeypatch.setenv("PR_GATE_REQUIRE_CODEOWNERS", "false")
        monkeypatch.setenv("PR_GATE_ALLOW_BYPASS", "0")
        monkeypatch.setenv("PR_GATE_REQUIRE_MERGED", "no")
        config = PRGateConfig.from_env()
        assert config.require_codeowners is False
        assert config.allow_bypass is False
        assert config.require_merged is False


# =============================================================================
# CODEOWNERS Tests
# =============================================================================


class TestCodeOwners:
    """Tests for CODEOWNERS parsing and matching."""

    def test_parse_simple_codeowners(self) -> None:
        """Test parsing simple CODEOWNERS content."""
        content = """
# CODEOWNERS for azure-operator

*.yaml @infra-team
specs/firewall*.yaml @security-team @network-team
specs/role.yaml @iam-team
"""
        owners = parse_codeowners(content)
        assert len(owners) == 3
        assert owners[0].pattern == "*.yaml"
        assert owners[0].owners == ("infra-team",)
        assert owners[1].pattern == "specs/firewall*.yaml"
        assert owners[1].owners == ("security-team", "network-team")
        assert owners[2].pattern == "specs/role.yaml"
        assert owners[2].owners == ("iam-team",)

    def test_parse_codeowners_with_emails(self) -> None:
        """Test parsing CODEOWNERS with email addresses."""
        content = """
*.yaml @alice@example.com @bob@example.com
"""
        owners = parse_codeowners(content)
        assert len(owners) == 1
        assert owners[0].owners == ("alice@example.com", "bob@example.com")

    def test_parse_codeowners_ignores_comments(self) -> None:
        """Test that comments are ignored."""
        content = """
# This is a comment
*.yaml @team1
# Another comment
# specs/*.yaml @ignored
"""
        owners = parse_codeowners(content)
        assert len(owners) == 1

    def test_parse_codeowners_empty_file(self) -> None:
        """Test parsing empty CODEOWNERS file."""
        owners = parse_codeowners("")
        assert len(owners) == 0

    def test_parse_codeowners_malformed_lines(self) -> None:
        """Test that malformed lines are skipped."""
        content = """
*.yaml @team1
invalid line without owner
another bad line
specs/*.yaml @team2
"""
        owners = parse_codeowners(content)
        assert len(owners) == 2

    def test_codeowner_matches_exact_path(self) -> None:
        """Test exact path matching."""
        owner = CodeOwner(pattern="specs/firewall.yaml", owners=("team1",))
        assert owner.matches_path("specs/firewall.yaml") is True
        assert owner.matches_path("specs/hub-network.yaml") is False

    def test_codeowner_matches_glob_pattern(self) -> None:
        """Test glob pattern matching."""
        owner = CodeOwner(pattern="specs/firewall*.yaml", owners=("team1",))
        assert owner.matches_path("specs/firewall.yaml") is True
        assert owner.matches_path("specs/firewall-secondary.yaml") is True
        assert owner.matches_path("specs/hub-network.yaml") is False

    def test_codeowner_matches_wildcard(self) -> None:
        """Test wildcard matching."""
        owner = CodeOwner(pattern="*.yaml", owners=("team1",))
        assert owner.matches_path("firewall.yaml") is True
        assert owner.matches_path("hub-network.yaml") is True
        assert owner.matches_path("firewall.json") is False

    def test_load_codeowners_not_found(self, tmp_path: Path) -> None:
        """Test loading from repo without CODEOWNERS."""
        owners = load_codeowners_from_file(tmp_path)
        assert len(owners) == 0

    def test_load_codeowners_from_root(self, tmp_path: Path) -> None:
        """Test loading CODEOWNERS from repo root."""
        codeowners = tmp_path / "CODEOWNERS"
        codeowners.write_text("*.yaml @team1\n")
        owners = load_codeowners_from_file(tmp_path)
        assert len(owners) == 1

    def test_load_codeowners_from_github_dir(self, tmp_path: Path) -> None:
        """Test loading CODEOWNERS from .github directory."""
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        codeowners = github_dir / "CODEOWNERS"
        codeowners.write_text("*.yaml @team2\n")
        owners = load_codeowners_from_file(tmp_path)
        assert len(owners) == 1
        assert owners[0].owners == ("team2",)


# =============================================================================
# PRInfo Tests
# =============================================================================


class TestPRInfo:
    """Tests for PRInfo data class."""

    def test_pr_is_merged(self, approved_pr: PRInfo) -> None:
        """Test is_merged property."""
        assert approved_pr.is_merged is True

    def test_pr_not_merged(self, pending_pr: PRInfo) -> None:
        """Test is_merged when not merged."""
        assert pending_pr.is_merged is False

    def test_pr_is_approved(self, approved_pr: PRInfo) -> None:
        """Test is_approved property."""
        assert approved_pr.is_approved is True

    def test_pr_not_approved(self, pending_pr: PRInfo) -> None:
        """Test is_approved when pending."""
        assert pending_pr.is_approved is False

    def test_pr_to_dict(self, approved_pr: PRInfo) -> None:
        """Test serialization to dict."""
        d = approved_pr.to_dict()
        assert d["pr_number"] == 42
        assert d["title"] == "Add hub-network configuration"
        assert d["approved_by"] == ["reviewer1@example.com", "reviewer2@example.com"]
        assert d["review_status"] == "approved"


# =============================================================================
# PRGateValidator Tests
# =============================================================================


class TestPRGateValidatorDisabled:
    """Tests for PRGateValidator in DISABLED mode."""

    def test_disabled_mode_always_bypassed(self) -> None:
        """Test that DISABLED mode bypasses all validation."""
        config = PRGateConfig(mode=PRGateMode.DISABLED)
        validator = PRGateValidator(config=config)
        result = validator.validate_commit("anysha123", "firewall")
        assert result.status == PRApprovalStatus.BYPASSED
        assert result.is_valid is True
        assert "disabled" in (result.bypass_reason or "").lower()


class TestPRGateValidatorRelaxedDomains:
    """Tests for relaxed domain handling."""

    def test_relaxed_domain_bypassed(self) -> None:
        """Test that relaxed domains bypass validation."""
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            relaxed_domains=frozenset({"log-analytics", "monitor"}),
        )
        validator = PRGateValidator(config=config)
        result = validator.validate_commit("anysha123", "log-analytics")
        assert result.status == PRApprovalStatus.BYPASSED
        assert result.is_valid is True

    def test_non_relaxed_domain_not_bypassed(
        self, mock_provider: MockPRProvider
    ) -> None:
        """Test that non-relaxed domains are not bypassed."""
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            relaxed_domains=frozenset({"log-analytics"}),
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        result = validator.validate_commit("anysha123", "firewall")
        assert result.status == PRApprovalStatus.NOT_FOUND  # No PR in mock


class TestPRGateValidatorEmergencyBypass:
    """Tests for emergency bypass handling."""

    def test_emergency_bypass_with_ticket(self) -> None:
        """Test emergency bypass with ticket ID."""
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            allow_bypass=True,
            bypass_requires_ticket=True,
        )
        validator = PRGateValidator(config=config)
        result = validator.validate_commit(
            "anysha123", "firewall", bypass_ticket="INC-12345"
        )
        assert result.status == PRApprovalStatus.BYPASSED
        assert result.is_valid is True
        assert result.bypass_ticket == "INC-12345"

    def test_emergency_bypass_disabled(self, mock_provider: MockPRProvider) -> None:
        """Test that bypass fails when disabled."""
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            allow_bypass=False,
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        result = validator.validate_commit(
            "anysha123", "firewall", bypass_ticket="INC-12345"
        )
        # Bypass not allowed, so normal validation applies
        assert result.status == PRApprovalStatus.NOT_FOUND


class TestPRGateValidatorNoProvider:
    """Tests for PRGateValidator without PR provider."""

    def test_no_provider_warn_mode_returns_unknown(self) -> None:
        """Test that WARN mode without provider returns UNKNOWN."""
        config = PRGateConfig(mode=PRGateMode.WARN)
        validator = PRGateValidator(config=config, pr_provider=None)
        result = validator.validate_commit("anysha123", "firewall")
        assert result.status == PRApprovalStatus.UNKNOWN
        assert "No PR provider" in result.errors[0]

    def test_no_provider_enforce_mode_fails_closed(self) -> None:
        """Test that ENFORCE mode without provider fails closed."""
        config = PRGateConfig(mode=PRGateMode.ENFORCE)
        validator = PRGateValidator(config=config, pr_provider=None)
        result = validator.validate_commit("anysha123", "firewall")
        assert result.status == PRApprovalStatus.NOT_FOUND
        assert result.is_valid is False


class TestPRGateValidatorWithProvider:
    """Tests for PRGateValidator with mock PR provider."""

    def test_approved_pr_validates(
        self,
        mock_provider: MockPRProvider,
        approved_pr: PRInfo,
        basic_config: PRGateConfig,
    ) -> None:
        """Test that approved and merged PR validates successfully."""
        mock_provider.add_pr(approved_pr)
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)
        result = validator.validate_commit(approved_pr.merge_commit_sha, "hub-network")
        assert result.status == PRApprovalStatus.APPROVED
        assert result.is_valid is True
        assert result.pr_info is not None
        assert result.pr_info.pr_number == 42

    def test_pending_pr_not_approved(
        self,
        mock_provider: MockPRProvider,
        pending_pr: PRInfo,
        basic_config: PRGateConfig,
    ) -> None:
        """Test that pending PR does not validate."""
        mock_provider.add_pr(pending_pr)
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)
        result = validator.validate_commit(pending_pr.merge_commit_sha, "firewall")
        assert result.status == PRApprovalStatus.PENDING
        assert result.is_valid is False
        assert "not merged" in str(result.errors).lower()

    def test_commit_not_found(
        self, mock_provider: MockPRProvider, basic_config: PRGateConfig
    ) -> None:
        """Test commit with no associated PR."""
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)
        result = validator.validate_commit("unknown123", "firewall")
        assert result.status == PRApprovalStatus.NOT_FOUND
        assert result.is_valid is False

    def test_insufficient_approvals(
        self, mock_provider: MockPRProvider
    ) -> None:
        """Test PR with insufficient approvals."""
        pr = PRInfo(
            pr_number=44,
            title="Single approval PR",
            source_branch="feature/test",
            target_branch="main",
            merge_commit_sha="single123",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            merged_at=datetime.now(UTC) - timedelta(hours=1),
            approved_by=("one-reviewer@example.com",),
            review_status="approved",
        )
        mock_provider.add_pr(pr)
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            min_approvals=2,  # Require 2 approvals
            require_codeowners=False,
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        result = validator.validate_commit("single123", "test-domain")
        assert result.status == PRApprovalStatus.PENDING
        assert "Insufficient approvals" in str(result.errors)

    def test_wrong_target_branch(
        self, mock_provider: MockPRProvider, basic_config: PRGateConfig
    ) -> None:
        """Test PR targeting wrong branch."""
        pr = PRInfo(
            pr_number=45,
            title="Wrong branch PR",
            source_branch="feature/test",
            target_branch="develop",  # Not main/master
            merge_commit_sha="wrongbranch123",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            merged_at=datetime.now(UTC) - timedelta(hours=1),
            approved_by=("reviewer@example.com",),
            review_status="approved",
        )
        mock_provider.add_pr(pr)
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)
        result = validator.validate_commit("wrongbranch123", "test-domain")
        assert result.status == PRApprovalStatus.PENDING
        assert "target branch" in str(result.errors).lower()

    def test_commit_too_old(self, mock_provider: MockPRProvider) -> None:
        """Test PR with commit older than allowed."""
        old_pr = PRInfo(
            pr_number=46,
            title="Old PR",
            source_branch="feature/old",
            target_branch="main",
            merge_commit_sha="old123",
            created_at=datetime.now(UTC) - timedelta(days=30),
            merged_at=datetime.now(UTC) - timedelta(days=10),  # 10 days old
            approved_by=("reviewer@example.com",),
            review_status="approved",
        )
        mock_provider.add_pr(old_pr)
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            max_commit_age_hours=24,  # Only 24 hours allowed
            require_codeowners=False,
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        result = validator.validate_commit("old123", "test-domain")
        assert result.status == PRApprovalStatus.PENDING
        assert "too old" in str(result.errors).lower()

    def test_validation_cache(
        self,
        mock_provider: MockPRProvider,
        approved_pr: PRInfo,
        basic_config: PRGateConfig,
    ) -> None:
        """Test that validation results are cached."""
        mock_provider.add_pr(approved_pr)
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)

        # First validation
        result1 = validator.validate_commit(approved_pr.merge_commit_sha, "hub-network")
        # Second validation (should use cache)
        result2 = validator.validate_commit(approved_pr.merge_commit_sha, "hub-network")

        assert result1.status == result2.status
        assert result1.validated_at == result2.validated_at  # Same object from cache

    def test_cache_cleared(
        self,
        mock_provider: MockPRProvider,
        approved_pr: PRInfo,
        basic_config: PRGateConfig,
    ) -> None:
        """Test that cache can be cleared."""
        mock_provider.add_pr(approved_pr)
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)

        validator.validate_commit(approved_pr.merge_commit_sha, "hub-network")
        validator.clear_cache()

        # After clear, should fetch again
        result = validator.validate_commit(approved_pr.merge_commit_sha, "hub-network")
        assert result.status == PRApprovalStatus.APPROVED


class TestPRGateValidatorCodeOwners:
    """Tests for CODEOWNERS enforcement."""

    def test_codeowners_satisfied(self, mock_provider: MockPRProvider) -> None:
        """Test CODEOWNERS requirements satisfied."""
        pr = PRInfo(
            pr_number=47,
            title="With CODEOWNERS approval",
            source_branch="feature/firewall",
            target_branch="main",
            merge_commit_sha="codeowners123",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            merged_at=datetime.now(UTC) - timedelta(hours=1),
            approved_by=("security-team@example.com",),  # Matches CODEOWNERS
            review_status="approved",
        )
        mock_provider.add_pr(pr)

        codeowners = (
            CodeOwner(pattern="specs/firewall*.yaml", owners=("security-team@example.com",)),
        )
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            require_codeowners=True,
            codeowners=codeowners,
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        result = validator.validate_commit(
            "codeowners123",
            "firewall",
            spec_paths=["specs/firewall.yaml"],
        )
        assert result.status == PRApprovalStatus.APPROVED
        assert result.codeowners_satisfied is True

    def test_codeowners_missing_approver(self, mock_provider: MockPRProvider) -> None:
        """Test CODEOWNERS requirements not satisfied."""
        pr = PRInfo(
            pr_number=48,
            title="Missing CODEOWNERS approval",
            source_branch="feature/firewall",
            target_branch="main",
            merge_commit_sha="missing123",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            merged_at=datetime.now(UTC) - timedelta(hours=1),
            approved_by=("random-person@example.com",),  # Not in CODEOWNERS
            review_status="approved",
        )
        mock_provider.add_pr(pr)

        codeowners = (
            CodeOwner(pattern="specs/firewall*.yaml", owners=("security-team@example.com",)),
        )
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            require_codeowners=True,
            codeowners=codeowners,
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        result = validator.validate_commit(
            "missing123",
            "firewall",
            spec_paths=["specs/firewall.yaml"],
        )
        assert result.status == PRApprovalStatus.PENDING
        assert result.codeowners_satisfied is False
        assert "security-team@example.com" in result.missing_approvers


class TestPRGateValidatorEnforce:
    """Tests for enforce() method which raises exceptions."""

    def test_enforce_raises_on_not_approved(
        self, mock_provider: MockPRProvider, basic_config: PRGateConfig
    ) -> None:
        """Test that enforce raises PRNotApprovedError."""
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)
        with pytest.raises(PRNotApprovedError) as exc_info:
            validator.enforce("unknown123", "firewall")
        assert exc_info.value.validation_result.status == PRApprovalStatus.NOT_FOUND

    def test_enforce_raises_on_missing_codeowners(
        self, mock_provider: MockPRProvider
    ) -> None:
        """Test that enforce raises CodeOwnersMissingError."""
        pr = PRInfo(
            pr_number=49,
            title="Missing CODEOWNERS",
            source_branch="feature/test",
            target_branch="main",
            merge_commit_sha="missingco123",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            merged_at=datetime.now(UTC) - timedelta(hours=1),
            approved_by=("random@example.com",),
            review_status="approved",
        )
        mock_provider.add_pr(pr)

        codeowners = (
            CodeOwner(pattern="*.yaml", owners=("required-team@example.com",)),
        )
        config = PRGateConfig(
            mode=PRGateMode.ENFORCE,
            require_codeowners=True,
            codeowners=codeowners,
        )
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        with pytest.raises(CodeOwnersMissingError) as exc_info:
            validator.enforce(
                "missingco123",
                "test-domain",
                spec_paths=["specs/test.yaml"],
            )
        assert "required-team@example.com" in exc_info.value.missing_approvers

    def test_enforce_succeeds_when_approved(
        self,
        mock_provider: MockPRProvider,
        approved_pr: PRInfo,
        basic_config: PRGateConfig,
    ) -> None:
        """Test that enforce succeeds with approved PR."""
        mock_provider.add_pr(approved_pr)
        validator = PRGateValidator(config=basic_config, pr_provider=mock_provider)
        result = validator.enforce(approved_pr.merge_commit_sha, "hub-network")
        assert result.status == PRApprovalStatus.APPROVED

    def test_enforce_warn_mode_does_not_raise(
        self, mock_provider: MockPRProvider
    ) -> None:
        """Test that WARN mode does not raise exceptions."""
        config = PRGateConfig(mode=PRGateMode.WARN)
        validator = PRGateValidator(config=config, pr_provider=mock_provider)
        # Should not raise
        result = validator.enforce("unknown123", "firewall")
        assert result.status == PRApprovalStatus.NOT_FOUND
        assert result.is_valid is False


# =============================================================================
# Promotion Path Tests
# =============================================================================


class TestPromotionState:
    """Tests for promotion path tracking."""

    def test_initial_state(self) -> None:
        """Test initial promotion state."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")
        assert not state.is_promoted_to(PromotionEnvironment.DEVELOPMENT)
        assert not state.is_promoted_to(PromotionEnvironment.STAGING)
        assert not state.is_promoted_to(PromotionEnvironment.PRODUCTION)

    def test_record_promotion(self) -> None:
        """Test recording promotion."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")
        state.record_promotion(PromotionEnvironment.DEVELOPMENT)
        assert state.is_promoted_to(PromotionEnvironment.DEVELOPMENT)
        assert not state.is_promoted_to(PromotionEnvironment.STAGING)

    def test_validate_promotion_path_development(self) -> None:
        """Test development is always allowed."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")
        is_valid, error = state.validate_promotion_path(PromotionEnvironment.DEVELOPMENT)
        assert is_valid is True
        assert error == ""

    def test_validate_promotion_path_staging_requires_development(self) -> None:
        """Test staging requires development first."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")
        is_valid, error = state.validate_promotion_path(PromotionEnvironment.STAGING)
        assert is_valid is False
        assert "development" in error.lower()

    def test_validate_promotion_path_staging_after_development(self) -> None:
        """Test staging allowed after development."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")
        state.record_promotion(PromotionEnvironment.DEVELOPMENT)
        is_valid, error = state.validate_promotion_path(PromotionEnvironment.STAGING)
        assert is_valid is True

    def test_validate_promotion_path_production_requires_staging(self) -> None:
        """Test production requires staging first."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")
        state.record_promotion(PromotionEnvironment.DEVELOPMENT)
        is_valid, error = state.validate_promotion_path(PromotionEnvironment.PRODUCTION)
        assert is_valid is False
        assert "staging" in error.lower()

    def test_validate_full_promotion_path(self) -> None:
        """Test full promotion path: dev -> staging -> prod."""
        state = PromotionState(commit_sha="abc123", spec_hash="hash123")

        # Development
        state.record_promotion(PromotionEnvironment.DEVELOPMENT)
        is_valid, _ = state.validate_promotion_path(PromotionEnvironment.STAGING)
        assert is_valid

        # Staging
        state.record_promotion(PromotionEnvironment.STAGING)
        is_valid, _ = state.validate_promotion_path(PromotionEnvironment.PRODUCTION)
        assert is_valid

        # Production
        state.record_promotion(PromotionEnvironment.PRODUCTION)
        assert state.is_promoted_to(PromotionEnvironment.PRODUCTION)


# =============================================================================
# Environment Detection Tests
# =============================================================================


class TestEnvironmentDetection:
    """Tests for environment detection from branch names."""

    def test_main_is_production(self) -> None:
        """Test main branch is production."""
        assert detect_environment_from_branch("main") == PromotionEnvironment.PRODUCTION

    def test_master_is_production(self) -> None:
        """Test master branch is production."""
        assert detect_environment_from_branch("master") == PromotionEnvironment.PRODUCTION

    def test_release_is_production(self) -> None:
        """Test release/* branch is production."""
        assert detect_environment_from_branch("release/v1.0.0") == PromotionEnvironment.PRODUCTION

    def test_staging_is_staging(self) -> None:
        """Test staging branch is staging."""
        assert detect_environment_from_branch("staging") == PromotionEnvironment.STAGING

    def test_uat_is_staging(self) -> None:
        """Test uat branch is staging."""
        assert detect_environment_from_branch("uat") == PromotionEnvironment.STAGING

    def test_develop_is_development(self) -> None:
        """Test develop branch is development."""
        assert detect_environment_from_branch("develop") == PromotionEnvironment.DEVELOPMENT

    def test_feature_is_development(self) -> None:
        """Test feature/* branch is development."""
        assert detect_environment_from_branch("feature/my-feature") == PromotionEnvironment.DEVELOPMENT

    def test_unknown_branch_defaults_to_development(self) -> None:
        """Test unknown branch defaults to development."""
        assert detect_environment_from_branch("some-random-branch") == PromotionEnvironment.DEVELOPMENT


# =============================================================================
# Utility Tests
# =============================================================================


class TestCriticalDomains:
    """Tests for critical domain detection."""

    def test_hub_network_is_critical(self) -> None:
        """Test hub-network is critical."""
        assert is_critical_domain("hub-network") is True

    def test_firewall_is_critical(self) -> None:
        """Test firewall is critical."""
        assert is_critical_domain("firewall") is True

    def test_management_group_is_critical(self) -> None:
        """Test management-group is critical."""
        assert is_critical_domain("management-group") is True

    def test_log_analytics_not_critical(self) -> None:
        """Test log-analytics is not critical."""
        assert is_critical_domain("log-analytics") is False

    def test_critical_domains_constant(self) -> None:
        """Test CRITICAL_DOMAINS contains expected entries."""
        assert "hub-network" in CRITICAL_DOMAINS
        assert "firewall" in CRITICAL_DOMAINS
        assert "vpn-gateway" in CRITICAL_DOMAINS
        assert "dns" in CRITICAL_DOMAINS
        assert "role" in CRITICAL_DOMAINS


class TestSpecHash:
    """Tests for spec hash computation."""

    def test_compute_spec_hash(self) -> None:
        """Test hash computation."""
        hash1 = compute_spec_hash("content1")
        hash2 = compute_spec_hash("content2")
        assert hash1 != hash2
        assert len(hash1) == 16  # First 16 chars of SHA256

    def test_compute_spec_hash_deterministic(self) -> None:
        """Test hash is deterministic."""
        hash1 = compute_spec_hash("same content")
        hash2 = compute_spec_hash("same content")
        assert hash1 == hash2


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_pr_gate_validator(self) -> None:
        """Test create_pr_gate_validator factory."""
        config = PRGateConfig(mode=PRGateMode.WARN)
        validator = create_pr_gate_validator(config=config)
        assert validator.mode == PRGateMode.WARN
