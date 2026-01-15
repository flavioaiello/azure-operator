"""Tests for operator dependency ordering."""

from __future__ import annotations

import pytest

from controller.dependency import (
    CyclicDependencyError,
    DependencyChecker,
    DependencyConfig,
    DependencyGraph,
    DependencyNode,
    DependencyStatus,
    KNOWN_DEPENDENCIES,
    UnsatisfiedDependencyError,
    get_suggested_dependencies,
    validate_dependency_declaration,
)


class TestDependencyStatus:
    """Tests for DependencyStatus enum."""

    def test_values(self) -> None:
        """Test enum values."""
        assert DependencyStatus.SATISFIED.value == "satisfied"
        assert DependencyStatus.PENDING.value == "pending"
        assert DependencyStatus.FAILED.value == "failed"
        assert DependencyStatus.UNKNOWN.value == "unknown"


class TestDependencyNode:
    """Tests for DependencyNode dataclass."""

    def test_default_values(self) -> None:
        """Test default node values."""
        node = DependencyNode(domain="test")
        assert node.domain == "test"
        assert node.depends_on == []
        assert node.status == DependencyStatus.UNKNOWN
        assert node.last_checked is None

    def test_with_dependencies(self) -> None:
        """Test node with dependencies."""
        node = DependencyNode(domain="firewall", depends_on=["hub-network", "log-analytics"])
        assert node.depends_on == ["hub-network", "log-analytics"]


class TestDependencyGraph:
    """Tests for DependencyGraph."""

    def test_add_node(self) -> None:
        """Test adding nodes."""
        graph = DependencyGraph()
        graph.add_node("firewall", ["hub-network"])
        
        assert "firewall" in graph.nodes
        assert "hub-network" in graph.nodes  # Auto-created
        assert graph.nodes["firewall"].depends_on == ["hub-network"]

    def test_validate_no_cycle(self) -> None:
        """Test validation passes for acyclic graph."""
        graph = DependencyGraph()
        graph.add_node("log-analytics", [])
        graph.add_node("hub-network", ["log-analytics"])
        graph.add_node("firewall", ["hub-network", "log-analytics"])
        
        # Should not raise
        graph.validate()

    def test_validate_detects_cycle(self) -> None:
        """Test validation detects cycles."""
        graph = DependencyGraph()
        graph.add_node("a", ["b"])
        graph.add_node("b", ["c"])
        graph.add_node("c", ["a"])  # Cycle: a -> b -> c -> a
        
        with pytest.raises(CyclicDependencyError, match="Circular dependency"):
            graph.validate()

    def test_topological_sort_simple(self) -> None:
        """Test topological sort with simple dependencies."""
        graph = DependencyGraph()
        graph.add_node("log-analytics", [])
        graph.add_node("hub-network", ["log-analytics"])
        graph.add_node("firewall", ["hub-network"])
        
        order = graph.topological_sort()
        
        # log-analytics must come before hub-network
        assert order.index("log-analytics") < order.index("hub-network")
        # hub-network must come before firewall
        assert order.index("hub-network") < order.index("firewall")

    def test_topological_sort_multiple_deps(self) -> None:
        """Test topological sort with multiple dependencies."""
        graph = DependencyGraph()
        graph.add_node("log-analytics", [])
        graph.add_node("hub-network", ["log-analytics"])
        graph.add_node("firewall", ["hub-network", "log-analytics"])
        
        order = graph.topological_sort()
        
        # Both deps must come before firewall
        assert order.index("log-analytics") < order.index("firewall")
        assert order.index("hub-network") < order.index("firewall")

    def test_get_ready_domains_none_satisfied(self) -> None:
        """Test getting ready domains when nothing is satisfied."""
        graph = DependencyGraph()
        graph.add_node("log-analytics", [])
        graph.add_node("hub-network", ["log-analytics"])
        graph.add_node("firewall", ["hub-network"])
        
        ready = graph.get_ready_domains(satisfied=set())
        
        # Only log-analytics has no deps
        assert ready == ["log-analytics"]

    def test_get_ready_domains_some_satisfied(self) -> None:
        """Test getting ready domains when some are satisfied."""
        graph = DependencyGraph()
        graph.add_node("log-analytics", [])
        graph.add_node("hub-network", ["log-analytics"])
        graph.add_node("firewall", ["hub-network"])
        
        ready = graph.get_ready_domains(satisfied={"log-analytics"})
        
        # Now hub-network can proceed
        assert ready == ["hub-network"]

    def test_get_ready_domains_all_satisfied(self) -> None:
        """Test getting ready domains when all satisfied."""
        graph = DependencyGraph()
        graph.add_node("log-analytics", [])
        graph.add_node("hub-network", ["log-analytics"])
        
        ready = graph.get_ready_domains(satisfied={"log-analytics", "hub-network"})
        
        # Nothing left to deploy
        assert ready == []


class TestDependencyConfig:
    """Tests for DependencyConfig."""

    def test_defaults(self) -> None:
        """Test default configuration."""
        config = DependencyConfig()
        assert config.enforce_dependencies is True
        assert config.wait_for_dependencies is True
        assert config.dependency_timeout_seconds == 300
        assert config.verify_via_resource_graph is True

    def test_from_env_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with empty environment."""
        for var in [
            "ENFORCE_DEPENDENCIES",
            "WAIT_FOR_DEPENDENCIES",
            "DEPENDENCY_TIMEOUT_SECONDS",
            "VERIFY_DEPENDENCIES_VIA_GRAPH",
        ]:
            monkeypatch.delenv(var, raising=False)
        
        config = DependencyConfig.from_env()
        assert config.enforce_dependencies is True

    def test_from_env_disable_enforcement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test disabling enforcement via environment."""
        monkeypatch.setenv("ENFORCE_DEPENDENCIES", "false")
        config = DependencyConfig.from_env()
        assert config.enforce_dependencies is False

    def test_from_env_custom_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test custom timeout from environment."""
        monkeypatch.setenv("DEPENDENCY_TIMEOUT_SECONDS", "600")
        config = DependencyConfig.from_env()
        assert config.dependency_timeout_seconds == 600

    def test_from_env_timeout_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test timeout is clamped to maximum."""
        monkeypatch.setenv("DEPENDENCY_TIMEOUT_SECONDS", "99999")
        config = DependencyConfig.from_env()
        assert config.dependency_timeout_seconds == 3600  # MAX


class TestDependencyChecker:
    """Tests for DependencyChecker."""

    @pytest.fixture
    def checker(self) -> DependencyChecker:
        """Create a checker with default config."""
        return DependencyChecker(DependencyConfig())

    @pytest.fixture
    def checker_no_verify(self) -> DependencyChecker:
        """Create a checker without Resource Graph verification."""
        return DependencyChecker(DependencyConfig(verify_via_resource_graph=False))

    @pytest.fixture
    def checker_disabled(self) -> DependencyChecker:
        """Create a checker with enforcement disabled."""
        return DependencyChecker(DependencyConfig(enforce_dependencies=False))

    def test_no_dependencies(self, checker: DependencyChecker) -> None:
        """Test checking with no dependencies."""
        satisfied, unsatisfied = checker.check_dependencies(
            domain="log-analytics",
            depends_on=[],
            subscription_id="sub-1",
        )
        assert satisfied is True
        assert unsatisfied == []

    def test_enforcement_disabled(self, checker_disabled: DependencyChecker) -> None:
        """Test that disabled enforcement always succeeds."""
        satisfied, unsatisfied = checker_disabled.check_dependencies(
            domain="firewall",
            depends_on=["hub-network", "log-analytics"],
            subscription_id="sub-1",
        )
        assert satisfied is True
        assert unsatisfied == []

    def test_mark_satisfied(self, checker_no_verify: DependencyChecker) -> None:
        """Test marking a domain as satisfied."""
        checker_no_verify.mark_satisfied("log-analytics")
        
        # Now log-analytics should be in the cache
        satisfied, unsatisfied = checker_no_verify.check_dependencies(
            domain="firewall",
            depends_on=["log-analytics"],
            subscription_id="sub-1",
        )
        assert satisfied is True

    def test_clear_cache(self, checker_no_verify: DependencyChecker) -> None:
        """Test clearing the satisfied cache."""
        checker_no_verify.mark_satisfied("log-analytics")
        checker_no_verify.clear_cache()
        
        # Cache is cleared - verification would be needed again
        # But without verify_via_resource_graph, it returns SATISFIED
        satisfied, _ = checker_no_verify.check_dependencies(
            domain="firewall",
            depends_on=["log-analytics"],
            subscription_id="sub-1",
        )
        assert satisfied is True


class TestKnownDependencies:
    """Tests for KNOWN_DEPENDENCIES constant."""

    def test_management_group_no_deps(self) -> None:
        """Test management-group has no dependencies."""
        assert KNOWN_DEPENDENCIES.get("management-group") == []

    def test_log_analytics_no_deps(self) -> None:
        """Test log-analytics has no dependencies."""
        assert KNOWN_DEPENDENCIES.get("log-analytics") == []

    def test_firewall_depends_on_hub(self) -> None:
        """Test firewall depends on hub-network."""
        deps = KNOWN_DEPENDENCIES.get("firewall", [])
        assert "hub-network" in deps
        assert "log-analytics" in deps

    def test_secondary_depends_on_primary(self) -> None:
        """Test secondary regions depend on primary."""
        deps = KNOWN_DEPENDENCIES.get("hub-network-secondary", [])
        assert "hub-network" in deps


class TestGetSuggestedDependencies:
    """Tests for get_suggested_dependencies function."""

    def test_known_domain(self) -> None:
        """Test getting suggestions for known domain."""
        deps = get_suggested_dependencies("firewall")
        assert "hub-network" in deps

    def test_unknown_domain(self) -> None:
        """Test getting suggestions for unknown domain."""
        deps = get_suggested_dependencies("custom-domain")
        assert deps == []


class TestValidateDependencyDeclaration:
    """Tests for validate_dependency_declaration function."""

    def test_valid_declaration(self) -> None:
        """Test validation of valid declaration."""
        warnings = validate_dependency_declaration(
            domain="firewall",
            depends_on=["hub-network", "log-analytics"],
        )
        # Should have no warnings or just suggestions
        assert not any("cannot depend on itself" in w for w in warnings)

    def test_self_dependency_warning(self) -> None:
        """Test warning for self-dependency."""
        warnings = validate_dependency_declaration(
            domain="firewall",
            depends_on=["firewall", "hub-network"],
        )
        assert any("cannot depend on itself" in w for w in warnings)

    def test_unknown_dependency_warning(self) -> None:
        """Test warning for unknown dependency."""
        warnings = validate_dependency_declaration(
            domain="firewall",
            depends_on=["unknown-domain"],
        )
        assert any("Unknown dependency" in w for w in warnings)

    def test_missing_suggested_warning(self) -> None:
        """Test warning for missing suggested dependencies."""
        warnings = validate_dependency_declaration(
            domain="firewall",
            depends_on=[],  # Missing hub-network and log-analytics
        )
        assert any("Consider adding" in w for w in warnings)
