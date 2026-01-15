"""Tests for diff normalization rules engine."""

from __future__ import annotations

import pytest

from controller.diff_normalizer import (
    DEFAULT_NORMALIZATION_RULES,
    DiffNormalizer,
    NormalizationConfig,
    NormalizationRule,
    NormalizationType,
    WhatIfDiffProcessor,
    create_diff_processor_from_env,
)


class TestNormalizationRule:
    """Tests for NormalizationRule matching."""

    def test_matches_exact_resource_type(self) -> None:
        """Test exact resource type matching."""
        rule = NormalizationRule(
            resource_type="Microsoft.Network/virtualNetworks",
            path_pattern="*",
            normalization_type=NormalizationType.EMPTY_EQUIVALENCE,
        )

        assert rule.matches("Microsoft.Network/virtualNetworks", "properties.tags") is True
        assert rule.matches("Microsoft.Network/networkSecurityGroups", "properties.tags") is False

    def test_matches_wildcard_resource_type(self) -> None:
        """Test wildcard resource type matching."""
        rule = NormalizationRule(
            resource_type="*",
            path_pattern="properties.tags",
            normalization_type=NormalizationType.EMPTY_EQUIVALENCE,
        )

        assert rule.matches("Microsoft.Network/virtualNetworks", "properties.tags") is True
        assert rule.matches("Microsoft.Compute/virtualMachines", "properties.tags") is True

    def test_matches_glob_resource_type(self) -> None:
        """Test glob pattern in resource type."""
        rule = NormalizationRule(
            resource_type="Microsoft.Network/*",
            path_pattern="*",
            normalization_type=NormalizationType.CASE_INSENSITIVE,
        )

        assert rule.matches("Microsoft.Network/virtualNetworks", "properties.sku.name") is True
        assert rule.matches("Microsoft.Compute/virtualMachines", "properties.sku.name") is False

    def test_matches_path_pattern(self) -> None:
        """Test path pattern matching."""
        rule = NormalizationRule(
            resource_type="*",
            path_pattern="**.enabled",
            normalization_type=NormalizationType.BOOLEAN_NORMALIZE,
        )

        assert rule.matches("Microsoft.Network/firewalls", "properties.enabled") is True
        assert rule.matches(
            "Microsoft.Network/firewalls", "properties.features.logging.enabled"
        ) is True
        assert rule.matches("Microsoft.Network/firewalls", "properties.name") is False

    def test_matches_case_insensitive(self) -> None:
        """Test case-insensitive matching."""
        rule = NormalizationRule(
            resource_type="microsoft.network/virtualnetworks",
            path_pattern="properties.tags",
            normalization_type=NormalizationType.EMPTY_EQUIVALENCE,
        )

        assert rule.matches("Microsoft.Network/VirtualNetworks", "properties.tags") is True


class TestDiffNormalizer:
    """Tests for DiffNormalizer."""

    @pytest.fixture
    def normalizer(self) -> DiffNormalizer:
        """Create a normalizer with default rules."""
        return DiffNormalizer(enable_default_rules=True)

    @pytest.fixture
    def normalizer_no_defaults(self) -> DiffNormalizer:
        """Create a normalizer without default rules."""
        return DiffNormalizer(enable_default_rules=False)

    # Empty equivalence tests

    def test_normalize_empty_list_to_none(self, normalizer: DiffNormalizer) -> None:
        """Test empty list normalizes to None."""
        result = normalizer.normalize_value(
            [], "Microsoft.Network/virtualNetworks", "properties.tags"
        )
        assert result is None

    def test_normalize_empty_dict_to_none(self, normalizer: DiffNormalizer) -> None:
        """Test empty dict normalizes to None."""
        result = normalizer.normalize_value(
            {}, "Microsoft.Network/virtualNetworks", "properties.tags"
        )
        assert result is None

    def test_normalize_null_stays_none(self, normalizer: DiffNormalizer) -> None:
        """Test None stays None."""
        result = normalizer.normalize_value(
            None, "Microsoft.Network/virtualNetworks", "properties.tags"
        )
        assert result is None

    def test_empty_equivalence_with_values(self, normalizer: DiffNormalizer) -> None:
        """Test that non-empty values are preserved."""
        result = normalizer.normalize_value(
            {"key": "value"}, "Microsoft.Network/virtualNetworks", "properties.tags"
        )
        assert result == {"key": "value"}

    # Boolean normalization tests

    def test_normalize_boolean_string_true(self, normalizer: DiffNormalizer) -> None:
        """Test string 'true' normalizes to True."""
        result = normalizer.normalize_value(
            "true", "Microsoft.Network/firewalls", "properties.enabled"
        )
        assert result is True

    def test_normalize_boolean_string_false(self, normalizer: DiffNormalizer) -> None:
        """Test string 'false' normalizes to False."""
        result = normalizer.normalize_value(
            "false", "Microsoft.Network/firewalls", "properties.enabled"
        )
        assert result is False

    def test_normalize_boolean_int_1(self, normalizer: DiffNormalizer) -> None:
        """Test integer 1 normalizes to True."""
        result = normalizer.normalize_value(
            1, "Microsoft.Network/firewalls", "properties.enabled"
        )
        assert result is True

    def test_normalize_boolean_int_0(self, normalizer: DiffNormalizer) -> None:
        """Test integer 0 normalizes to False."""
        result = normalizer.normalize_value(
            0, "Microsoft.Network/firewalls", "properties.enabled"
        )
        assert result is False

    # Case insensitive tests

    def test_normalize_case_sku_name(self, normalizer: DiffNormalizer) -> None:
        """Test SKU name is case-normalized."""
        result = normalizer.normalize_value(
            "Standard", "Microsoft.Network/publicIPAddresses", "properties.sku.name"
        )
        assert result == "standard"

    # are_equivalent tests

    def test_are_equivalent_empty_list_vs_none(self, normalizer: DiffNormalizer) -> None:
        """Test empty list is equivalent to None."""
        is_equiv, reason = normalizer.are_equivalent(
            before=[],
            after=None,
            resource_type="Microsoft.Network/virtualNetworks",
            path="properties.tags",
        )
        assert is_equiv is True
        assert reason is not None

    def test_are_equivalent_boolean_string_vs_bool(self, normalizer: DiffNormalizer) -> None:
        """Test string 'true' is equivalent to True."""
        is_equiv, _reason = normalizer.are_equivalent(
            before="true",
            after=True,
            resource_type="Microsoft.Network/firewalls",
            path="properties.enabled",
        )
        assert is_equiv is True

    def test_are_equivalent_case_difference(self, normalizer: DiffNormalizer) -> None:
        """Test case differences are normalized."""
        is_equiv, _reason = normalizer.are_equivalent(
            before="Standard",
            after="standard",
            resource_type="Microsoft.Network/publicIPAddresses",
            path="properties.sku.name",
        )
        assert is_equiv is True

    def test_not_equivalent_different_values(self, normalizer: DiffNormalizer) -> None:
        """Test different values are not equivalent."""
        is_equiv, reason = normalizer.are_equivalent(
            before="10.0.0.0/16",
            after="10.0.0.0/24",
            resource_type="Microsoft.Network/virtualNetworks",
            path="properties.addressSpace.addressPrefixes",
        )
        assert is_equiv is False
        assert reason is None


class TestDiffNormalizerNumericString:
    """Tests for numeric string normalization."""

    @pytest.fixture
    def normalizer(self) -> DiffNormalizer:
        """Create normalizer with numeric string rule."""
        return DiffNormalizer(
            rules=[
                NormalizationRule(
                    resource_type="*",
                    path_pattern="**.port",
                    normalization_type=NormalizationType.NUMERIC_STRING,
                )
            ],
            enable_default_rules=False,
        )

    def test_normalize_string_to_int(self, normalizer: DiffNormalizer) -> None:
        """Test string '443' normalizes to 443."""
        result = normalizer.normalize_value(
            "443", "Microsoft.Network/firewalls", "properties.rules.port"
        )
        assert result == 443

    def test_normalize_string_to_float(self, normalizer: DiffNormalizer) -> None:
        """Test string '3.14' normalizes to 3.14."""
        result = normalizer.normalize_value(
            "3.14", "Microsoft.Network/firewalls", "properties.rules.port"
        )
        assert isinstance(result, float) and abs(result - 3.14) < 1e-9


class TestDiffNormalizerUrl:
    """Tests for URL normalization."""

    @pytest.fixture
    def normalizer(self) -> DiffNormalizer:
        """Create normalizer with URL rule."""
        return DiffNormalizer(
            rules=[
                NormalizationRule(
                    resource_type="*",
                    path_pattern="**.url",
                    normalization_type=NormalizationType.URL_NORMALIZE,
                )
            ],
            enable_default_rules=False,
        )

    def test_normalize_trailing_slash(self, normalizer: DiffNormalizer) -> None:
        """Test trailing slash is removed."""
        result = normalizer.normalize_value(
            "https://example.com/api/", "Microsoft.Web/sites", "properties.url"
        )
        assert result == "https://example.com/api"

    def test_normalize_scheme_case(self, normalizer: DiffNormalizer) -> None:
        """Test HTTP scheme is lowercased."""
        result = normalizer.normalize_value(
            "HTTPS://example.com/api", "Microsoft.Web/sites", "properties.url"
        )
        assert result == "https://example.com/api"


class TestDiffNormalizerWhitespace:
    """Tests for whitespace normalization."""

    @pytest.fixture
    def normalizer(self) -> DiffNormalizer:
        """Create normalizer with whitespace rule."""
        return DiffNormalizer(
            rules=[
                NormalizationRule(
                    resource_type="*",
                    path_pattern="**.script",
                    normalization_type=NormalizationType.WHITESPACE_NORMALIZE,
                )
            ],
            enable_default_rules=False,
        )

    def test_normalize_multiple_spaces(self, normalizer: DiffNormalizer) -> None:
        """Test multiple spaces are collapsed."""
        result = normalizer.normalize_value(
            "hello    world", "Microsoft.Automation/runbooks", "properties.script"
        )
        assert result == "hello world"

    def test_normalize_line_endings(self, normalizer: DiffNormalizer) -> None:
        """Test line endings are normalized."""
        result = normalizer.normalize_value(
            "line1\r\nline2\rline3", "Microsoft.Automation/runbooks", "properties.script"
        )
        assert result == "line1\nline2\nline3"


class TestDiffNormalizerArrayOrder:
    """Tests for array order normalization."""

    @pytest.fixture
    def normalizer(self) -> DiffNormalizer:
        """Create normalizer with array order rule."""
        return DiffNormalizer(
            rules=[
                NormalizationRule(
                    resource_type="*",
                    path_pattern="properties.tags",
                    normalization_type=NormalizationType.ARRAY_UNORDERED,
                )
            ],
            enable_default_rules=False,
        )

    def test_normalize_array_order(self, normalizer: DiffNormalizer) -> None:
        """Test arrays are sorted for comparison."""
        result1 = normalizer.normalize_value(
            ["c", "a", "b"], "Microsoft.Resources/tags", "properties.tags"
        )
        result2 = normalizer.normalize_value(
            ["a", "b", "c"], "Microsoft.Resources/tags", "properties.tags"
        )
        assert result1 == result2


class TestDiffNormalizerDefaultValue:
    """Tests for default value normalization."""

    @pytest.fixture
    def normalizer(self) -> DiffNormalizer:
        """Create normalizer with default value rules."""
        return DiffNormalizer(enable_default_rules=True)

    def test_default_ddos_protection(self, normalizer: DiffNormalizer) -> None:
        """Test DDoS protection defaults to False."""
        # None should be treated as False (the default)
        is_equiv, _ = normalizer.are_equivalent(
            before=None,
            after=False,
            resource_type="Microsoft.Network/virtualNetworks",
            path="properties.enableDdosProtection",
        )
        assert is_equiv is True


class TestWhatIfDiffProcessor:
    """Tests for WhatIfDiffProcessor."""

    @pytest.fixture
    def processor(self) -> WhatIfDiffProcessor:
        """Create a processor with default config."""
        return WhatIfDiffProcessor()

    def test_process_property_change_equivalent(self, processor: WhatIfDiffProcessor) -> None:
        """Test processing equivalent changes."""
        is_significant, reason = processor.process_property_change(
            resource_type="Microsoft.Network/virtualNetworks",
            path="properties.tags",
            before=[],
            after=None,
        )
        assert is_significant is False
        assert reason is not None

    def test_process_property_change_significant(self, processor: WhatIfDiffProcessor) -> None:
        """Test processing significant changes."""
        is_significant, reason = processor.process_property_change(
            resource_type="Microsoft.Network/virtualNetworks",
            path="properties.addressSpace.addressPrefixes",
            before=["10.0.0.0/16"],
            after=["10.0.0.0/24"],
        )
        assert is_significant is True
        assert reason is None

    def test_filter_delta(self, processor: WhatIfDiffProcessor) -> None:
        """Test filtering a delta list."""
        delta = [
            {"path": "properties.tags", "before": [], "after": None},  # Equivalent
            {  # Significant
                "path": "properties.addressSpace",
                "before": "10.0.0.0/16",
                "after": "10.0.0.0/24",
            },
        ]

        filtered, normalized_count = processor.filter_delta(
            "Microsoft.Network/virtualNetworks",
            delta,
        )

        assert len(filtered) == 1
        assert normalized_count == 1
        assert filtered[0]["path"] == "properties.addressSpace"


class TestNormalizationConfig:
    """Tests for NormalizationConfig."""

    def test_defaults(self) -> None:
        """Test default configuration."""
        config = NormalizationConfig()
        assert config.enable_default_rules is True
        assert config.log_normalizations is True

    def test_from_env_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with empty environment."""
        for var in ["ENABLE_DEFAULT_NORMALIZATION_RULES", "LOG_NORMALIZATIONS"]:
            monkeypatch.delenv(var, raising=False)

        config = NormalizationConfig.from_env()
        assert config.enable_default_rules is True

    def test_from_env_disable_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test disabling default rules."""
        monkeypatch.setenv("ENABLE_DEFAULT_NORMALIZATION_RULES", "false")
        config = NormalizationConfig.from_env()
        assert config.enable_default_rules is False


class TestDefaultNormalizationRules:
    """Tests for DEFAULT_NORMALIZATION_RULES."""

    def test_has_empty_equivalence_rules(self) -> None:
        """Test default rules include empty equivalence."""
        empty_rules = [
            r for r in DEFAULT_NORMALIZATION_RULES
            if r.normalization_type == NormalizationType.EMPTY_EQUIVALENCE
        ]
        assert len(empty_rules) > 0

    def test_has_boolean_rules(self) -> None:
        """Test default rules include boolean normalization."""
        bool_rules = [
            r for r in DEFAULT_NORMALIZATION_RULES
            if r.normalization_type == NormalizationType.BOOLEAN_NORMALIZE
        ]
        assert len(bool_rules) > 0

    def test_has_case_insensitive_rules(self) -> None:
        """Test default rules include case insensitive."""
        case_rules = [
            r for r in DEFAULT_NORMALIZATION_RULES
            if r.normalization_type == NormalizationType.CASE_INSENSITIVE
        ]
        assert len(case_rules) > 0


class TestCreateDiffProcessorFromEnv:
    """Tests for create_diff_processor_from_env."""

    def test_creates_processor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test factory function creates processor."""
        for var in ["ENABLE_DEFAULT_NORMALIZATION_RULES", "LOG_NORMALIZATIONS"]:
            monkeypatch.delenv(var, raising=False)

        processor = create_diff_processor_from_env()
        assert processor is not None
        assert processor.normalizer is not None
