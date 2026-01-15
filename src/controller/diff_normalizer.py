"""Diff normalization rules engine for WhatIf result processing.

This module handles semantic equivalence in Azure ARM WhatIf results,
normalizing differences that are syntactically different but semantically
equivalent.

DESIGN PHILOSOPHY:
- Semantic equivalence: empty array ≡ null ≡ missing for many properties
- Default value awareness: Azure fills in defaults that weren't specified
- Type coercion: "100" vs 100, true vs "True"
- Order independence: Arrays where order doesn't matter

These normalizations reduce false positives in drift detection by
understanding ARM's quirks and default behaviors.

COMMON FALSE POSITIVES HANDLED:
1. Empty array [] vs null vs missing property
2. String "true" vs boolean true
3. Default values Azure adds automatically
4. Case differences in enums (e.g., "Enabled" vs "enabled")
5. Trailing slashes in URLs
6. Whitespace differences in multi-line strings
7. Array ordering for unordered collections (tags, etc.)
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class NormalizationType(str, Enum):
    """Types of normalization operations."""

    # Empty equivalence: [], null, missing are equivalent
    EMPTY_EQUIVALENCE = "empty_equivalence"

    # Boolean normalization: "true", "True", True, 1 are equivalent
    BOOLEAN_NORMALIZE = "boolean_normalize"

    # Numeric string normalization: "100" == 100
    NUMERIC_STRING = "numeric_string"

    # Case normalization for enums/strings
    CASE_INSENSITIVE = "case_insensitive"

    # URL normalization (trailing slashes, scheme case)
    URL_NORMALIZE = "url_normalize"

    # Whitespace normalization for multi-line strings
    WHITESPACE_NORMALIZE = "whitespace_normalize"

    # Array order independence
    ARRAY_UNORDERED = "array_unordered"

    # Default value equivalence
    DEFAULT_VALUE = "default_value"

    # Timestamp tolerance (within N seconds)
    TIMESTAMP_TOLERANCE = "timestamp_tolerance"


@dataclass(frozen=True)
class NormalizationRule:
    """A single normalization rule.

    Attributes:
        resource_type: Azure resource type to match (supports wildcards)
        path_pattern: Property path pattern to match (supports wildcards)
        normalization_type: Type of normalization to apply
        params: Additional parameters for the normalization
        reason: Human-readable explanation
    """

    resource_type: str
    path_pattern: str
    normalization_type: NormalizationType
    params: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    def matches(self, resource_type: str, path: str) -> bool:
        """Check if this rule applies to a resource and path.

        Args:
            resource_type: Azure resource type.
            path: Property path.

        Returns:
            True if this rule applies.
        """
        # Check resource type
        if self.resource_type != "*" and not self._glob_match(
            resource_type.lower(), self.resource_type.lower()
        ):
            return False

        # Check path pattern
        return not (
            self.path_pattern != "*"
            and not self._glob_match(path.lower(), self.path_pattern.lower())
        )

    def _glob_match(self, value: str, pattern: str) -> bool:
        """Simple glob matching with * and ** support."""
        # Convert glob to regex
        regex_pattern = "^"
        i = 0
        while i < len(pattern):
            if pattern[i:i+2] == "**":
                regex_pattern += ".*"
                i += 2
            elif pattern[i] == "*":
                regex_pattern += "[^.]*"
                i += 1
            elif pattern[i] in r"\.[]{}()+^$|":
                regex_pattern += "\\" + pattern[i]
                i += 1
            else:
                regex_pattern += pattern[i]
                i += 1
        regex_pattern += "$"

        return bool(re.match(regex_pattern, value))


# Default normalization rules for common Azure patterns
DEFAULT_NORMALIZATION_RULES: list[NormalizationRule] = [
    # Empty equivalence for common properties
    NormalizationRule(
        resource_type="*",
        path_pattern="properties.tags",
        normalization_type=NormalizationType.EMPTY_EQUIVALENCE,
        reason="Empty tags object equals null/missing",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.ipConfigurations",
        normalization_type=NormalizationType.EMPTY_EQUIVALENCE,
        reason="Empty IP configurations equals null",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.dnsServers",
        normalization_type=NormalizationType.EMPTY_EQUIVALENCE,
        reason="Empty DNS servers equals Azure DNS",
    ),

    # Boolean normalization
    NormalizationRule(
        resource_type="*",
        path_pattern="**.enabled",
        normalization_type=NormalizationType.BOOLEAN_NORMALIZE,
        reason="Boolean enabled flags may be string or bool",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.enableDdosProtection",
        normalization_type=NormalizationType.BOOLEAN_NORMALIZE,
        reason="DDoS protection flag",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.enableVmProtection",
        normalization_type=NormalizationType.BOOLEAN_NORMALIZE,
        reason="VM protection flag",
    ),

    # Case insensitive for common enums
    NormalizationRule(
        resource_type="*",
        path_pattern="**.sku.name",
        normalization_type=NormalizationType.CASE_INSENSITIVE,
        reason="SKU names may have case variations",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.sku.tier",
        normalization_type=NormalizationType.CASE_INSENSITIVE,
        reason="SKU tiers may have case variations",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.state",
        normalization_type=NormalizationType.CASE_INSENSITIVE,
        reason="State values may have case variations",
    ),
    NormalizationRule(
        resource_type="*",
        path_pattern="**.status",
        normalization_type=NormalizationType.CASE_INSENSITIVE,
        reason="Status values may have case variations",
    ),

    # Default values
    NormalizationRule(
        resource_type="Microsoft.Network/virtualNetworks",
        path_pattern="properties.enableDdosProtection",
        normalization_type=NormalizationType.DEFAULT_VALUE,
        params={"default": False},
        reason="DDoS protection defaults to false",
    ),
    NormalizationRule(
        resource_type="Microsoft.Network/virtualNetworks",
        path_pattern="properties.enableVmProtection",
        normalization_type=NormalizationType.DEFAULT_VALUE,
        params={"default": False},
        reason="VM protection defaults to false",
    ),
    NormalizationRule(
        resource_type="Microsoft.Storage/storageAccounts",
        path_pattern="properties.supportsHttpsTrafficOnly",
        normalization_type=NormalizationType.DEFAULT_VALUE,
        params={"default": True},
        reason="HTTPS only defaults to true",
    ),
    NormalizationRule(
        resource_type="Microsoft.Storage/storageAccounts",
        path_pattern="properties.minimumTlsVersion",
        normalization_type=NormalizationType.DEFAULT_VALUE,
        params={"default": "TLS1_2"},
        reason="Minimum TLS defaults to 1.2",
    ),

    # Array ordering for unordered collections
    NormalizationRule(
        resource_type="*",
        path_pattern="properties.tags",
        normalization_type=NormalizationType.ARRAY_UNORDERED,
        reason="Tag order doesn't matter",
    ),
    NormalizationRule(
        resource_type="Microsoft.Network/networkSecurityGroups",
        path_pattern="properties.securityRules",
        normalization_type=NormalizationType.ARRAY_UNORDERED,
        reason="NSG rules are ordered by priority, not array index",
    ),
]


class DiffNormalizer:
    """Normalizes WhatIf diffs to handle semantic equivalence.

    This class transforms before/after values to detect when differences
    are only syntactic, not semantic.
    """

    def __init__(
        self,
        rules: list[NormalizationRule] | None = None,
        enable_default_rules: bool = True,
    ) -> None:
        """Initialize normalizer.

        Args:
            rules: Custom normalization rules.
            enable_default_rules: Whether to include default rules.
        """
        self._rules: list[NormalizationRule] = []
        if enable_default_rules:
            self._rules.extend(DEFAULT_NORMALIZATION_RULES)
        if rules:
            self._rules.extend(rules)

    def normalize_value(
        self,
        value: Any,
        resource_type: str,
        path: str,
    ) -> Any:
        """Normalize a value based on applicable rules.

        Args:
            value: The value to normalize.
            resource_type: Azure resource type.
            path: Property path.

        Returns:
            Normalized value.
        """
        normalized = value

        for rule in self._rules:
            if rule.matches(resource_type, path):
                normalized = self._apply_normalization(normalized, rule)

        return normalized

    def _apply_normalization(
        self,
        value: Any,
        rule: NormalizationRule,
    ) -> Any:
        """Apply a specific normalization rule to a value.

        Args:
            value: The value to normalize.
            rule: The normalization rule.

        Returns:
            Normalized value.
        """
        match rule.normalization_type:
            case NormalizationType.EMPTY_EQUIVALENCE:
                return self._normalize_empty(value)
            case NormalizationType.BOOLEAN_NORMALIZE:
                return self._normalize_boolean(value)
            case NormalizationType.NUMERIC_STRING:
                return self._normalize_numeric_string(value)
            case NormalizationType.CASE_INSENSITIVE:
                return self._normalize_case(value)
            case NormalizationType.URL_NORMALIZE:
                return self._normalize_url(value)
            case NormalizationType.WHITESPACE_NORMALIZE:
                return self._normalize_whitespace(value)
            case NormalizationType.ARRAY_UNORDERED:
                return self._normalize_array_order(value)
            case NormalizationType.DEFAULT_VALUE:
                return self._normalize_default(value, rule.params.get("default"))
            case NormalizationType.TIMESTAMP_TOLERANCE:
                return value  # Timestamps handled specially in comparison
            case _:
                return value

    def _normalize_empty(self, value: Any) -> Any:
        """Normalize empty values to None.

        [], {}, "", null all become None for comparison.
        """
        if value is None:
            return None
        if isinstance(value, str) and value == "":
            return None
        if isinstance(value, list) and len(value) == 0:
            return None
        if isinstance(value, dict) and len(value) == 0:
            return None
        return value

    def _normalize_boolean(self, value: Any) -> bool | Any:
        """Normalize boolean-like values to actual booleans.

        "true", "True", "TRUE", 1, True -> True
        "false", "False", "FALSE", 0, False -> False
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() in ("true", "yes", "1", "on"):
                return True
            if value.lower() in ("false", "no", "0", "off"):
                return False
        if isinstance(value, int):
            if value == 1:
                return True
            if value == 0:
                return False
        return value

    def _normalize_numeric_string(self, value: Any) -> int | float | Any:
        """Normalize numeric strings to numbers.

        "100" -> 100
        "3.14" -> 3.14
        """
        if isinstance(value, int | float):
            return value
        if isinstance(value, str):
            try:
                if "." in value:
                    return float(value)
                return int(value)
            except ValueError:
                pass
        return value

    def _normalize_case(self, value: Any) -> str | Any:
        """Normalize string case for case-insensitive comparison."""
        if isinstance(value, str):
            return value.lower()
        return value

    def _normalize_url(self, value: Any) -> str | Any:
        """Normalize URLs.

        - Remove trailing slashes
        - Lowercase scheme
        """
        if isinstance(value, str):
            lower = value.lower()
            if lower.startswith("http://") or lower.startswith("https://"):
                # Find the scheme part (up to ://)
                scheme_end = value.index("://")
                value = value[:scheme_end].lower() + value[scheme_end:]
                # Remove trailing slash
                value = value.rstrip("/")
        return value

    def _normalize_whitespace(self, value: Any) -> str | Any:
        """Normalize whitespace in strings.

        - Collapse multiple spaces
        - Normalize line endings
        - Strip leading/trailing whitespace
        """
        if isinstance(value, str):
            # Normalize line endings
            value = value.replace("\r\n", "\n").replace("\r", "\n")
            # Collapse multiple spaces (but preserve newlines)
            lines = value.split("\n")
            lines = [" ".join(line.split()) for line in lines]
            value = "\n".join(lines)
            # Strip
            value = value.strip()
        return value

    def _normalize_array_order(self, value: Any) -> tuple | Any:
        """Normalize array order by sorting.

        For comparison, arrays are sorted to make order irrelevant.
        Returns a tuple for hashability.
        """
        if isinstance(value, list):
            try:
                # Try to sort - may fail for complex objects
                sorted_list = sorted(value, key=lambda x: str(x))
                return tuple(sorted_list)
            except TypeError:
                # Can't sort, return as-is
                return value
        return value

    def _normalize_default(self, value: Any, default: Any) -> Any:
        """Handle default value equivalence.

        If value is None/missing and default is provided, return default.
        """
        if value is None:
            return default
        return value

    def are_equivalent(
        self,
        before: Any,
        after: Any,
        resource_type: str,
        path: str,
    ) -> tuple[bool, str | None]:
        """Check if two values are semantically equivalent.

        Args:
            before: Value before change.
            after: Value after change.
            resource_type: Azure resource type.
            path: Property path.

        Returns:
            Tuple of (are_equivalent, reason_if_equivalent).
        """
        # Normalize both values
        normalized_before = self.normalize_value(before, resource_type, path)
        normalized_after = self.normalize_value(after, resource_type, path)

        # Compare normalized values
        if normalized_before == normalized_after:
            reason = self._get_equivalence_reason(before, after, resource_type, path)
            return True, reason

        # Deep comparison for complex types
        if self._deep_equal(normalized_before, normalized_after):
            reason = self._get_equivalence_reason(before, after, resource_type, path)
            return True, reason

        return False, None

    def _deep_equal(self, a: Any, b: Any) -> bool:
        """Deep equality check for complex nested structures."""
        if type(a) is not type(b):
            return False

        if isinstance(a, dict):
            if set(a.keys()) != set(b.keys()):
                return False
            return all(self._deep_equal(a[k], b[k]) for k in a)

        if isinstance(a, list | tuple):
            if len(a) != len(b):
                return False
            return all(self._deep_equal(x, y) for x, y in zip(a, b, strict=True))

        return a == b

    def _get_equivalence_reason(
        self,
        _before: Any,
        _after: Any,
        resource_type: str,
        path: str,
    ) -> str:
        """Get the reason why two values are considered equivalent."""
        for rule in self._rules:
            if rule.matches(resource_type, path):
                return rule.reason or f"Normalized via {rule.normalization_type.value}"
        return "Values are semantically equivalent after normalization"


@dataclass
class NormalizationConfig:
    """Configuration for diff normalization.

    Attributes:
        rules: Custom normalization rules.
        enable_default_rules: Whether to include default rules.
        log_normalizations: Whether to log when normalizations are applied.
    """

    rules: list[NormalizationRule] = field(default_factory=list)
    enable_default_rules: bool = True
    log_normalizations: bool = True

    @classmethod
    def from_env(cls) -> NormalizationConfig:
        """Load configuration from environment.

        Environment Variables:
            ENABLE_DEFAULT_NORMALIZATION_RULES: If "false", disable defaults
            LOG_NORMALIZATIONS: If "false", don't log normalizations

        Returns:
            Configured NormalizationConfig instance.
        """
        return cls(
            enable_default_rules=os.environ.get(
                "ENABLE_DEFAULT_NORMALIZATION_RULES", "true"
            ).lower() in ("true", "1", "yes"),
            log_normalizations=os.environ.get(
                "LOG_NORMALIZATIONS", "true"
            ).lower() in ("true", "1", "yes"),
        )


class WhatIfDiffProcessor:
    """Processes WhatIf results with normalization.

    Combines ignore rules and normalization to produce clean,
    actionable drift detection results.
    """

    def __init__(
        self,
        normalizer: DiffNormalizer | None = None,
        config: NormalizationConfig | None = None,
    ) -> None:
        """Initialize processor.

        Args:
            normalizer: Custom DiffNormalizer instance.
            config: Normalization configuration.
        """
        self._config = config or NormalizationConfig.from_env()
        self._normalizer = normalizer or DiffNormalizer(
            rules=self._config.rules,
            enable_default_rules=self._config.enable_default_rules,
        )

    @property
    def normalizer(self) -> DiffNormalizer:
        """Get the normalizer instance."""
        return self._normalizer

    def process_property_change(
        self,
        resource_type: str,
        path: str,
        before: Any,
        after: Any,
    ) -> tuple[bool, str | None]:
        """Process a single property change.

        Args:
            resource_type: Azure resource type.
            path: Property path.
            before: Value before change.
            after: Value after change.

        Returns:
            Tuple of (is_significant_change, reason_if_not).
        """
        is_equivalent, reason = self._normalizer.are_equivalent(
            before, after, resource_type, path
        )

        if is_equivalent:
            if self._config.log_normalizations:
                logger.debug(
                    "Change normalized away",
                    extra={
                        "resource_type": resource_type,
                        "path": path,
                        "before": before,
                        "after": after,
                        "reason": reason,
                    },
                )
            return False, reason

        return True, None

    def filter_delta(
        self,
        resource_type: str,
        delta: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        """Filter a delta list to remove semantically equivalent changes.

        Args:
            resource_type: Azure resource type.
            delta: List of property changes from WhatIf.

        Returns:
            Tuple of (filtered_delta, normalized_away_count).
        """
        filtered: list[dict[str, Any]] = []
        normalized_count = 0

        for change in delta:
            path = change.get("path", "")
            before = change.get("before")
            after = change.get("after")

            is_significant, _ = self.process_property_change(
                resource_type, path, before, after
            )

            if is_significant:
                filtered.append(change)
            else:
                normalized_count += 1

        return filtered, normalized_count


def create_diff_processor_from_env() -> WhatIfDiffProcessor:
    """Create a WhatIfDiffProcessor from environment configuration.

    Returns:
        Configured WhatIfDiffProcessor.
    """
    config = NormalizationConfig.from_env()
    return WhatIfDiffProcessor(config=config)
