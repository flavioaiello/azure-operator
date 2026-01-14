"""Spec file loading with validation.

SECURITY: All file operations enforce size limits to prevent DoS attacks
via large files. Input validation is performed at the boundary.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .config import MAX_SPEC_FILE_SIZE_BYTES, MAX_TEMPLATE_FILE_SIZE_BYTES
from .models import BaseSpec, get_spec_class

logger = logging.getLogger(__name__)


class SpecLoadError(Exception):
    """Raised when spec loading or validation fails."""

    pass


# =============================================================================
# Operator to Template Mapping
# =============================================================================
# Granular operators map to domain templates. Each domain template bundles
# related resources but operators only deploy their specific resource type.
#
# This mapping allows:
# - Granular operators (firewall, bastion, etc.) to use bundled domain templates
# - Template reuse across related operators
# - Backward compatibility with legacy domain structure

OPERATOR_TO_TEMPLATE: dict[str, str] = {
    # Bootstrap operator - uses identity template for UAMI provisioning
    "bootstrap": "identity",
    # Connectivity operators → connectivity template
    "firewall": "connectivity",
    "vpn-gateway": "connectivity",
    "expressroute": "connectivity",
    "bastion": "connectivity",
    "dns": "connectivity",
    "hub-network": "connectivity",
    # vWAN operators → connectivity template
    "vwan": "connectivity",
    "vwan-hub": "connectivity",
    "vwan-firewall": "connectivity",
    "vwan-vpn-gateway": "connectivity",
    "vwan-expressroute": "connectivity",
    # Management operators → management template
    "log-analytics": "management",
    "automation": "management",
    "monitor": "management",
    # Security operators → security template
    "defender": "security",
    "keyvault": "security",
    "sentinel": "security",
    # Governance operators → identity template
    "management-group": "identity",
    "role": "identity",
    # Secondary region operators (same template as primary)
    "bastion-secondary": "connectivity",
    "firewall-secondary": "connectivity",
    "hub-network-secondary": "connectivity",
    "vpn-gateway-secondary": "connectivity",
    "expressroute-secondary": "connectivity",
    "dns-secondary": "connectivity",
    "vwan-hub-secondary": "connectivity",
    "vwan-firewall-secondary": "connectivity",
    "vwan-vpn-gateway-secondary": "connectivity",
    "vwan-expressroute-secondary": "connectivity",
}


def get_template_for_operator(operator: str) -> str:
    """Get the template name for a given operator.

    Args:
        operator: The operator name (e.g., "firewall", "bastion").

    Returns:
        Template name (e.g., "connectivity", "management").

    Raises:
        ValueError: If operator is not recognized.
    """
    template = OPERATOR_TO_TEMPLATE.get(operator)
    if template is None:
        valid_operators = list(OPERATOR_TO_TEMPLATE.keys())
        raise ValueError(f"Unknown operator '{operator}'. Valid operators: {valid_operators}")
    return template


def load_spec(specs_dir: Path, domain: str) -> BaseSpec:
    """Load and validate a domain spec from YAML.

    Args:
        specs_dir: Directory containing spec files.
        domain: The domain name (e.g., "management", "connectivity").

    Returns:
        Validated spec instance.

    Raises:
        SpecLoadError: If the spec cannot be loaded or fails validation.
    """
    spec_path = specs_dir / f"{domain}.yaml"

    if not spec_path.exists():
        raise SpecLoadError(f"Spec file not found: {spec_path}")

    # SECURITY: Check file size before reading to prevent DoS
    try:
        file_size = spec_path.stat().st_size
    except OSError as e:
        raise SpecLoadError(f"Failed to stat spec file {spec_path}: {e}") from e

    if file_size > MAX_SPEC_FILE_SIZE_BYTES:
        raise SpecLoadError(
            f"Spec file exceeds maximum size of {MAX_SPEC_FILE_SIZE_BYTES} bytes: {spec_path}"
        )

    try:
        content = spec_path.read_text(encoding="utf-8")
    except OSError as e:
        raise SpecLoadError(f"Failed to read spec file {spec_path}: {e}") from e

    try:
        raw_data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise SpecLoadError(f"Invalid YAML in {spec_path}: {e}") from e

    if not isinstance(raw_data, dict):
        raise SpecLoadError(f"Spec file must contain a YAML mapping: {spec_path}")

    # SECURITY: Support both flat format and Kubernetes-style wrapper
    # If the file has apiVersion/kind/spec, extract the spec section
    if "apiVersion" in raw_data and "spec" in raw_data:
        # Kubernetes-style format: apiVersion, kind, metadata, spec
        spec_data = raw_data.get("spec", {})
        if not isinstance(spec_data, dict):
            raise SpecLoadError(f"Spec section must be a mapping: {spec_path}")
    else:
        # Flat format: direct spec content
        spec_data = raw_data

    try:
        spec_class = get_spec_class(domain)
    except ValueError as e:
        raise SpecLoadError(str(e)) from e

    try:
        spec = spec_class.model_validate(spec_data)
    except ValidationError as e:
        # Format Pydantic validation errors for readability
        errors = []
        for error in e.errors():
            loc = ".".join(str(x) for x in error["loc"])
            msg = error["msg"]
            errors.append(f"  - {loc}: {msg}")

        error_list = "\n".join(errors)
        raise SpecLoadError(f"Validation failed for {spec_path}:\n{error_list}") from e

    logger.info("Loaded spec for domain '%s' from %s", domain, spec_path)
    return spec


def load_template(templates_dir: Path, operator: str) -> dict[str, Any]:
    """Load a compiled ARM template JSON for an operator.

    Granular operators (firewall, bastion, etc.) are mapped to their
    domain template (connectivity, management, etc.) via OPERATOR_TO_TEMPLATE.

    Args:
        templates_dir: Directory containing compiled ARM JSON templates.
        operator: The operator name (e.g., "firewall", "log-analytics").

    Returns:
        Parsed ARM template as a dictionary.

    Raises:
        SpecLoadError: If the template cannot be loaded.
    """
    import json

    # Map operator to its domain template
    try:
        template_name = get_template_for_operator(operator)
    except ValueError as e:
        raise SpecLoadError(str(e)) from e

    template_path = templates_dir / f"{template_name}.json"

    if not template_path.exists():
        raise SpecLoadError(
            f"Template file not found: {template_path}. "
            f"Operator '{operator}' requires template '{template_name}'."
        )

    # SECURITY: Check file size before reading to prevent DoS
    try:
        file_size = template_path.stat().st_size
    except OSError as e:
        raise SpecLoadError(f"Failed to stat template file {template_path}: {e}") from e

    if file_size > MAX_TEMPLATE_FILE_SIZE_BYTES:
        raise SpecLoadError(
            f"Template file exceeds maximum size of "
            f"{MAX_TEMPLATE_FILE_SIZE_BYTES} bytes: {template_path}"
        )

    try:
        content = template_path.read_text(encoding="utf-8")
    except OSError as e:
        raise SpecLoadError(f"Failed to read template file {template_path}: {e}") from e

    try:
        template = json.loads(content)
    except json.JSONDecodeError as e:
        raise SpecLoadError(f"Invalid JSON in {template_path}: {e}") from e

    if not isinstance(template, dict):
        raise SpecLoadError(f"Template must be a JSON object: {template_path}")

    logger.info(
        "Loaded template '%s' for operator '%s' from %s",
        template_name,
        operator,
        template_path,
    )
    return template
