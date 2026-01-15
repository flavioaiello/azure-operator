"""Azure API Mock for Integration Testing.

This module provides a mock implementation of Azure Resource Manager APIs
that enables integration testing without actual Azure connectivity.

Key Features:
- In-memory state management for resources
- WhatIf API simulation with realistic change detection
- Deployment lifecycle simulation (running → succeeded/failed)
- Error injection for testing failure scenarios
- Managed Identity simulation
- Resource Graph simulation for fast-path drift detection

Usage:
    from tests.azure_mock import MockAzureContext, create_mock_credential

    with MockAzureContext() as ctx:
        # Inject the mock credential
        credential = create_mock_credential()

        # Your test code here
        reconciler = Reconciler(config)
        await reconciler._reconcile_once()

        # Assert on mock state
        assert ctx.get_deployment_count() == 1
"""

from .context import MockAzureContext
from .credential import MockManagedIdentityCredential, create_mock_credential
from .graph import MockGraphChange, MockGraphResource, MockResourceGraphClient, create_mock_graph_client
from .resources import MockResourceClient, MockResourceState

__all__ = [
    "MockAzureContext",
    "MockGraphChange",
    "MockGraphResource",
    "MockManagedIdentityCredential",
    "MockResourceClient",
    "MockResourceGraphClient",
    "MockResourceState",
    "create_mock_credential",
    "create_mock_graph_client",
]
