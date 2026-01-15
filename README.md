# Azure Landing Zone Operator

> **A better operational model than "run pipelines occasionally."**
>
> *Continuous reconciliation. Per-domain identities. ACI isolation. The operator pattern that cloud infrastructure deserves.*

A **Go-based, stateless operator framework** for continuously reconciling Azure Landing Zones. Inspired by Kubernetes controller patterns, designed for Azure's unique characteristics.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fflavioaiello%2Fazure-operator%2Fmain%2Fportal%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fflavioaiello%2Fazure-operator%2Fmain%2Fportal%2FcreateUiDefinition.json)

[![Go 1.24+](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Azure SDK](https://img.shields.io/badge/Azure%20SDK-Latest-0078D4.svg)](https://github.com/Azure/azure-sdk-for-go)
[![AVM Modules](https://img.shields.io/badge/Bicep-AVM%20Modules-0078D4.svg)](https://aka.ms/avm)
[![Security: Secretless](https://img.shields.io/badge/security-secretless-brightgreen.svg)](#secretless-architecture-mandatory)

---

## Architecture

This project is split into two repositories:

| Repository | Purpose | Language |
|------------|---------|----------|
| **[azure-controller](https://github.com/flavioaiello/azure-controller)** | Generic reconciliation engine | Go |
| **azure-operator** (this repo) | Azure Landing Zone specs, templates, and CLI | Go + Bicep |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         azure-controller                                     │
│                    (Generic Reconciliation Engine)                           │
│                                                                              │
│  pkg/                                                                        │
│  ├── reconciler/      # Core reconciliation loop with SpecLoader interface  │
│  ├── provisioner/     # Identity + RBAC provisioning                        │
│  ├── deploy/          # ARM deployment execution                            │
│  ├── whatif/          # WhatIf drift detection                              │
│  ├── guardrails/      # Safety limits, kill switch                          │
│  ├── config/          # Configuration management                            │
│  ├── auth/            # Managed Identity enforcement                        │
│  ├── graph/           # Resource Graph queries                              │
│  ├── dependency/      # Operator ordering                                   │
│  ├── pause/           # Time-bound pause/resume                             │
│  ├── approval/        # Confidence scoring, approval gates                  │
│  ├── provenance/      # Audit trail logging                                 │
│  ├── stacks/          # Deployment stacks protection                        │
│  ├── modes/           # observe/enforce/protect modes                       │
│  ├── diff/            # Diff normalization                                  │
│  ├── ignore/          # Ignore rules for WhatIf noise                       │
│  └── validate/        # Spec validation                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ imports
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         azure-operator                                       │
│                    (Azure Landing Zone Implementation)                       │
│                                                                              │
│  pkg/                                                                        │
│  ├── specs/           # Landing zone spec models (connectivity, security)   │
│  └── loader/          # SpecLoader implementation for YAML/templates        │
│                                                                              │
│  cmd/                                                                        │
│  └── azo/             # CLI tool for dev, build, run, deploy                │
│                                                                              │
│  archetypes/          # 9 pre-configured landing zone patterns              │
│  bicep/               # Bicep templates (built on AVM)                      │
│  templates/           # Compiled ARM JSON templates                         │
│  infrastructure/      # Operator deployment infrastructure                  │
│  portal/              # Azure Portal deployment UI                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why Operators Beat Pipelines

**The core insight:** Landing zones aren't a one-time deployment — they're living infrastructure that drifts. Pipelines run when you remember to trigger them. Operators run continuously.

| Pipeline Model | Operator Model |
|----------------|----------------|
| Run occasionally, hope nothing drifted | **Continuous reconciliation** — drift detected and corrected automatically |
| Single pipeline identity with broad permissions | **Per-domain identities** — each operator has least-privilege RBAC |
| Shared runners, shared blast radius | **ACI isolation** — each operator runs in its own container |
| Terraform state files introduce drift risk | **ARM is the source of truth** — no external state to corrupt |
| Manual intervention to detect drift | **GitOps-native** — desired state in Git, reconciled continuously |

### The Three Pillars

1. **Continuous Reconciliation**
   - Every operator runs a control loop: detect drift → plan changes → apply (or alert)
   - Hybrid detection: Resource Graph for fast-path (~2s), WhatIf for authoritative diff
   - Circuit breaker pattern prevents runaway remediation

2. **Per-Domain Identities**
   - 21 operator types, each with a distinct managed identity
   - Firewall operator can't touch DNS. DNS operator can't touch RBAC.
   - Compromise of one operator doesn't compromise the landing zone

3. **ACI Isolation**
   - Each operator is a separate container instance
   - No shared runtime, no shared secrets, no shared failure modes
   - Private VNet deployment — no public IP addresses

---

## Separation of Concerns

Each operator manages a **single concern** with its own:
- **Container instance** — Isolated process, independent lifecycle
- **Managed identity** — Unique identity with least-privilege RBAC
- **Spec file** — Concern-specific YAML configuration
- **Bicep template** — Concern-specific resource definitions

### Granular Operators (21 types)

| Category | Operator | Scope | Resources | RBAC |
|----------|----------|-------|-----------|------|
| **Hub-Spoke** | `firewall` | Subscription | Azure Firewall, policies | Network Contributor |
| | `vpn-gateway` | Subscription | VPN Gateway, connections | Network Contributor |
| | `expressroute` | Subscription | ExpressRoute Gateway | Network Contributor |
| | `bastion` | Subscription | Azure Bastion | Network Contributor |
| | `dns` | Subscription | Private DNS zones | Private DNS Zone Contributor |
| | `hub-network` | Subscription | Hub VNet, subnets, peerings | Network Contributor |
| **vWAN** | `vwan` | Subscription | Virtual WAN only | Network Contributor |
| | `vwan-hub` | Subscription | Virtual Hub | Network Contributor |
| | `vwan-firewall` | Subscription | Azure Firewall in Secured Hub | Network Contributor |
| | `vwan-vpn-gateway` | Subscription | VPN Gateway in vWAN | Network Contributor |
| | `vwan-expressroute` | Subscription | ExpressRoute in vWAN | Network Contributor |
| **Management** | `log-analytics` | Subscription | Log Analytics workspaces | Log Analytics Contributor |
| | `automation` | Subscription | Automation accounts | Automation Contributor |
| | `monitor` | Subscription | DCRs, alerts | Monitoring Contributor |
| **Security** | `defender` | Subscription | Defender for Cloud | Security Admin |
| | `keyvault` | Subscription | Key Vaults | Key Vault Administrator |
| | `sentinel` | Subscription | Microsoft Sentinel | Log Analytics + Security Admin |
| **Governance** | `management-group` | Management Group | MG hierarchy | MG Contributor |
| | `role` | Management Group | Custom roles, RBAC | User Access Administrator |

---

## Project Structure

```
azure-operator/
├── cmd/
│   └── azo/                    # CLI tool
│       └── main.go
├── pkg/
│   ├── specs/                  # Landing zone spec models
│   │   ├── base.go            # BaseSpec interface
│   │   ├── connectivity.go    # ConnectivitySpec
│   │   ├── security.go        # SecuritySpec
│   │   ├── management.go      # ManagementSpec
│   │   ├── identity.go        # IdentitySpec
│   │   ├── bastion.go         # BastionSpec
│   │   ├── firewall.go        # FirewallSpec
│   │   └── ...
│   └── loader/                 # SpecLoader implementation
│       ├── loader.go          # YAML/template loading
│       └── loader_test.go
├── archetypes/                 # Pre-configured patterns
│   ├── 1-multi-region-hub-spoke-azfw/
│   ├── 2-multi-region-vwan-azfw/
│   ├── 3-multi-region-hub-spoke-nva/
│   ├── 4-multi-region-vwan-nva/
│   ├── 5-management-only/
│   ├── 6-single-region-hub-spoke-azfw/  ⭐ Recommended
│   ├── 7-single-region-vwan-azfw/
│   ├── 8-single-region-hub-spoke-nva/
│   └── 9-single-region-vwan-nva/
├── bicep/                      # Bicep templates (AVM-based)
│   ├── connectivity/main.bicep
│   ├── management/main.bicep
│   ├── security/main.bicep
│   └── identity/main.bicep
├── templates/                  # Compiled ARM JSON
├── infrastructure/             # Operator deployment
│   ├── main.bicep
│   └── rbac.bicep
├── portal/                     # Azure Portal UI
├── build/
│   ├── Dockerfile             # Operator container
│   └── Dockerfile.git-sync    # Git-sync sidecar
├── go.mod
├── go.sum
└── README.md
```

---

## Quick Start

### Prerequisites

- Go 1.24+
- Azure CLI with Bicep extension
- Docker
- Azure Container Registry

### 1. Build Operator Image

```bash
# Build static Go binary in scratch container (~10MB)
docker build -t azure-operator:latest -f build/Dockerfile .

# Push to Azure Container Registry
az acr login --name youracr
docker tag azure-operator:latest youracr.azurecr.io/azure-operator:latest
docker push youracr.azurecr.io/azure-operator:latest
```

### 2. Deploy Infrastructure

```bash
# Deploy ACI operators with VNet isolation
az deployment sub create \
  --location westeurope \
  --template-file infrastructure/main.bicep \
  --parameters @infrastructure/main.example.bicepparam
```

### 3. Configure Specs

Choose an archetype and customize:

```yaml
# archetypes/6-single-region-hub-spoke-azfw/specs/hub-network.yaml
apiVersion: azure-operator/v1
kind: HubNetworkOperator
metadata:
  name: hub-network-primary
spec:
  location: westeurope
  resourceGroupName: rg-alz-connectivity
  virtualNetwork:
    name: vnet-hub
    addressSpace: "10.0.0.0/16"
  tags:
    environment: production
    managedBy: azure-operator
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPERATOR_NAME` | Domain to reconcile (e.g., `firewall`, `hub-network`) | Required |
| `AZURE_SUBSCRIPTION_ID` | Target subscription ID | Required |
| `AZURE_LOCATION` | Azure region (e.g., `westeurope`) | Required |
| `SPEC_DIR` | Path to YAML spec files | Required |
| `RECONCILE_INTERVAL` | Loop interval | `5m` |
| `RECONCILIATION_MODE` | `observe`, `enforce`, or `protect` | `observe` |

### Reconciliation Modes

| Mode | Behavior |
|------|----------|
| **observe** | Detect drift only, log changes (default) |
| **enforce** | Auto-fix drift, apply changes |
| **protect** | Block changes that violate invariants |

### Guardrails

| Variable | Description | Default |
|----------|-------------|---------|
| `KILL_SWITCH` | Emergency stop - blocks all deployments | `false` |
| `MAX_CREATE_PER_CYCLE` | Max resources to create per cycle | `50` |
| `MAX_DELETE_PER_CYCLE` | Max resources to delete per cycle | `10` |
| `MAX_MODIFY_PER_CYCLE` | Max resources to modify per cycle | `100` |

---

## Security Model

### Secretless Architecture (Mandatory)

This framework enforces a **secretless security model**:

- ✅ User-Assigned Managed Identities only
- ✅ Ephemeral Entra ID tokens (never stored)
- ❌ No `AZURE_CLIENT_SECRET`
- ❌ No stored credentials or API keys

**Enforcement:** The operator will **fail to start** if credential environment variables are detected.

### Defense in Depth

```
Layer 1: Network Isolation
├── Private VNet (no public IPs)
├── NSG: Deny all inbound
└── NSG: Outbound to Azure service tags only

Layer 2: Identity Isolation
├── One managed identity per operator
├── Least-privilege RBAC per domain
└── No shared credentials

Layer 3: Compute Isolation
├── One ACI container per operator
├── Scratch image (~10MB, no shell)
└── Read-only spec volume

Layer 4: Data Isolation
├── Git-synced specs (auditable changes)
├── Structured JSON logging
└── No persistent storage (stateless)
```

---

## Archetypes

Pre-configured deployment patterns matching ALZ Accelerator archetypes.

| # | Archetype | Topology | Firewall | Regions |
|---|----------|----------|----------|---------|
| 1 | Multi-Region Hub-Spoke + Azure Firewall | Hub-Spoke | Azure | 2 |
| 2 | Multi-Region Virtual WAN + Azure Firewall | vWAN | Azure | 2 |
| 3 | Multi-Region Hub-Spoke + NVA | Hub-Spoke | NVA | 2 |
| 4 | Multi-Region Virtual WAN + NVA | vWAN | NVA | 2 |
| **5** | **Management Only** | None | None | 1 |
| **6** | **Single-Region Hub-Spoke + Azure Firewall** ⭐ | Hub-Spoke | Azure | 1 |
| 7 | Single-Region Virtual WAN + Azure Firewall | vWAN | Azure | 1 |
| 8 | Single-Region Hub-Spoke + NVA | Hub-Spoke | NVA | 1 |
| 9 | Single-Region Virtual WAN + NVA | vWAN | NVA | 1 |

⭐ **Recommended starting point**

---

## CLI Reference

The `azo` CLI provides development, build, and deployment commands:

```bash
# Development
azo dev setup      # Set up development environment
azo dev test       # Run tests
azo dev lint       # Lint code

# Build
azo build image    # Build Docker image
azo build templates # Compile Bicep to ARM JSON

# Run
azo run management # Run operator locally
azo run connectivity --no-dry-run

# Deploy
azo deploy infra   # Deploy infrastructure
azo deploy rbac    # Deploy RBAC
```

---

## Development

```bash
# Clone both repositories
git clone https://github.com/flavioaiello/azure-controller
git clone https://github.com/flavioaiello/azure-operator

# Build and test
cd azure-operator
go build ./...
go test ./...

# Run locally
export AZURE_SUBSCRIPTION_ID="your-sub-id"
export SPEC_DIR="./archetypes/6-single-region-hub-spoke-azfw/specs"
go run ./cmd/azo run management
```

---

## Related Projects

- **[azure-controller](https://github.com/flavioaiello/azure-controller)** — Generic reconciliation engine (required dependency)
- **[Enterprise Policy as Code (EPAC)](https://aka.ms/epac)** — Recommended for Azure Policy management
- **[Azure Verified Modules (AVM)](https://aka.ms/avm)** — Microsoft's official Bicep module library

---

## License

MIT
