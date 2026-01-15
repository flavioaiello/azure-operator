# Azure Landing Zone Operator

> **Landing Zones, and Enterprise Runways.**
>
> *Continuous reconciliation. Secretless. GitOps-native. The operator pattern that cloud infrastructure deserves.*

A **Python-based, stateless operator framework** for continuously reconciling Azure Landing Zones. Inspired by Kubernetes controller patterns, designed for Azure's unique characteristics.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fflavioaiello%2Fazure-operator%2Fmain%2Fportal%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fflavioaiello%2Fazure-operator%2Fmain%2Fportal%2FcreateUiDefinition.json)

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Pydantic v2](https://img.shields.io/badge/pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Azure SDK](https://img.shields.io/badge/Azure%20SDK-Latest-0078D4.svg)](https://github.com/Azure/azure-sdk-for-python)
[![Security: Secretless](https://img.shields.io/badge/security-secretless-brightgreen.svg)](#secretless-architecture-mandatory)
[![Tests: 67 passing](https://img.shields.io/badge/tests-67%20passing-brightgreen.svg)](tests/)
[![DeepWiki](https://img.shields.io/badge/DeepWiki-flavioaiello%2Fazure--operator-blue.svg?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNCAxOWg0djJINHoiLz48cGF0aCBkPSJNMTAgMTloNHYyaC00eiIvPjxwYXRoIGQ9Ik0xNiAxOWg0djJoLTR6Ii8+PHBhdGggZD0iTTQgMTFoMTZ2Mkg0eiIvPjxwYXRoIGQ9Ik00IDNoMTZ2Mkg0eiIvPjxwYXRoIGQ9Ik04IDN2MTYiLz48cGF0aCBkPSJNMTYgM3YxNiIvPjwvc3ZnPg==)](https://deepwiki.com/flavioaiello/azure-operator)



## Why an Operator Framework?

Traditional Azure Landing Zone deployments suffer from:

| Problem | Impact |
|---------|--------|
| **One-off bootstrapping** | Infrastructure drifts from desired state over time |
| **Terraform state files** | External state introduces drift risk and lock contention |
| **Monolithic deployments** | All concerns coupled, single failure breaks everything |
| **Manual reconciliation** | Drift detection requires human intervention |

The **Azure Operator Framework** solves these by:

- **Continuous reconciliation** — Desired state is constantly compared to actual state
- **ARM as the source of truth** — No external state files, Azure IS the state
- **Separation of concerns** — Each domain operates independently
- **Loose coupling** — Operators don't depend on each other, reducing blast radius

---

## TL;DR

> **What:** Python operators that continuously reconcile Azure Landing Zones using GitOps.
>
> **How:** YAML specs → ARM WhatIf (drift detection) → ARM deployment (apply). No Terraform state files.
>
> **Policy:** Use [Enterprise Policy as Code (EPAC)](https://aka.ms/epac) for policy management — Microsoft's battle-tested solution.
>
> **Security:** Secretless architecture — Managed Identities only, zero stored credentials.
>
> **CLI:** `azo` — dev, build, run, and deploy commands (`azo run management`, `azo build image`, etc.).
>
> **Deploy:** Click "Deploy to Azure" button above, or `az deployment sub create -l westeurope -f portal/main.bicep`. See [Quick Start](#quick-start).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MANAGEMENT SUBSCRIPTION                              │
│                    (Isolated from managed resources)                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         PRIVATE VNET                                     ││
│  │                    (No Public IP addresses)                              ││
│  │                                                                          ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       ││
│  │  │ Firewall │ │ VPN GW   │ │ Bastion  │ │ DNS      │ │ Hub Net  │ ...   ││
│  │  │ Operator │ │ Operator │ │ Operator │ │ Operator │ │ Operator │       ││
│  │  │  (ACI)   │ │  (ACI)   │ │  (ACI)   │ │  (ACI)   │ │  (ACI)   │       ││
│  │  │          │ │          │ │          │ │          │ │          │       ││
│  │  │ UAMI-FW  │ │ UAMI-VPN │ │UAMI-Bast │ │ UAMI-DNS │ │ UAMI-Hub │       ││
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       ││
│  │         │               │               │               │               ││
│  │         └───────────────┼───────────────┼───────────────┘               ││
│  │                         │               │                                ││
│  │  ┌──────────────────────▼───────────────▼────────────────────┐          ││
│  │  │                 NSG: Deny All Inbound                      │          ││
│  │  │           Outbound: Azure Service Tags Only                │          ││
│  │  │     (AzureResourceManager, AzureAD, ACR, AzureMonitor)    │          ││
│  │  └───────────────────────────────────────────────────────────┘          ││
│  │                                                                          ││
│  │  ┌───────────────────────────────────────────────────────────┐          ││
│  │  │              PRIVATE ENDPOINT SUBNET                       │          ││
│  │  │         (ACR Private Endpoint, ARM Private Link)          │          ││
│  │  └───────────────────────────────────────────────────────────┘          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐                 │
│  │  Log Analytics │  │      ACR       │  │   Key Vault    │                 │
│  │   (Operator    │  │   (Operator    │  │  (Git Creds,   │                 │
│  │     Logs)      │  │    Images)     │  │    Secrets)    │                 │
│  └────────────────┘  └────────────────┘  └────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    Cross-Subscription RBAC │
                    (Least Privilege)       │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MANAGED SUBSCRIPTIONS                                │
│                                                                              │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐                │
│  │   Management    │ │   Connectivity  │ │    Security     │                │
│  │  Subscription   │ │  Subscription   │ │  Subscription   │                │
│  │                 │ │                 │ │                 │                │
│  │  • Log Analytics│ │  • Hub VNet     │ │  • Defender     │                │
│  │  • Automation   │ │  • Firewall     │ │  • Key Vaults   │                │
│  │  • DCRs         │ │  • VPN/ER GW    │ │  • Sentinel     │                │
│  │  • Identities   │ │  • Bastion      │ │                 │                │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘                │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐            │
│  │                   MANAGEMENT GROUP HIERARCHY                 │            │
│  │                                                              │            │
│  │               ┌─────────┐                                    │            │
│  │               │  Root   │ ◄── Identity Operators              │            │
│  │               └────┬────┘                                    │            │
│  │          ┌─────────┼─────────┐                               │            │
│  │     ┌────▼───┐ ┌───▼────┐ ┌──▼───┐                          │            │
│  │     │Platform│ │Landing │ │Sandbox│                          │            │
│  │     └────┬───┘ │ Zones  │ └──────┘                          │            │
│  │    ┌─────┼─────┤        │                                    │            │
│  │ ┌──▼──┐┌─▼─┐┌──▼──┐ ┌───▼───┐                               │            │
│  │ │Mgmt ││Con││Iden │ │Corp/On│                               │            │
│  │ └─────┘└───┘└─────┘ └───────┘                               │            │
│  └─────────────────────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Separation of Concerns

Each operator manages a **single concern** with its own:
- **Container instance** — Isolated process, independent lifecycle
- **Managed identity** — Unique identity with least-privilege RBAC
- **Spec file** — Concern-specific YAML configuration
- **Bicep template** — Concern-specific resource definitions

### Granular Operators (19 total + 10 secondary region aliases)

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

**Multi-Region Support:** Secondary region operators (`-secondary` suffix) reuse primary spec classes:
- Hub-Spoke: `bastion-secondary`, `firewall-secondary`, `hub-network-secondary`, `vpn-gateway-secondary`, `expressroute-secondary`, `dns-secondary`
- vWAN: `vwan-hub-secondary`, `vwan-firewall-secondary`, `vwan-vpn-gateway-secondary`, `vwan-expressroute-secondary`

---

## Policy Management

For Azure Policy management, we recommend [**Enterprise Policy as Code (EPAC)**](https://aka.ms/epac) — Microsoft's mature, battle-tested solution for policy-as-code.

### Why EPAC?

| Benefit | Description |
|---------|-------------|
| **Mature & Battle-tested** | Used by Microsoft and enterprises worldwide |
| **Separation of Concerns** | Policy lifecycle differs from infrastructure — manage them separately |
| **Reduced Blast Radius** | No Root MG privileges required from this operator |
| **Rich Feature Set** | Exemptions, assignments, initiatives, compliance reporting built-in |
| **Active Community** | Regular updates, comprehensive documentation, Microsoft support |

### Getting Started with EPAC

```bash
# Install EPAC module
Install-Module -Name EnterprisePolicyAsCode

# Initialize EPAC in your repo
New-EPACDefinitionsFolder -DefinitionsRootFolder Definitions

# Export existing policies
Export-AzPolicyResources -DefinitionsRootFolder Definitions -Mode export
```

For complete documentation, see [EPAC on GitHub](https://github.com/Azure/enterprise-azure-policy-as-code).

---

### Why One Operator Per Concern?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DOMAIN-BASED (5 Operators)                                │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────┐          │
│    │              Connectivity Operator                          │          │
│    │                                                              │          │
│    │  Firewall + VPN + ExpressRoute + Bastion + DNS + VNet       │          │
│    │                                                              │          │
│    │  ⚠️  Issues:                                                 │          │
│    │  • Firewall change requires full Contributor role           │          │
│    │  • One misconfiguration affects all network resources       │          │
│    │  • Blast radius = entire connectivity subscription          │          │
│    └─────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONCERN-BASED (20 Operators)                              │
│                                                                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │Firewall │ │VPN GW   │ │Express  │ │Bastion  │ │  DNS    │ │Hub VNet │   │
│  │Operator │ │Operator │ │Route Op │ │Operator │ │Operator │ │Operator │   │
│  │         │ │         │ │         │ │         │ │         │ │         │   │
│  │Network  │ │Network  │ │Network  │ │Network  │ │DNS Zone │ │Network  │   │
│  │Contrib  │ │Contrib  │ │Contrib  │ │Contrib  │ │Contrib  │ │Contrib  │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
│                                                                              │
│  ✅ Benefits:                                                                │
│  • Each operator has ONLY the permissions it needs                          │
│  • Firewall misconfiguration doesn't affect Bastion                         │
│  • Blast radius = single resource type                                      │
│  • Independent reconciliation schedules                                     │
│  • Easier to audit and troubleshoot                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Loose Coupling Matters

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TRADITIONAL MONOLITHIC APPROACH                           │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────┐          │
│    │              Single Deployment / State File                  │          │
│    │                                                              │          │
│    │  Management ──► Connectivity ──► Security                   │          │
│    │       ▲              │             │            │            │          │
│    │       └──────────────┴─────────────┴────────────┘            │          │
│    │                                                              │          │
│    │  ⚠️  Tight Coupling:                                         │          │
│    │  • Single failure blocks all domains                         │          │
│    │  • Changes require full deployment                           │          │
│    │  • State file drift affects everything                       │          │
│    │  • Blast radius = entire landing zone                        │          │
│    └─────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    OPERATOR FRAMEWORK APPROACH (16 Operators)                │
│                                                                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │Firewall │ │ VPN GW  │ │Bastion  │ │   DNS   │ │ Hub Net │ │  vWAN   │   │
│  │ Operator│ │Operator │ │Operator │ │Operator │ │Operator │ │Operator │   │
│  ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤   │
│  │ Spec    │ │ Spec    │ │ Spec    │ │ Spec    │ │ Spec    │ │ Spec    │   │
│  │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │   │
│  │ Azure   │ │ Azure   │ │ Azure   │ │ Azure   │ │ Azure   │ │ Azure   │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
│                                                                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │ Log     │ │Automaton│ │ Monitor │ │Defender │ │KeyVault │ │Sentinel │   │
│  │Analytics│ │Operator │ │Operator │ │Operator │ │Operator │ │Operator │   │
│  ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤   │
│  │ Spec    │ │ Spec    │ │ Spec    │ │ Spec    │ │ Spec    │ │ Spec    │   │
│  │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │ │ ↓ ARM   │   │
│  │ Azure   │ │ Azure   │ │ Azure   │ │ Azure   │ │ Azure   │ │ Azure   │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
│                                                                              │
│  ┌─────────────────┐                   ┌─────────────────┐ + ExpressRoute │
│  │ Management-Group│                   │  Role Operator  │                │
│  │     Operator    │                   │                 │                │
│  └─────────────────┘                   └─────────────────┘                │
│                                                                              │
│  ✅ Loose Coupling:                                                          │
│  • 16 operators run independently — failure in one doesn't affect others    │
│  • Each concern reconciles on its own schedule                              │
│  • Blast radius limited to single domain                                    │
│  • No shared state files — ARM is the source of truth                       │
│  • Continuous reconciliation succeeds because no cross-domain locks         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Continuous Reconciliation

Each operator runs an **infinite reconciliation loop**:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Reconciliation Cycle                                  │
│                                                                               │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐           │
│   │   Load   │ ──► │   Drift  │ ──► │   Apply  │ ──► │   Wait   │ ──┐       │
│   │   Spec   │     │   Check  │     │  Changes │     │ Interval │   │       │
│   │          │     │          │     │          │     │          │   │       │
│   │ Pydantic │     │  WhatIf  │     │  Deploy  │     │  Async   │   │       │
│   │Validation│     │   API    │     │   API    │     │  Sleep   │   │       │
│   └──────────┘     └──────────┘     └──────────┘     └──────────┘   │       │
│        ▲                                                  │          │       │
│        └──────────────────────────────────────────────────┘          │       │
│                                                                      │       │
│   ┌──────────────────────────────────────────────────────────────────┘       │
│   │                                                                          │
│   │   On Each Cycle:                                                         │
│   │   1. Load YAML spec (from git-synced volume)                             │
│   │   2. Validate with Pydantic models (fail-fast)                           │
│   │   3. Transform to ARM parameters                                         │
│   │   4. Call WhatIf API to detect drift                                     │
│   │   5. If drift: Deploy to apply changes                                   │
│   │   6. Log structured JSON results                                         │
│   │   7. Wait for next interval                                              │
│   │                                                                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Why Continuous Reconciliation Succeeds

| Factor | How Operator Framework Enables It |
|--------|-----------------------------------|
| **No state file locks** | ARM is the state — no lock contention between operators |
| **Independent cycles** | Each operator reconciles on its own schedule |
| **Idempotent deployments** | ARM deployments are naturally idempotent |
| **WhatIf pre-validation** | Drift detection without modification |
| **Bounded failure** | One operator failing doesn't block others |

---

## Security Model

### Secretless Architecture (Mandatory)

This framework enforces a **secretless security model** — there are zero secrets to manage, rotate, or leak:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECRETLESS ARCHITECTURE                                 │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         ZERO SECRETS                                     ││
│  │                                                                          ││
│  │  ❌ No AZURE_CLIENT_SECRET          ❌ No stored credentials             ││
│  │  ❌ No certificate passwords        ❌ No API keys                       ││
│  │  ❌ No connection strings           ❌ No username/password              ││
│  │                                                                          ││
│  │  ✅ User-Assigned Managed Identities (UAMIs) only                       ││
│  │  ✅ Ephemeral Azure AD tokens (never stored)                            ││
│  │  ✅ Automatic token refresh by Azure runtime                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  How Authentication Works:                                                   │
│                                                                              │
│  ┌──────────────┐     token request     ┌─────────────────────┐             │
│  │   Operator   │ ────────────────────► │  Azure AD/Entra ID  │             │
│  │   (ACI)      │                       │                     │             │
│  │              │ ◄──────────────────── │  Issues short-lived │             │
│  │   with UAMI  │     JWT token         │  JWT (~1hr validity)│             │
│  └──────────────┘                       └─────────────────────┘             │
│         │                                                                    │
│         │ Bearer token in header                                            │
│         ▼                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    Azure Resource Manager                                ││
│  │  • Validates token signature (Azure AD public keys)                     ││
│  │  • Checks RBAC: Does UAMI have permission for this operation?           ││
│  │  • Audit log: Records who did what (tied to UAMI identity)              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  Why This is Superior:                                                       │
│                                                                              │
│  │ Concern          │ Traditional (Secrets)   │ Secretless (UAMI)         │ │
│  │──────────────────│─────────────────────────│───────────────────────────│ │
│  │ Rotation         │ Manual, error-prone     │ Not needed                │ │
│  │ Leakage risk     │ High (logs, env vars)   │ Zero (no secrets exist)   │ │
│  │ Storage          │ Key Vault, env vars     │ None (ephemeral tokens)   │ │
│  │ Audit trail      │ "Service Principal X"   │ "UAMI firewall-op"        │ │
│  │ Blast radius     │ SP may have broad perms │ Scoped to single resource │ │
│  │ Revocation       │ Rotate secret           │ Delete UAMI or remove RBAC│ │
│  │──────────────────│─────────────────────────│───────────────────────────│ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Enforcement:** The operator will **fail to start** if credential environment variables are detected:
- `AZURE_CLIENT_SECRET`
- `AZURE_CLIENT_CERTIFICATE_PATH`
- `AZURE_CLIENT_CERTIFICATE_PASSWORD`
- `AZURE_USERNAME` / `AZURE_PASSWORD`

See [security.py](src/controller/security.py) for the enforcement implementation.

### Threat Model Considerations

The operator framework is designed with the following threat model:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         THREAT MODEL                                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Threat: Operator Compromise                                              ││
│  │                                                                          ││
│  │ Mitigation:                                                              ││
│  │ • Separate managed identity per operator (blast radius = 1 domain)      ││
│  │ • Least-privilege RBAC (only permissions needed for that domain)        ││
│  │ • No cross-operator communication (no lateral movement path)            ││
│  │ • Distroless image (no shell, minimal attack surface)                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Threat: Network-based Attack                                             ││
│  │                                                                          ││
│  │ Mitigation:                                                              ││
│  │ • Private VNet with no public IPs                                       ││
│  │ • NSG: Deny ALL inbound traffic                                         ││
│  │ • NSG: Outbound restricted to Azure service tags only                   ││
│  │ • Private endpoints for ACR (image pulls over private network)          ││
│  │ • Operators cannot receive unsolicited traffic                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Threat: Credential Theft                                                 ││
│  │                                                                          ││
│  │ Mitigation:                                                              ││
│  │ • Managed Identity only (no secrets in environment variables)           ││
│  │ • DefaultAzureCredential with IMDS (no credentials stored)              ││
│  │ • No credential rotation needed (Azure handles token lifecycle)         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Threat: Supply Chain Attack                                              ││
│  │                                                                          ││
│  │ Mitigation:                                                              ││
│  │ • Distroless base image (minimal dependencies)                          ││
│  │ • Private ACR (images not exposed to public)                            ││
│  │ • Git as source of truth (auditable spec changes)                       ││
│  │ • Bicep compiled at build time (no runtime compilation)                 ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Defense in Depth

```
Layer 1: Network Isolation
├── Private VNet (10.250.0.0/24)
├── No public IP addresses
├── NSG: Deny all inbound
└── NSG: Outbound to Azure service tags only
    ├── AzureResourceManager (ARM API)
    ├── AzureActiveDirectory (Token auth)
    ├── AzureContainerRegistry.{region}
    └── AzureMonitor (Logging)

Layer 2: Identity Isolation
├── One managed identity per operator
├── Least-privilege RBAC per domain
├── Cross-subscription scoped (not tenant-wide)
└── No shared credentials

Layer 3: Compute Isolation
├── One ACI container group per operator
├── Distroless image (~100MB, no shell)
├── Non-root execution (UID 65532)
└── Read-only spec volume

Layer 4: Data Isolation
├── Git-synced specs (auditable changes)
├── Pydantic validation (fail-fast on invalid input)
├── Structured JSON logging to Log Analytics
└── No persistent storage (stateless)
```

### RBAC Matrix (Fine-Grained)

| Category | Operator | Target Scope | Role | Justification |
|----------|----------|--------------|------|---------------|
| **Connectivity** | `firewall` | Connectivity Sub | Network Contributor | Manage Firewall only |
| | `vpn-gateway` | Connectivity Sub | Network Contributor | Manage VPN Gateway only |
| | `expressroute` | Connectivity Sub | Network Contributor | Manage ExpressRoute only |
| | `bastion` | Connectivity Sub | Network Contributor | Manage Bastion only |
| | `dns` | Connectivity Sub | Private DNS Zone Contributor | Manage DNS zones only |
| | `hub-network` | Connectivity Sub | Network Contributor | Manage Hub VNet only |
| | `vwan` | Connectivity Sub | Network Contributor | Manage Virtual WAN only |
| **Management** | `log-analytics` | Management Sub | Log Analytics Contributor | Manage workspaces only |
| | `automation` | Management Sub | Automation Contributor | Manage Automation only |
| | `monitor` | Management Sub | Monitoring Contributor | Manage DCRs/alerts only |
| **Security** | `defender` | Security Sub | Security Admin | Configure Defender only |
| | `keyvault` | Security Sub | Key Vault Administrator | Manage Key Vaults only |
| | `sentinel` | Security Sub | Log Analytics + Security Admin | Configure Sentinel |
| **Governance** | `management-group` | Root MG | MG Contributor | Manage MG hierarchy only |
| | `role` | Root MG | User Access Administrator | Manage RBAC only |

---

## Bootstrap Cascade Pattern

The bootstrap cascade pattern enables **ephemeral, zero-secret deployment** where operator identities are provisioned dynamically instead of pre-created.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BOOTSTRAP CASCADE PATTERN                                 │
│                                                                              │
│  PHASE 0: Infrastructure Pre-deployment (Bicep)                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │  Creates ONLY:                                                          ││
│  │  • Bootstrap Operator ACI container                                     ││
│  │  • Bootstrap Operator UAMI (with constrained UAA + MI Contributor)      ││
│  │  • Private VNet + NSG                                                   ││
│  │  • ACR (for operator images)                                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                              │                                               │
│                              ▼                                               │
│  PHASE 1: Bootstrap (Bootstrap Operator)                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │  ┌──────────────────┐                                                   ││
│  │  │  Bootstrap       │  Reads: bootstrap.yaml                            ││
│  │  │  Operator        │  Creates:                                         ││
│  │  │  (UAMI-Boot)     │  • 16 downstream UAMIs                            ││
│  │  │                  │  • RBAC role assignments per operator             ││
│  │  │  Constrained UAA │  • Operator ACI container groups (optional)       ││
│  │  └────────┬─────────┘                                                   ││
│  │           │                                                              ││
│  │           ▼                                                              ││
│  │  ┌────────────────────────────────────────────────────────────────────┐ ││
│  │  │  UAMI-FW   UAMI-VPN   UAMI-Bast   UAMI-DNS   UAMI-Hub   ...       │ ││
│  │  │  (Network  (Network   (Network    (DNS Zone  (Network             │ ││
│  │  │   Contrib)  Contrib)   Contrib)    Contrib)   Contrib)            │ ││
│  │  └────────────────────────────────────────────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                              │                                               │
│                              ▼                                               │
│  PHASE 2: Operator Startup (All Others)                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │  Each operator:                                                         ││
│  │  1. Polls for its UAMI to exist (via ARM API)                          ││
│  │  2. Waits for RBAC propagation (~2 min)                                ││
│  │  3. Starts reconciliation loop                                         ││
│  │                                                                          ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           ││
│  │  │Firewall │ │ VPN GW  │ │ Bastion │ │   DNS   │ │ Hub Net │ ...       ││
│  │  │         │ │         │ │         │ │         │ │         │           ││
│  │  │UAMI-FW  │ │UAMI-VPN │ │UAMI-Bast│ │UAMI-DNS │ │UAMI-Hub │           ││
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘           ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  KEY: All tokens remain EPHEMERAL — fetched via IMDS from provisioned UAMIs│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Bootstrap Operator Configuration

The bootstrap operator uses `bootstrap.yaml` to define all downstream identities:

```yaml
apiVersion: azure-operator/v1
kind: BootstrapOperator
metadata:
  name: operator-identities

spec:
  location: westeurope
  identityResourceGroup: rg-operator-identities
  operatorsResourceGroup: rg-operators
  containerRegistry: youracr.azurecr.io
  rbacPropagationSeconds: 120  # Wait for Azure AD replication
  deployOperators: true
  
  operators:
    - name: firewall
      displayName: "Azure Operator - Firewall"
      scope: subscription
      subscriptionId: "00000000-0000-0000-0000-000000000000"
      roleAssignments:
        - roleDefinitionName: "Network Contributor"
          scope: "/subscriptions/00000000-0000-0000-0000-000000000000"
    

### Cascade vs. Pre-Provisioned Mode

| Aspect | Bootstrap Cascade | Pre-Provisioned |
|--------|-------------------|-----------------|
| **Identity creation** | Bootstrap operator provisions UAMIs | Bicep/Terraform pre-creates UAMIs |
| **Deployment order** | Bootstrap → wait → operators | All operators start simultaneously |
| **Flexibility** | Add operators via YAML | Add operators via IaC change |
| **Chicken-and-egg** | Solved: Bootstrap has constrained UAA | Solved: IaC has privileged identity |
| **Environment variable** | Set `BOOTSTRAP_IDENTITY_RESOURCE_GROUP` | Not set (uses pre-assigned UAMI) |

### Enabling Cascade Mode

For downstream operators to wait for their identity:

```bash
# Set this environment variable to enable cascade waiting
export BOOTSTRAP_IDENTITY_RESOURCE_GROUP="rg-operator-identities"
export OPERATOR_NAME="firewall"
```

The operator will:
1. Poll for `uami-operator-firewall` in the specified resource group
2. Wait up to 5 minutes for the identity to appear
3. Once found, proceed with normal reconciliation

---

## Advantages of ACI-based Operators

| Advantage | Description |
|-----------|-------------|
| **No Kubernetes cluster** | ACI is serverless — no cluster management, patching, or scaling |
| **Native Azure integration** | Managed Identity, VNet integration, Log Analytics built-in |
| **Cost efficient** | Pay per second of execution, auto-stop on completion |
| **Simple deployment** | Single Bicep deployment creates all operators |
| **GitOps native** | Git-sync sidecar pulls specs from repository |
| **Minimal attack surface** | Distroless image, no shell, no package manager |
| **Independent scaling** | Each operator can have different CPU/memory allocation |

### Comparison with Alternatives

| Approach | Operators (ACI) | Azure DevOps/GitHub Actions | Kubernetes Operators |
|----------|-----------------|----------------------------|---------------------|
| **Continuous reconciliation** | ✅ Built-in loop | ❌ Triggered only | ✅ Built-in loop |
| **No external state** | ✅ ARM is state | ❌ Terraform state | ✅ CR/API is state |
| **Blast radius** | ✅ Per-domain | ⚠️ Per-pipeline | ✅ Per-operator |
| **Infrastructure overhead** | ✅ None (serverless) | ✅ Managed | ❌ Cluster required |
| **Native Azure identity** | ✅ Managed Identity | ⚠️ Service Principal | ⚠️ Workload Identity |
| **Network isolation** | ✅ VNet integrated | ❌ Shared runners | ⚠️ Requires setup |

---

## Archetypes

Pre-configured deployment patterns matching [ALZ Accelerator archetypes](https://azure.github.io/Azure-Landing-Zones/accelerator/startermodules/terraform-platform-landing-zone/archetypes/).

Each archetype directory contains **ready-to-use operator specs** — no generation step required.

### Available Archetypes

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

⭐ **Recommended starting point** for most organizations

### Using a Archetype

```bash
# 1. Copy a archetype as your starting point
cp -r archetypes/6-single-region-hub-spoke-azfw archetypes/my-landing-zone

# 2. Edit specs to match your environment (look for "# CHANGE:" comments)
vim archetypes/my-landing-zone/specs/hub-network.yaml
vim archetypes/my-landing-zone/specs/firewall.yaml

# 3. Deploy operators pointing to your archetype
az deployment sub create \
  --location westeurope \
  --template-file infrastructure/main.bicep \
  --parameters archetypePath="archetypes/my-landing-zone/specs"
```

### Archetype Selection Matrix

```
                      ┌─────────────────────────────────────────────┐
                      │           Network Topology                   │
                      ├─────────────────────┬───────────────────────┤
                      │     Hub-Spoke       │     Virtual WAN        │
┌─────────────────────┼─────────────────────┼───────────────────────┤
│ Multi-Region        │                     │                       │
│   + Azure Firewall  │    Archetype 1       │    Archetype 2         │
│   + NVA             │    Archetype 3       │    Archetype 4         │
├─────────────────────┼─────────────────────┼───────────────────────┤
│ Single-Region       │                     │                       │
│   + Azure Firewall  │    Archetype 6 ⭐    │    Archetype 7         │
│   + NVA             │    Archetype 8       │    Archetype 9         │
├─────────────────────┼─────────────────────┴───────────────────────┤
│ Management Only     │              Archetype 5                     │
└─────────────────────┴─────────────────────────────────────────────┘
```

See [archetypes/README.md](archetypes/README.md) for detailed documentation.

---

## Quick Start

### Prerequisites

- Python 3.12+
- Azure CLI with Bicep extension
- Docker
- Azure Container Registry
- **User Access Administrator** + **Managed Identity Contributor** at subscription scope (for bootstrap)

> **Security Note:** The bootstrap operator uses constrained RBAC roles instead of Owner.
> User Access Administrator is further restricted with conditions to only assign specific
> least-privilege roles (Network Contributor, Log Analytics Contributor, etc.).

### 1. Build Operator Image

```bash
# Build distroless Docker image (compiles Bicep → ARM JSON)
make build

# Push to Azure Container Registry
ACR_NAME=your-acr make push-all
```

### 2. Deploy Infrastructure

```bash
# Deploy ACI operators with VNet isolation
az deployment sub create \
  --location westeurope \
  --template-file infrastructure/main.bicep \
  --parameters @infrastructure/main.example.bicepparam

# Deploy RBAC (requires User Access Administrator at subscription/MG scope)
# This assigns least-privilege roles to each downstream operator
az deployment mg create \
  --location westeurope \
  --management-group-id your-root-mg \
  --template-file infrastructure/rbac.bicep \
  --parameters operatorPrincipalIds=@principal-ids.json
```

### 4. Configure Specs

Choose a archetype from `archetypes/` and edit YAML files:

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

### 5. Monitor Reconciliation

```bash
# View operator logs in Log Analytics
az monitor log-analytics query \
  --workspace your-workspace-id \
  --analytics-query "ContainerInstanceLog_CL | where ContainerGroup_s contains 'alz-operator'"
```

---

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPERATOR_NAME` | Domain to reconcile (e.g., `firewall`, `policy`, `hub-network`) | Required |
| `DEPLOYMENT_SCOPE` | `subscription` or `management_group` | Required |
| `AZURE_SUBSCRIPTION_ID` | Target subscription ID | Required for subscription scope |
| `AZURE_MANAGEMENT_GROUP` | Target management group ID | Required for management_group scope |
| `AZURE_LOCATION` | Azure region (e.g., `westeurope`) | Required |
| `SPEC_DIR` | Path to YAML spec files | Required |
| `RECONCILE_INTERVAL` | Loop interval in seconds | `300` |
| `DRY_RUN` | Detect drift only, don't apply changes | `false` |
| `LOG_LEVEL` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |
| `TEMPLATE_DIR` | Path to compiled ARM JSON templates | `./templates` |

### Security Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `REQUIRE_MANAGED_IDENTITY` | Enforce ManagedIdentityCredential; rejects AZURE_CLIENT_SECRET | `true` |
| `ENABLE_AUDIT_LOGGING` | Enable structured audit logs for all operations | `true` |
| `MAX_RESOURCES_PER_DEPLOYMENT` | Maximum resources per deployment batch | `50` |

### Reliability Features

| Feature | Description |
|---------|-------------|
| **Circuit Breaker** | After 5 consecutive failures, operator pauses for 5 minutes before retrying |
| **Operation Timeouts** | All Azure SDK poller operations have explicit timeouts |
| **Managed Identity Enforcement** | Rejects service principal credentials (AZURE_CLIENT_SECRET) when enabled |
| **Random Deployment Suffix** | Deployment names include random suffix to prevent conflicts |

### Spec File Format

Specs use a Kubernetes-style wrapper format:

```yaml
apiVersion: azure-operator/v1
kind: HubNetworkOperator
metadata:
  name: hub-network-primary
spec:
  location: westeurope
  resourceGroupName: rg-connectivity
  virtualNetwork:
    name: vnet-hub
    addressSpace: "10.0.0.0/16"
  tags:
    environment: production
    managedBy: azure-operator
```

See individual spec files in `archetypes/*/specs/` directory for domain-specific configuration options.

---

## Development

The project uses the `azo` CLI for all development, build, and deployment operations.

### Quick Start

```bash
# Set up development environment (creates venv, installs deps)
azo dev setup

# Run tests with coverage
azo dev test

# Type checking
azo dev typecheck

# Lint Python code (--fix to auto-fix)
azo dev lint
azo dev lint --fix

# Format code
azo dev fmt
```

### Build Commands

```bash
# Build Docker image
azo build image

# Build git-sync sidecar
azo build git-sync

# Compile Bicep to ARM JSON
azo build templates
```

### Run Locally

```bash
# Run operator locally (dry-run by default)
export AZURE_SUBSCRIPTION_ID="your-sub-id"
azo run management

# Run with live deployment
azo run connectivity --no-dry-run
azo deploy infra

# Deploy RBAC (requires management group Owner)
azo deploy rbac --management-group <mg-id>
```

### Other Commands

```bash
# Show project info
azo info

# Clean build artifacts
azo clean

# Clean everything including venv and Docker images
azo clean --all
```

### Full CLI Reference

```bash
# See all available commands
azo --help

# See help for a specific command
azo dev --help
azo run --help
```

---

## License

MIT
