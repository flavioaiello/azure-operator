# Azure Landing Zone Archetypes

Each archetype directory contains **ready-to-use operator specs** — no generation step required.

## Quick Start

```bash
# Copy a archetype as your starting point
cp -r archetypes/6-single-region-hub-spoke-azfw archetypes/my-landing-zone

# Edit specs to match your environment
vim archetypes/my-landing-zone/specs/hub-network.yaml

# Deploy
az deployment sub create \
  --location westeurope \
  --template-file infrastructure/main.bicep \
  --parameters archetypePath="archetypes/my-landing-zone/specs"
```

## Available Archetypes

| # | Archetype | Topology | Firewall | Regions | Directory |
|---|----------|----------|----------|---------|-----------|
| 1 | Multi-Region Hub-Spoke + Azure Firewall | Hub-Spoke | Azure | 2 | `1-multi-region-hub-spoke-azfw/` |
| 2 | Multi-Region Virtual WAN + Azure Firewall | vWAN | Azure | 2 | `2-multi-region-vwan-azfw/` |
| 3 | Multi-Region Hub-Spoke + NVA | Hub-Spoke | NVA | 2 | `3-multi-region-hub-spoke-nva/` |
| 4 | Multi-Region Virtual WAN + NVA | vWAN | NVA | 2 | `4-multi-region-vwan-nva/` |
| **5** | **Management Only** | None | None | 1 | `5-management-only/` |
| **6** | **Single-Region Hub-Spoke + Azure Firewall** ⭐ | Hub-Spoke | Azure | 1 | `6-single-region-hub-spoke-azfw/` |
| 7 | Single-Region Virtual WAN + Azure Firewall | vWAN | Azure | 1 | `7-single-region-vwan-azfw/` |
| 8 | Single-Region Hub-Spoke + NVA | Hub-Spoke | NVA | 1 | `8-single-region-hub-spoke-nva/` |
| 9 | Single-Region Virtual WAN + NVA | vWAN | NVA | 1 | `9-single-region-vwan-nva/` |

⭐ **Recommended starting point** for most organizations

## Archetype Selection Matrix

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

## What Gets Deployed

### All Archetypes Include

| Operator | Purpose |
|----------|---------|
| management-group | ALZ management group hierarchy |
| role | Custom roles & RBAC |
| log-analytics | Log Analytics workspace |
| automation | Automation account |
| monitor | Data collection rules, alerts |
| defender | Microsoft Defender for Cloud |

> **Policy Management:** Use [Enterprise Policy as Code (EPAC)](https://aka.ms/epac) for Azure Policy.

### Connectivity Operators (varies by archetype)

| Operator | Hub-Spoke | vWAN | NVA |
|----------|-----------|------|-----|
| hub-network | ✅ | ❌ | ✅ |
| vwan | ❌ | ✅ | ✅ |
| firewall | ✅ | ✅ | ❌ |
| bastion | ✅ | ❌ | ✅ |
| dns | ✅ | ✅ | ✅ |
| vpn-gateway | Multi-region only | ❌ | Multi-region only |
| sentinel | Multi-region only | Multi-region only | Multi-region only |

## Customization

### Required Changes

Every spec file has `# CHANGE:` comments marking values you must update:

1. **Subscription IDs** — Your actual Azure subscription IDs
2. **Management Group ID** — Your tenant root or ALZ root MG
3. **Contact emails** — Your security team's email address
4. **Location** — If not using `westeurope`

### Optional Changes

- **Address spaces** — Hub VNet and subnet CIDRs
- **SKUs** — Firewall (Standard/Premium), Bastion (Basic/Standard)
- **Private DNS zones** — Add/remove based on services used
- **Defender plans** — Enable/disable specific plans

## Directory Structure

```
archetypes/
├── 1-multi-region-hub-spoke-azfw/
│   ├── README.md
│   └── specs/
│       ├── management-group.yaml
│       ├── hub-network.yaml
│       ├── hub-network-secondary.yaml   # Secondary region
│       ├── firewall.yaml
│       ├── firewall-secondary.yaml      # Secondary region
│       ├── vpn-gateway.yaml
│       ├── vpn-gateway-secondary.yaml   # Secondary region
│       ├── sentinel.yaml                # SIEM for multi-region
│       └── ...
├── 6-single-region-hub-spoke-azfw/
│   ├── README.md
│   └── specs/
│       ├── management-group.yaml
│       ├── hub-network.yaml
│       ├── firewall.yaml
│       ├── bastion.yaml
│       ├── dns.yaml
│       └── ...
└── README.md                            # This file
```
