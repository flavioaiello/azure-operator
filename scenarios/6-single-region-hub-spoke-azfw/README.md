# Scenario 6: Single-Region Hub and Spoke Virtual Network with Azure Firewall

The most common starting topology for organizations new to Azure.

## What's Deployed

| Operator | Resources |
|----------|-----------|
| management-group | ALZ management group hierarchy |
| policy | Azure Policy definitions & assignments |
| role | Custom roles & RBAC |
| log-analytics | Log Analytics workspace |
| automation | Automation account |
| monitor | Data collection rules, alerts |
| defender | Microsoft Defender for Cloud |
| hub-network | Hub VNet with required subnets |
| firewall | Azure Firewall Standard/Premium |
| bastion | Azure Bastion for secure VM access |
| dns | Private DNS zones for Azure services |

## Customization

Edit the YAML files in `specs/` to match your environment:

1. **Required changes:**
   - Update `subscriptionId` in each spec
   - Update `location` if not using `westeurope`
   - Update `managementGroups.rootId` to your tenant root

2. **Common customizations:**
   - Hub VNet address space in `hub-network.yaml`
   - Firewall SKU (Standard vs Premium) in `firewall.yaml`
   - Private DNS zones list in `dns.yaml`
   - Defender plans in `defender.yaml`

## Usage

```bash
# Deploy using this scenario
az deployment sub create \
  --location westeurope \
  --template-file infrastructure/main.bicep \
  --parameters scenarioPath="scenarios/6-single-region-hub-spoke-azfw/specs"
```
