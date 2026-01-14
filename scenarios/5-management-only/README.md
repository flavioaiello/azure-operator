# Scenario 5: Management Groups, Policy and Management Resources Only

Use this when you already have network connectivity or are migrating from another implementation.

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

**Not deployed:** Hub VNet, Firewall, Bastion, DNS zones, Gateways

## Usage

```bash
az deployment sub create \
  --location westeurope \
  --template-file infrastructure/main.bicep \
  --parameters scenarioPath="scenarios/5-management-only/specs"
```
