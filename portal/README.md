# Azure Landing Zones Operator - Portal Deployment

This directory contains the Azure Portal deployment experience for azure-operator.

## Quick Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fflavioaiello%2Fazure-operator%2Fmain%2Fportal%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fflavioaiello%2Fazure-operator%2Fmain%2Fportal%2FcreateUiDefinition.json)

## What Gets Deployed

The wizard deploys the operator infrastructure:

```
┌─────────────────────────────────────────────────────────────────┐
│  Resource Group: rg-azure-operator                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  User-Assigned Managed Identity (Bootstrap)              │   │
│  │  ├── User Access Admin @ Subscription (constrained)      │   │
│  │  └── Managed Identity Contributor @ Subscription        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Azure Container Instance                                │   │
│  │  ├── operator (reconciliation loop)                      │   │
│  │  └── git-sync (pulls specs from Git)                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Log Analytics Workspace (optional)                      │   │
│  │  └── Container Insights solution                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Wizard Steps

### 1. Basics
- Subscription and region selection
- Resource group name

### 2. Identity & RBAC
- Bootstrap identity name
- RBAC scope (Subscription or Management Group)
- Management Group ID (if applicable)

### 3. Operators
- Network topology selection (Hub-Spoke or vWAN)
- Connectivity operators (Firewall, Bastion, VPN, etc.)
- Management operators (Log Analytics, Monitor)
- Security operators (Defender, Sentinel, Key Vault)
- Governance operators (Roles, Management Groups)

### 4. Git Configuration
- Repository URL
- Branch
- Specs path
- Authentication (for private repos)
- Sync interval

### 5. Advanced
- Reconciliation interval
- Dry-run mode
- Container image
- Monitoring configuration
- Resource tags

## Files

| File | Purpose |
|------|---------|
| `createUiDefinition.json` | Portal wizard UI definition |
| `mainTemplate.json` | ARM template for deployment |
| `main.bicep` | Bicep version of the deployment |
| `modules/identity.bicep` | UAMI creation module |
| `modules/containerGroup.bicep` | ACI with operator + git-sync |
| `modules/logAnalytics.bicep` | Log Analytics workspace |

## Local Testing

Test the wizard locally using the Azure Portal Sandbox:

1. Go to https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/SandboxBlade
2. Upload `createUiDefinition.json`
3. Preview the wizard experience

## CLI Deployment

If you prefer CLI over the portal:

```bash
# Using Bicep
az deployment sub create \
  --location westeurope \
  --template-file main.bicep \
  --parameters \
    gitRepoUrl='https://github.com/your-org/landing-zone-specs.git' \
    gitBranch='main' \
    gitSpecsPath='specs/'

# Using ARM
az deployment sub create \
  --location westeurope \
  --template-file mainTemplate.json \
  --parameters \
    gitRepoUrl='https://github.com/your-org/landing-zone-specs.git' \
    gitBranch='main' \
    gitSpecsPath='specs/'
```

## Post-Deployment

After deployment:

1. **Create your specs repository** with YAML files for each operator
2. **Push initial specs** to trigger the first reconciliation
3. **Monitor logs** in Log Analytics to verify operation

Example spec file (`specs/firewall.yaml`):
```yaml
apiVersion: azure-operator/v1
kind: FirewallSpec
metadata:
  name: hub-firewall
spec:
  location: westeurope
  resourceGroupName: rg-connectivity
  firewall:
    name: afw-hub-westeurope
    skuTier: Standard
    threatIntelMode: Alert
    availabilityZones: [1, 2, 3]
```

## Security Notes

- **Secretless Architecture**: All authentication uses Managed Identity
- **Bootstrap Scope**: The bootstrap identity has elevated permissions initially
- **Downstream Operators**: Use least-privilege identities created by bootstrap
- **No Credentials Stored**: PAT for private Git repos is stored as ACI secret

## Troubleshooting

### Operator not starting
Check ACI logs in Log Analytics or via:
```bash
az container logs -g rg-azure-operator -n azure-operator-bootstrap --container-name operator
```

### Git sync failing
Check git-sync container logs:
```bash
az container logs -g rg-azure-operator -n azure-operator-bootstrap --container-name git-sync
```

### RBAC not propagating
Entra ID replication can take up to 10 minutes. The bootstrap operator handles this with retry logic.
