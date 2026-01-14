# ALZ Policy Library

This directory contains Azure Landing Zone (ALZ) policy definitions and initiatives, synced from the [Azure/Enterprise-Scale](https://github.com/Azure/Enterprise-Scale) repository.

## Structure

```
lib/policies/
├── definitions/          # Individual ALZ policy definition files (~114 files)
├── initiatives/          # Individual ALZ policy initiative files (~12 files)
├── definitions.json      # Combined array for Bicep loadJsonContent()
├── initiatives.json      # Combined array for Bicep loadJsonContent()
├── VERSION               # Tracks which ALZ release these came from
├── sync.sh               # Script to update from upstream
└── README.md             # This file
```

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  POLICY DEPLOYMENT FLOW                                                      │
│  ─────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  1. sync.sh fetches from Azure/Enterprise-Scale                             │
│     └── Downloads ~114 definitions + ~12 initiatives                        │
│     └── Generates definitions.json and initiatives.json (combined arrays)  │
│                                                                              │
│  2. bicep/policy/main.bicep loads via loadJsonContent()                     │
│     └── var alzPolicies = loadJsonContent('../../lib/policies/definitions.json')   │
│     └── Deploys all definitions to Management Group scope                   │
│                                                                              │
│  3. specs/policy.yaml defines ASSIGNMENTS                                   │
│     └── Which policies to assign to which scopes                            │
│     └── Parameters, enforcement mode, exemptions                            │
│                                                                              │
│  4. Policy Operator reconciles continuously                                  │
│     └── Detects drift via WhatIf                                            │
│     └── Applies changes                                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Usage

### Initial Sync

```bash
# Sync from latest ALZ release
./lib/policies/sync.sh

# Or sync from specific release
./lib/policies/sync.sh 2025-09-17
```

### In Your Spec Files

Reference policies by name in your `specs/policy.yaml`:

```yaml
apiVersion: alz.azure.com/v1alpha1
kind: PolicySpec

spec:
  managementGroupId: contoso

  initiatives:
    # ALZ initiatives (from lib/policies/initiatives/)
    - name: Deploy-MDFC-Config
      scope: /providers/Microsoft.Management/managementGroups/contoso
    - name: Enforce-ALZ-Decomm
      scope: /providers/Microsoft.Management/managementGroups/decommissioned

  # Individual policy assignments
  policyAssignments:
    - name: Deny-MgmtPorts-From-Internet
      scope: /providers/Microsoft.Management/managementGroups/landingzones
```

## Updating Policies

ALZ policies are updated quarterly. To sync:

```bash
# Check current version
cat lib/policies/VERSION

# Sync to latest
./lib/policies/sync.sh

# Review changes
git diff lib/policies/

# Commit if satisfied
git add lib/policies/
git commit -m "chore: sync ALZ policies to $(cat lib/policies/VERSION)"
```

## Policy Operator

The policy operator (`azo run policy`) will:

1. Load definitions from `lib/policies/definitions/`
2. Load initiatives from `lib/policies/initiatives/`
3. Deploy to the management group scope
4. Create assignments per `specs/policy.yaml`
5. Continuously reconcile (detect drift, apply changes)

## What's Included

### Initiatives (Policy Sets)

| Initiative | Purpose |
|------------|---------|
| Deploy-MDFC-Config | Microsoft Defender for Cloud configuration |
| Enforce-ALZ-Decomm | Decommissioned subscription guardrails |
| Enforce-ALZ-Sandbox | Sandbox subscription guardrails |
| Deploy-Diagnostics-LogAnalytics | Diagnostic settings for all resources |
| Deny-PublicPaaSEndpoints | Block public endpoints on PaaS services |
| Deploy-Private-DNS-Zones | Private DNS zone configuration |
| ... | See `initiatives/` for full list |

### Policy Categories

| Category | Examples |
|----------|----------|
| **Network Security** | Deny-MgmtPorts-From-Internet, Deny-RDP-From-Internet |
| **Encryption** | Deny-Storage-minTLS, Deny-Sql-minTLS |
| **Logging** | Deploy-Diagnostics-*, Deploy-Nsg-FlowLogs |
| **Identity** | Deny-PublicIP (Identity MG) |
| **Cost** | Audit-UnusedResources, Deploy-Budget |

## License

ALZ policies are MIT licensed. See [Azure/Enterprise-Scale LICENSE](https://github.com/Azure/Enterprise-Scale/blob/main/LICENSE).
