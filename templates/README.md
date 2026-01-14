# Compiled ARM Templates

This directory contains ARM JSON templates compiled from Bicep source files.

## ⚠️ Do Not Edit Manually

These files are **auto-generated** by the CI pipeline. Any manual changes will be overwritten.

To modify templates:
1. Edit the Bicep source in `/bicep/<domain>/main.bicep`
2. Commit and push to `main` branch
3. CI automatically compiles and commits ARM JSON here

## Template Mapping

| Template | Source | Used By |
|----------|--------|---------|
| `connectivity.json` | `bicep/connectivity/main.bicep` | firewall, bastion, dns, hub-network, vpn-gateway, expressroute, vwan-* |
| `management.json` | `bicep/management/main.bicep` | log-analytics, automation, monitor |
| `security.json` | `bicep/security/main.bicep` | defender, keyvault, sentinel |
| `identity.json` | `bicep/identity/main.bicep` | role, management-group, bootstrap |

## How It Works

```
bicep/              # Source (human-editable)
    └── connectivity/
        └── main.bicep
    └── management/
        └── main.bicep
    └── ...

templates/          # Compiled (auto-generated)
    └── connectivity.json
    └── management.json
    └── ...
```

The git-sync sidecar in ACI pulls this entire repo, making compiled templates
available to operators at runtime without container rebuilds.
