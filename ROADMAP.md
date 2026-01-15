# Azure Operator Roadmap

**Goal:** Be obviously better than Microsoft's official ALZ implementation by matching ALZ strengths (AVM modular IaC + accelerator bootstrapping + policy/archetype model) and adding clear wins (safer continuous reconciliation, better drift intelligence, better multi-team ops).

---

## Priority Matrix

| Priority | Theme | Why Critical |
|----------|-------|--------------|
| **P0** | Blast Radius Governance | #1 gap - operators touching MG/tenant scope need hard limits |
| **P0** | Multi-Signal Drift Detection | WhatIf alone is insufficient (Ignore conditions, templateLinks) |
| **P1** | Archetype-First Model | Match ALZ's conceptual model to enable adoption |
| **P1** | EPAC Policy Integration | Don't reinvent policy - orchestrate EPAC |
| **P2** | Enterprise Security Posture | Supply chain, signed commits, SLSA |
| **P2** | Operational Excellence | Day-0 UX, promotion gates, drift-to-PR |
| **P3** | Scale & Resiliency | Leader election, tenant-scale testing |
| **P3** | Compliance Reporting | Unified dashboard, exception lifecycle |

---

## P0: Critical Path (Must Have for v1.0)

### 1. Blast Radius Governance

**Current state:** MG-scope RBAC deployment exists, mentions MG Owner for RBAC deploy paths.

#### 1.1 Hard Scope Guardrails
**Location:** `src/controller/config.py`, new `src/controller/guardrails.py`

```yaml
# New spec section: guardrails.yaml
guardrails:
  allowed_scopes:
    management_groups:
      - "alz-platform"        # Explicit allowlist
      - "alz-landingzones"
    subscriptions: "*"        # All subscriptions under allowed MGs
    resource_groups: "*"
  
  denied_scopes:
    management_groups:
      - "Tenant Root Group"   # NEVER touch root
    
  max_changes_per_reconcile:
    rbac_assignments: 10
    policy_assignments: 5
    resource_deployments: 50
```

**Implementation:**
- [ ] Add `GuardrailsConfig` dataclass in `config.py`
- [ ] Add scope validation in `reconciler.py` before any deployment
- [ ] Add "refuse deployment" path when scope not in allowlist
- [ ] Add "Tenant Root Group" deny-by-default rule

#### 1.2 Two-Person Rule for High-Impact Scopes
**Location:** New `src/controller/approval.py`

```python
@dataclass
class ApprovalRequirement:
    """Defines when human approval is required."""
    scope_patterns: list[str]  # MG patterns requiring approval
    change_types: list[str]    # RBAC, Policy, etc.
    approval_source: str       # "github_environment" | "azure_devops" | "manual"
```

**Implementation:**
- [ ] Add GitHub Environment protection integration
- [ ] Add approval check before `_apply_with_retry()`
- [ ] Add "pending approval" state in reconciliation loop
- [ ] Add webhook/callback for approval completion

#### 1.3 Kill Switch
**Location:** `src/controller/config.py`, `src/controller/reconciler.py`

```python
# Environment variable or Azure App Configuration
KILL_SWITCH_ENABLED = True  # Immediately stops all apply operations

# Behavior when kill switch is active:
# - Drift detection continues (for visibility)
# - All apply operations are blocked
# - Logs "KILL_SWITCH: Apply blocked for {domain}"
```

**Implementation:**
- [ ] Add `KILL_SWITCH` environment variable
- [ ] Add Azure App Configuration polling (for central control)
- [ ] Add kill switch check in `_reconcile_once()` before apply
- [ ] Add Prometheus metric for kill switch state

#### 1.4 Change-Rate Limits
**Location:** `src/controller/config.py`, `src/controller/reconciler.py`

```python
@dataclass
class RateLimits:
    """Per-interval change limits to prevent runaway deployments."""
    max_rbac_changes: int = 10
    max_policy_changes: int = 5
    max_resource_changes: int = 50
    cooldown_after_limit_seconds: int = 3600  # 1 hour
```

**Implementation:**
- [ ] Add rate limit tracking per change type
- [ ] Add cooldown enforcement when limits hit
- [ ] Add override mechanism for emergency deployments

---

### 2. Multi-Signal Drift Detection

**Current state:** ARM WhatIf + Resource Graph (just implemented). Need to handle WhatIf limitations.

#### 2.1 WhatIf Reliability Handling
**Location:** `src/controller/reconciler.py`

**Problem:** WhatIf returns `Ignore` for:
- Nested template expansion limits
- Template links not evaluated
- Timeout conditions

**Implementation:**
- [ ] Add `Ignore` count threshold detection
- [ ] Add "fail closed" mode when too many Ignores
- [ ] Add "report-only" degradation mode
- [ ] Log warning when WhatIf reliability is questionable

```python
# In _filter_significant_changes()
ignore_count = sum(1 for c in changes if c.change_type == ChangeType.IGNORE)
if ignore_count > MAX_ACCEPTABLE_IGNORES:
    logger.error(
        "WhatIf returned too many Ignore results - possible expansion limit hit",
        extra={"ignore_count": ignore_count, "threshold": MAX_ACCEPTABLE_IGNORES}
    )
    if self._config.fail_closed_on_whatif_degradation:
        raise WhatIfDegradedError("WhatIf results unreliable, blocking apply")
```

#### 2.2 Policy Compliance Signal
**Location:** New `src/controller/policy_compliance.py`

```python
class PolicyComplianceQuerier:
    """Query Azure Policy compliance state for drift detection."""
    
    async def get_compliance_state(self, scope: str) -> ComplianceResult:
        """Get non-compliant resources in scope."""
        # Uses: Microsoft.PolicyInsights/policyStates
        pass
    
    async def get_remediation_tasks(self, scope: str) -> list[RemediationTask]:
        """Get pending remediation tasks."""
        pass
```

**Implementation:**
- [ ] Add Policy compliance API client
- [ ] Integrate compliance state into drift detection
- [ ] Add "compliance drift" vs "configuration drift" distinction
- [ ] Add remediation task awareness (don't fight DINE policies)

#### 2.3 Deployment History Correlation
**Location:** `src/controller/resource_graph.py` (extend)

```kusto
// Query recent deployments to correlate changes
resourcechanges
| where properties.changeAttributes.operation contains "deployments"
| extend deploymentName = extract(@"deployments/([^/]+)", 1, properties.targetResourceId)
| summarize changes = count() by deploymentName, bin(timestamp, 1h)
```

**Implementation:**
- [ ] Add deployment history query
- [ ] Correlate Graph changes with deployment operations
- [ ] Detect "deployment in progress" state to avoid conflicts

#### 2.4 Noise Suppression (Diff Normalization)
**Location:** New `src/controller/diff_normalizer.py`

**Problem:** Default value churn causes infinite redeploy loops.

```python
# Known ARM default-value patterns that should be ignored
NORMALIZE_RULES = [
    # SKU name vs tier redundancy
    {"path": "properties.sku.tier", "ignore_if_sku_name_matches": True},
    # Empty arrays vs null
    {"path": "*.ipConfigurations", "normalize": "empty_array_equals_null"},
    # Default provisioning state
    {"path": "properties.provisioningState", "ignore": True},
]
```

**Implementation:**
- [ ] Add diff normalization rules engine
- [ ] Add per-resource-type normalization rules
- [ ] Add "stable diff" mode that applies normalization before comparison

---

## P1: Competitive Parity (Match ALZ Strengths)

### 3. Archetype-First Model

**Goal:** Model ALZ archetypes explicitly (policy sets + RBAC bundles + platform resources).

#### 3.1 Archetype Schema
**Location:** New `src/controller/archetypes.py`, new spec schema

```yaml
# specs/archetypes/platform.yaml
apiVersion: azure-operator/v1
kind: Archetype
metadata:
  name: platform
  description: "Platform landing zone archetype"

spec:
  # Policy assignments applied at this archetype level
  policies:
    - initiative: "Enforce-ALZ-Sandbox"
      parameters:
        effect: "Deny"
    - initiative: "Deploy-MDFC-Config"
      parameters:
        enableDefenderForServers: true

  # RBAC assignments
  rbac:
    - role: "Reader"
      principals:
        - type: group
          name: "platform-readers"
    - role: "Contributor"
      principals:
        - type: group
          name: "platform-contributors"
      condition: "resourceType == 'Microsoft.Network/*'"

  # Platform resources deployed with this archetype
  resources:
    - template: "bicep/connectivity/main.bicep"
      parameters:
        hubVnetName: "hub-vnet"
    - template: "bicep/management/main.bicep"

  # Inheritance
  inherits:
    - archetype: "corp"      # Inherit from corp archetype
      overrides:
        policies:
          - initiative: "Enforce-ALZ-Sandbox"
            parameters:
              effect: "Audit"  # Override to Audit for platform
```

#### 3.2 Archetype Inheritance & Overrides
**Location:** `src/controller/archetypes.py`

```python
class ArchetypeResolver:
    """Resolve effective archetype by applying inheritance chain."""
    
    def resolve(self, archetype_name: str, scope: str) -> EffectiveArchetype:
        """Compute effective policies/RBAC/resources for a scope."""
        pass
    
    def diff(self, current: EffectiveArchetype, desired: EffectiveArchetype) -> ArchetypeDiff:
        """Compute drift between current and desired archetype."""
        pass
```

#### 3.3 Conflict Detection
**Location:** `src/controller/archetypes.py`

```python
class ConflictDetector:
    """Detect policy/RBAC conflicts across MG hierarchy."""
    
    def detect_policy_conflicts(self, mg_hierarchy: list[str]) -> list[Conflict]:
        """Detect conflicting policy effects across MG levels."""
        # e.g., Parent MG has "Deny" but child has "DeployIfNotExists"
        pass
```

---

### 4. EPAC Policy Integration

**Goal:** Orchestrate EPAC rather than reimplementing policy deployment.

#### 4.1 EPAC Pipeline Integration
**Location:** New `src/controller/epac_integration.py`

```python
class EpacOrchestrator:
    """Invoke EPAC pipelines from operator."""
    
    async def trigger_plan(self, scope: str) -> EpacPlanResult:
        """Trigger EPAC plan phase via GitHub Actions / ADO."""
        pass
    
    async def trigger_deploy(self, plan_id: str, approval: Approval) -> EpacDeployResult:
        """Trigger EPAC deploy phase after approval."""
        pass
    
    async def get_policy_state(self, scope: str) -> EpacState:
        """Query EPAC-managed policy state."""
        pass
```

#### 4.2 Preview Policy Handling
**Location:** `src/controller/policy_validation.py`

```python
# ALZ policy detection
PREVIEW_POLICIES = [
    "Audit-MachineLearning-PrivateEndpointId",
    # ... list from ALZ wiki
]

def validate_policy_assignment(assignment: PolicyAssignment) -> list[Warning]:
    """Warn if assignment includes preview policies."""
    warnings = []
    for policy_id in assignment.policy_definition_ids:
        if policy_id in PREVIEW_POLICIES:
            warnings.append(PreviewPolicyWarning(policy_id))
    return warnings
```

---

## P2: Differentiation (Clear Wins Over ALZ)

### 5. Enterprise Security Posture

#### 5.1 Supply Chain Hardening
**Location:** `.github/workflows/build.yml`, new verification in reconciler

- [ ] Add SBOM generation (Syft/SPDX)
- [ ] Add image signing (Cosign)
- [ ] Add SLSA provenance attestation
- [ ] Add signature verification before deployment

#### 5.2 Tamper-Proof GitOps
**Location:** `build/git-sync.sh`, new `src/controller/git_verification.py`

```python
class GitVerifier:
    """Verify git commits before reconciliation."""
    
    def verify_commit_signature(self, commit_sha: str) -> bool:
        """Verify commit is GPG/SSH signed by trusted key."""
        pass
    
    def verify_tag_signature(self, tag: str) -> bool:
        """Verify tag is signed."""
        pass
```

---

### 6. Operational Excellence

#### 6.1 Day-0 Bootstrap UX
**Location:** New `bootstrap/` directory

```bash
# One command bootstrap
./bootstrap.sh \
  --tenant-id "..." \
  --github-org "contoso" \
  --repo-name "azure-landing-zones" \
  --environments "dev,test,prod"
```

Creates:
- GitHub repo with branch protection
- Federated credentials for OIDC
- Azure identities (bootstrap + domain operators)
- Initial MG structure
- Pipeline configuration

#### 6.2 Drift-to-PR Workflow
**Location:** New `src/controller/drift_pr.py`

```python
class DriftPRGenerator:
    """Generate PRs for detected drift instead of auto-apply."""
    
    async def create_drift_pr(self, drift: DriftResult) -> PullRequest:
        """Create PR with proposed state updates."""
        # Includes:
        # - Diff visualization
        # - Risk scoring
        # - Approval requirements based on scope
        pass
```

---

## P3: Scale & Enterprise Features

### 7. Scale & Resiliency

#### 7.1 Leader Election
**Location:** New `src/controller/leader_election.py`

```python
class LeaderElector:
    """Ensure only one operator instance applies per scope."""
    
    async def acquire_lock(self, scope: str, ttl: int) -> Lock:
        """Acquire distributed lock (Azure Blob lease or Redis)."""
        pass
```

#### 7.2 Tenant-Scale Testing
**Location:** `tests/scale/`

- [ ] Add performance benchmarks for 100+ subscriptions
- [ ] Add MG hierarchy depth testing
- [ ] Add concurrent operator testing

---

### 8. Compliance Reporting

#### 8.1 Unified Dashboard
**Location:** New `src/controller/compliance_report.py`

```python
@dataclass
class ComplianceReport:
    """Unified compliance view per subscription."""
    subscription_id: str
    effective_archetype: str
    drift_status: DriftStatus
    policy_compliance: PolicyComplianceState
    rbac_compliance: RbacComplianceState
    exceptions: list[Exception]
    last_reconcile: datetime
```

---

## Implementation Phases

### Phase 1: Foundation (v0.2.0) - 4 weeks
- [ ] Blast radius guardrails (scope allowlist, deny root)
- [ ] Kill switch
- [ ] WhatIf reliability handling (Ignore detection)
- [ ] Rate limits per change type

### Phase 2: Drift Intelligence (v0.3.0) - 4 weeks
- [ ] Policy compliance signal integration
- [ ] Diff normalization rules
- [ ] Deployment history correlation
- [ ] Archetype schema definition

### Phase 3: ALZ Parity (v0.4.0) - 6 weeks
- [ ] Archetype inheritance resolver
- [ ] Conflict detection
- [ ] EPAC integration
- [ ] Preview policy warnings

### Phase 4: Differentiation (v0.5.0) - 4 weeks
- [ ] Supply chain hardening (SBOM, signing)
- [ ] Tamper-proof git verification
- [ ] Drift-to-PR workflow
- [ ] Two-person approval integration

### Phase 5: Enterprise (v1.0.0) - 6 weeks
- [ ] Day-0 bootstrap CLI
- [ ] Leader election
- [ ] Compliance dashboard
- [ ] Tenant-scale testing
- [ ] Documentation & adoption guides

---

## Success Metrics

| Metric | Target | Measure |
|--------|--------|---------|
| **Safety** | Zero unintended MG/tenant changes | Guardrail block count |
| **Reliability** | <1% false positive drift alerts | Diff normalization effectiveness |
| **Adoption** | Easier than ALZ accelerator | Time to first deployment |
| **Trust** | Auditable every change | Change attribution coverage |
| **Scale** | 500+ subscriptions | Reconcile time at scale |

---

## Quick Wins (Can Implement Today)

1. **Kill switch** - Simple env var check (2 hours)
2. **Scope allowlist** - Config validation (4 hours)
3. **WhatIf Ignore detection** - Add threshold check (2 hours)
4. **Rate limits** - Counter + cooldown (4 hours)

These four items alone make the operator **visibly safer** than raw ALZ + Terraform/Bicep.
