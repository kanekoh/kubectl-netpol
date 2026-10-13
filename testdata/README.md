# Test Scenarios for kubectl-netpol

Test fixtures covering NetworkPolicy, AdminNetworkPolicy (ANP), and BaselineAdminNetworkPolicy (BANP).

## 3-Layer Evaluation Order

```
Packet: source pod → destination pod

  [Layer 1] AdminNetworkPolicy  (cluster-scoped, priority 0–99)
      Action: Allow → ALLOW (stop)
      Action: Deny  → DENY  (stop)
      Action: Pass  → continue to Layer 2
      No match      → continue to Layer 2

  [Layer 2] NetworkPolicy  (namespace-scoped)
      Destination pod selected by NP?
        Yes → only explicitly allowed sources pass → else DENY
        No  → continue to Layer 3

  [Layer 3] BaselineAdminNetworkPolicy  (cluster-scoped, one instance)
      Action: Allow → ALLOW
      Action: Deny  → DENY
      No match      → ALLOW (Kubernetes default)
```

Reference: https://network-policy-api.sigs.k8s.io/

## Scenarios

### 01 — NP Only: 3-Tier App
Classic frontend → backend → database pattern using only NetworkPolicy.

- Demonstrates: NP default-deny, port-specific allow rules
- Key: pods selected by a NP get implicit default-deny for unmatched traffic

### 02 — NP: Namespace Isolation
Strict namespace isolation for multi-team cluster. Each team owns their namespace.

- Demonstrates: intra-namespace allow + cross-namespace deny
- Key: combining `default-deny` NP with a targeted allow is the standard isolation pattern

### 03 — ANP + NP + BANP: Multi-Tenant
Full 3-layer setup for a multi-tenant cluster with cluster admin (ANP), tenant admin (NP), and fallback (BANP).

- Demonstrates: all three layers working together
- Key: monitoring gets cluster-wide access via ANP; BANP blocks external egress as a catch-all

### 04 — ANP + NP + BANP: Dev/Staging/Prod
Multiple environments on one cluster with strict environment isolation enforced by cluster admin.

- Demonstrates: env-boundary enforcement via ANP, CI/CD access patterns
- Key: BANP as a "deny everything else" backstop when no NP or ANP matched

### 05 — BANP Deny vs NP Allow ⭐
**Edge case**: BANP would deny the traffic, but NetworkPolicy explicitly allows it.

- Demonstrates: NP is evaluated BEFORE BANP — NP wins
- Key: BANP only applies to pods NOT covered by any NetworkPolicy decision. If NP selected the pod and made a decision (Allow or Deny), BANP is never reached.

```
payment-gateway → payments:8443
  BANP says: Deny (cross-namespace)
  NP says:   Allow (explicit ingress rule)
  Result:    ALLOW — NP evaluated first
```

### 06 — ANP Pass → NP Decides ⭐
ANP uses the `Pass` action to explicitly hand off control to NetworkPolicy.

- Demonstrates: ANP Pass action, hard-deny coexisting with Pass
- Key: compromised namespace is hard-denied by a high-priority ANP (priority 10). A low-priority ANP (priority 50) passes everything else to NP. The Pass rule never applies to compromised traffic.

```
compromised-ns → services:8080
  ANP priority 10: Deny  (matches first, stops here)
  ANP priority 50: Pass  (never reached)
  Result: DENY

api-gateway → services:8080
  ANP priority 10: no match
  ANP priority 50: Pass → NP decides → Allow
  Result: ALLOW
```

### 07 — ANP Deny Overrides NP Allow ⭐
Incident response: cluster admin quarantines a namespace via ANP, overriding existing NP allow rules.

- Demonstrates: ANP Deny is absolute — NP cannot override it
- Key: tenant NetworkPolicies can never circumvent an ANP Deny. This is the intended security model for cluster admins.

```
quarantine → backend:8080
  NP says:   Allow (old rule, not yet cleaned up)
  ANP says:  Deny (quarantine lockdown, priority 5)
  Result:    DENY — ANP evaluated first, NP never reached
```

## Apply to Cluster

```bash
# Apply a single scenario
kubectl apply -f testdata/01-np-only-3tier/

# Apply edge case scenarios (requires ANP/BANP CRDs)
kubectl apply -f testdata/05-banp-deny-np-allow/

# Check if ANP CRDs are installed
kubectl get crd adminnetworkpolicies.policy.networking.k8s.io
```

### 08 — Policy-only ANP + BANP (no Pods)
Platform allow / egress infra / env isolation + BANP default deny — **policies only**.

- Demonstrates: zone synthesis from selectors when pods=0
- Key: `--from-dir` works without pods.yaml / namespaces.yaml

## Validate with kubectl-netpol

```bash
# Offline with fixtures (pods present)
go run . analyze --from-dir testdata/01-np-only-3tier -o table

# Policy-only synthesis (no pods)
go run . analyze --from-dir testdata/08-policy-only-anp-banp -o table
go run . analyze --from-dir testdata/08-policy-only-anp-banp -o html > /tmp/netpol.html

# Live cluster
kubectl netpol analyze -n frontend,backend,database

# Layer conflict / shadowed Allow review
go run . verify --from-dir testdata/07-anp-deny-override
go run . verify --from-dir testdata/05-banp-deny-np-allow
go run . verify --from-dir path/to/policies --warnings-only

# Run live probe tests against expected.yaml (not implemented yet)
kubectl netpol probe --spec testdata/01-np-only-3tier/expected.yaml
```
