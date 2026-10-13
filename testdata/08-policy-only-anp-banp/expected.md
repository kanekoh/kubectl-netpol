# Expected outcomes (policy-only synthesis)

No Pods or Namespaces YAML — analyzer synthesizes zones from selectors.

| Source | Destination | Verdict | Layer |
|---|---|---|---|
| openshift-ingress → user-project | Allow | ANP |
| staging → user-project+env=dev | Deny | ANP |
| user-project → openshift-dns | Allow | ANP |
| user-project → cidr=172.20.0.1/32 | Allow | ANP |
| user-project → cidr=0.0.0.0/0 | Deny | BANP |
| user-project → openshift-ingress | Deny | BANP |

Run:

```bash
go run . analyze --from-dir testdata/08-policy-only-anp-banp -o table
```
