# kubectl-netpol

A **kubectl plugin** for static analysis and visualization of Kubernetes network policy.

It evaluates **NetworkPolicy**, **AdminNetworkPolicy (ANP)**, and **BaselineAdminNetworkPolicy (BANP)** using the three-layer model (ANP → NetworkPolicy → BANP), groups workloads into zones (by namespace and pod labels), and shows **who can talk to whom** as a matrix, diagram, or report—not as a flat list of IPs and ports.

Works **against a live cluster** or **offline** from a directory of YAML (`--from-dir`), so you can use it in PR review and CI the same way you use other policy tooling.

## Where this fits

The ecosystem has several network-policy tools; they solve different problems:

| Focus | Examples | **kubectl-netpol** |
|--------|----------|-------------------|
| Policy lint / risk / invalid rules | [np-guard / netpol-analyzer](https://github.com/np-guard/netpol-analyzer) and similar validators | Not a YAML linter |
| Reachability at **workload / zone** level | — | **Zone connectivity matrix** + Mermaid / HTML / JSON |
| Admin policy API (ANP / BANP) | Varies by tool | **First-class** 3-layer evaluation |
| Offline / GitOps | Some validators | **`--from-dir`** including policy-only fixtures |

Use it when you want to answer: *“Given these policies, which app zones are allowed to connect, and which layer decided?”*

Design notes: [ARCHITECTURE.md](./ARCHITECTURE.md). Example manifests: [testdata/README.md](./testdata/README.md).

## Commands

| Command | Description |
|---------|-------------|
| `analyze` | Build a zone connectivity matrix (outputs: `table`, `mermaid`, `html`, `json`) |
| `verify` | Advisory checks (shadowed allows, layer overrides)—for human review, not schema validation |

Live connectivity testing (`probe`) is described in [ARCHITECTURE.md](./ARCHITECTURE.md) as a planned companion; it is **not** implemented yet.

## Requirements

- **Live mode**: a working kubeconfig (`kubectl` or `oc` context)
- **ANP / BANP**: fetched only if [Network Policy API](https://network-policy-api.sigs.k8s.io/) CRDs are installed; otherwise analysis is NetworkPolicy-centric
- **Offline mode**: YAML under a directory (`pods.yaml`, `namespaces.yaml`, policies, etc.). Policy-only dirs are supported (see `testdata/08-policy-only-anp-banp`)

## Install

### GitHub Releases (macOS)

Pushing a `v*` tag runs [release.yml](./.github/workflows/release.yml) and attaches **darwin/arm64** and **darwin/amd64** archives.

1. Download an archive from [Releases](https://github.com/kanekoh/kubectl-netpol/releases)
2. Extract (contains `kubectl-netpol` and a `oc-netpol` symlink)
3. Install both names on your `PATH` (e.g. `/usr/local/bin`)

```bash
tar xzf kubectl-netpol_v0.1.0_darwin_arm64.tar.gz
chmod +x kubectl-netpol
sudo mv kubectl-netpol oc-netpol /usr/local/bin/
```

Maintainers: `git tag v0.1.0 && git push origin v0.1.0`

### Build from source

```bash
git clone https://github.com/kanekoh/kubectl-netpol.git
cd kubectl-netpol
go build -o kubectl-netpol .
# or install to $GOPATH/bin or $GOBIN
go install .
# or, after a tagged release is on the module proxy:
go install github.com/kanekoh/kubectl-netpol@latest
```

## kubectl and OpenShift `oc`

[kubectl plugins](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/) are executables named `kubectl-<name>` on your `PATH`, invoked as `kubectl <name>`. OpenShift uses the same pattern with `oc-<name>` → `oc <name>`.

| Binary on `PATH` | Example |
|------------------|---------|
| `kubectl-netpol` | `kubectl netpol analyze` |
| `oc-netpol` (symlink to the same file is fine) | `oc netpol analyze` |

You can also run `kubectl-netpol analyze` directly.

### Live cluster

```bash
kubectl netpol analyze
kubectl netpol analyze -n frontend

oc netpol analyze
oc netpol analyze -n my-project

kubectl netpol analyze --kubeconfig ~/.kube/other-config
```

### Offline (Git / CI)

```bash
kubectl netpol analyze --from-dir testdata/01-np-only-3tier -o table
kubectl netpol analyze --from-dir testdata/08-policy-only-anp-banp -o html > report.html
```

### Output formats (`analyze -o`)

| Value | Use |
|-------|-----|
| `table` | Terminal matrix (default) |
| `mermaid` | Mermaid diagram (allow edges only) |
| `mermaid-full` | Mermaid including deny-related detail |
| `html` | Single-file HTML report |
| `json` | Machine-readable connectivity map |

`--focus` (`ns=...`, `app=...`, `namespace/key=value`) applies to `mermaid`, `mermaid-full`, and `html`.

```bash
kubectl netpol analyze --from-dir testdata/03-multitenant-anp-banp \
  -o mermaid --focus ns=monitoring
```

### Common flags

```bash
kubectl netpol analyze --label-key app   # zone grouping label (default: app)
kubectl netpol analyze --all             # include groups not referenced by policies
kubectl netpol verify --from-dir testdata/07-anp-deny-override
kubectl netpol verify --from-dir path/to/yaml --warnings-only
kubectl netpol verify --strict           # exit 1 if any Warning
```

## Development

```bash
go test ./...
go run . analyze --from-dir testdata/01-np-only-3tier -o table
```

## License

No `LICENSE` file is included yet; contact the maintainer before redistribution if you need explicit terms.
