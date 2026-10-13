# kubectl-netpol

Kubernetes / OpenShift の **NetworkPolicy**、**AdminNetworkPolicy (ANP)**、**BaselineAdminNetworkPolicy (BANP)** を静的に評価し、ワークロード（ラベル単位のゾーン）間の接続可否を表や図で表示する CLI です。

クラスタに接続する **ライブモード** と、YAML を置いたディレクトリだけで動く **オフラインモード**（`--from-dir`）の両方に対応しています。

設計の背景は [ARCHITECTURE.md](./ARCHITECTURE.md)、テスト用マニフェストは [testdata/README.md](./testdata/README.md) を参照してください。

## できること

| コマンド | 説明 |
|----------|------|
| `analyze` | ANP → NetworkPolicy → BANP の 3 層モデルでゾーン間マトリクスを生成（table / mermaid / html / json） |
| `verify` | 層の上書きや「見えなくなった Allow」など、レビュー向けの**助言**チェック（スキーマ検証ではありません） |

`probe`（実 Pod による疎通テスト）は [ARCHITECTURE.md](./ARCHITECTURE.md) に記載の将来機能です。現時点の実装には含まれません。

## 前提

- **ライブモード**: 有効な kubeconfig（`kubectl` / `oc` が使えるコンテキスト）
- **ANP / BANP**: クラスタに [Kubernetes Network Policy API](https://network-policy-api.sigs.k8s.io/) の CRD が入っている場合のみ取得・評価（未導入なら NetworkPolicy 中心で動作）
- **オフラインモード**: `pods.yaml` / `namespaces.yaml` / 各ポリシー YAML をディレクトリに配置（ポリシーだけのディレクトリでもゾーン合成可能 — `testdata/08-policy-only-anp-banp`）

## インストール

### 1. GitHub Releases（推奨）

タグ `v*` を push すると [GitHub Actions](./.github/workflows/release.yml) が **macOS arm64（Apple Silicon）** と **macOS amd64（Intel）** のバイナリをビルドし、Release に添付します。

1. [Releases](https://github.com/hkaneko/kubectl-netpol/releases) から自分の Mac 用アーカイブを取得
2. 展開する（アーカイブ内に `kubectl-netpol` と `oc-netpol` へのシンボリックリンクが入っています）
3. 両方を PATH のあるディレクトリに配置（例: `/usr/local/bin`）

```bash
tar xzf kubectl-netpol_v0.1.0_darwin_arm64.tar.gz
chmod +x kubectl-netpol
sudo mv kubectl-netpol oc-netpol /usr/local/bin/
```

初回リリース例:

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 2. Go からビルド / インストール

```bash
git clone https://github.com/hkaneko/kubectl-netpol.git
cd kubectl-netpol
go build -o kubectl-netpol .
# または
go install github.com/hkaneko/kubectl-netpol@latest
```

## kubectl / oc プラグインとしての呼び方

[kubectl プラグイン](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/)は、PATH 上の `kubectl-<名前>` として `kubectl <名前>` で実行できます。OpenShift の `oc` も同様に `oc-<名前>` → `oc <名前>` です（upstream / 経験知: バイナリ名がプラグイン名の源泉）。

| 配置するファイル名 | 実行例 |
|--------------------|--------|
| `kubectl-netpol` | `kubectl netpol analyze` |
| `oc-netpol`（同一バイナリのリンク可） | `oc netpol analyze` |

直接実行も可能です: `kubectl-netpol analyze ...`

### ライブクラスタで分析

```bash
# 全 Namespace（デフォルト）
kubectl netpol analyze

# Namespace を絞る
kubectl netpol analyze -n frontend

# OpenShift（ログイン済みのコンテキスト）
oc netpol analyze
oc netpol analyze -n my-project

# 別 kubeconfig
kubectl netpol analyze --kubeconfig ~/.kube/other-config
```

### オフライン（Git / CI でポリシーだけ検証）

```bash
kubectl netpol analyze --from-dir testdata/01-np-only-3tier -o table
kubectl netpol analyze --from-dir testdata/08-policy-only-anp-banp -o html > report.html
```

### 出力形式（`analyze -o`）

| 値 | 用途 |
|----|------|
| `table` | ターミナル向けマトリクス（デフォルト） |
| `mermaid` | Allow のみの Mermaid 図 |
| `mermaid-full` | Deny 等も含む Mermaid |
| `html` | 単一 HTML レポート（ブラウザで開く） |
| `json` | 機械可読な接続マップ |

図向けの `--focus`（`ns=...` / `app=...` / `namespace/key=value`）は `mermaid` / `mermaid-full` / `html` で有効です。

```bash
kubectl netpol analyze --from-dir testdata/03-multitenant-anp-banp \
  -o mermaid --focus ns=monitoring
```

### よく使うフラグ

```bash
kubectl netpol analyze --label-key app    # ゾーン分割に使う Pod ラベル（デフォルト: app）
kubectl netpol analyze --all              # ポリシー未参照のグループも表示
kubectl netpol verify --from-dir testdata/07-anp-deny-override
kubectl netpol verify --from-dir path/to/yaml --warnings-only
kubectl netpol verify --strict            # Warning があると exit 1
```

## 開発

```bash
go test ./...
go run . analyze --from-dir testdata/01-np-only-3tier -o table
```

## ライセンス

リポジトリに LICENSE が無い場合は利用前に作者に確認してください。
