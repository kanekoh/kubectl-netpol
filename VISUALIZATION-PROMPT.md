# 依頼: kubectl-netpol 可視化を「Allow-only + フォーカス + HTML hover 強調」に再定義して実装・テストする

作業先: `demos/kubectl-netpol/`（単体リポジトリではリポジトリルート）

対象: Mermaid / table /（新規）HTML レポート。`probe` は触らない。

## 背景

現状 Mermaid は辺が多く読みにくい。対策は次の 3 層:

1. **データ側で線を減らす** — 既定 Mermaid は Allow のみ。ラベルはポート優先
2. **生成時フォーカス** — 指定ノード／NS に関係する辺だけ出す（`--focus`）
3. **HTML でインタラクション** — ノード hover/click で関連フローを強調（Markdown 埋め込み Mermaid では不可）

重要制約:

- Mermaid **記法単体**や GitHub/Obsidian 埋め込みでは hover 近傍強調はできない
- hover 強調は **自前 HTML + Mermaid.js 描画後の JS** でのみ実装する
- 上流の「click highlight」PR に依存しない（自前実装）

`pkg/visualizer/mermaid.go`・`cmd/analyze.go`・`ARCHITECTURE.md`・`testdata/` を読んでから着手。

---

## 設計（これを正とする）

### 役割分担

| 出力 | 役割 |
|---|---|
| `table` | 網羅マトリクス（Allow/Deny の正本） |
| `mermaid` | Allow-only の flowchart（ストーリー図） |
| `mermaid-full` | デバッグ用 Allow+Deny。辺が多いと警告 |
| `html` | Mermaid 埋め込み + hover/click で関連強調（本命の閲覧 UX） |
| `json` | 互換維持 |

図種は **flowchart**（sequence は今回やらない）。

### A. Mermaid 既定（`-o mermaid`）

必須:

- Deny 辺を出さない
- NS は `subgraph`、ノードは label のみ（例: `app=api`）
- 辺ラベルは **ポート優先**（`8080/TCP`）。不明なら `any`
- レイヤ単独ラベル（`ANP` だけ等）は禁止。載せるなら `8080/TCP [ANP]` 程度の副記まで
- `flowchart LR`

### B. 生成時フォーカス（必須機能）

CLI にフォーカス手段を追加する（名前は実装で決めてよいが意味は固定）:

```text
--focus <selector>
```

セレクタ仕様（最低これだけ対応）:

- `ns=<namespace>` … その NS 内グループを「注目」、**入出辺のみ**描画
- `group=<namespace>/<label>` または `app=<value>`（`--label-key` と組み合わせ）  
  … その workload group を注目、**直接接続する辺のみ**描画
- 複数指定可なら OR（いずれかに接続すれば残す）。難しければ単一指定でよい

動作:

- `-o mermaid` / `-o html` に適用（table は全量のまま、または同じフィルタでも可。推奨: **図系だけフィルタ**）
- フォーカス時、注目ノード以外は「直接の隣人」だけ残し、それ以外のノード／辺は落とす
- 出力先頭コメントまたは stderr に `focus: ...` と残ノード数・辺数を出す
- フォーカス結果が空なら分かりやすくエラー／メッセージ

例:

```bash
kubectl-netpol analyze --from-dir testdata/03-multitenant-anp-banp -o mermaid --focus ns=monitoring
kubectl-netpol analyze --from-dir testdata/05-banp-deny-np-allow -o html --focus app=gateway
```

### C. HTML レポート + hover/click 強調（必須機能）

`-o html` で単一 HTML を stdout またはファイルに出す（フラグが無ければ stdout で可。`--output-file` があれば使う）。

HTML 要件:

1. Mermaid.js を CDN から読み込み、Allow-only flowchart を描画（フォーカス適用済みならそれを使う）
2. 描画後、SVG 上で:
   - **ノードに mouseenter**: そのノードと **直接つながる辺・相手ノード以外を薄く**（opacity 低下）
   - **mouseleave**: 元に戻す
   - （推奨）**click でピン留め**、再 click または背景 click で解除
3. 凡例をページ上部に短く置く（Allow-only / 緑=通る 等）
4. table（または簡易マトリクス）を同ページ下部に置けるとよい（任意だが推奨）
5. オフライン完全動作は必須としない（CDN 依存で可）。ただし JS エラーで図が消えないよう基本動作を確認

実装ヒント（制約ではない）:

- Mermaid 描画後の `g.node` / edge path（`.edgePaths` / `.edges`）を辿る
- 辺 ID と node ID の対応をパースして「隣接リスト」を自前で持つ
- 依存パッケージを増やさず、インライン JS/CSS でよい

### D. mermaid-full

- Allow+Deny 維持可
- 辺数 > 20 または Groups > 6 で警告（コメント or stderr）
- HTML の既定図は **mermaid-full ではなく Allow-only**

### スコープ外

- `probe`
- krew
- sequence 図
- ハブ圧縮（`monitoring → *`）の本実装（ARCHITECTURE に将来案として 1 段落残すのは可）
- analyzer 判定ロジックの変更（バグ発見時は報告のみ）

---

## 受け入れ条件

1. `testdata/01`〜`07` を `--from-dir` + `-o mermaid` で実行し、**Deny 辺が出ない**
2. 辺ラベルがポート/`any` 主体（レイヤ単独ラベルなし）
3. `--focus ns=...` と `--focus app=...`（または同等）で辺・ノードが絞られ、注目対象の入出だけになる
4. `-o html` で HTML が生成され、ブラウザで:
   - 図が表示される
   - ノード hover で非関連が薄くなる／関連が残る
   - leave で復帰する
5. `-o table` は従来どおり網羅（フォーカス非適用で可）
6. `ARCHITECTURE.md` の Visualization を、役割分担・`--focus`・HTML hover に合わせて更新
7. 報告に以下を含める:
   - 代表 Mermaid 生出力: `03`（Allow-only）と `03 --focus ns=monitoring`
   - HTML の使い方（ファイル保存コマンド）
   - ブラウザ確認結果（できたこと／残課題）

---

## 作業手順

1. 現状把握
2. visualizer: Allow-only + ポートラベル
3. `--focus` フィルタ実装（mermaid/html に接続）
4. `-o html` + hover/click JS
5. 全シナリオ off-line 実行で回帰確認
6. ARCHITECTURE.md 更新
7. 差分要約と受け入れ条件チェックリストを報告

## 判断に迷ったら

- 「図をリッチに」より「線を減らす」「注目を絞る」を優先
- Markdown Mermaid にインタラクションを無理に求めない → HTML へ誘導
- Mermaid 自動レイアウトの限界は、フォーカスと Allow-only で吸収する
