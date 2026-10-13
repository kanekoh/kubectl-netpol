package visualizer

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/hkaneko/kubectl-netpol/pkg/analyzer"
)

// os is used for stderr warnings in RenderMermaidFull
var _ = os.Stderr

func sanitizeID(key string) string {
	r := strings.NewReplacer(
		"/", "_",
		"=", "_",
		"-", "_",
		".", "_",
	)
	id := r.Replace(key)
	// Mermaid node/subgraph IDs must not start with "_" or a digit.
	if id == "" || id[0] == '_' || (id[0] >= '0' && id[0] <= '9') {
		id = "n" + id
	}
	return id
}

// escapeMermaidLabel escapes text used inside Mermaid ["..."] / |"..."| labels.
// Unescaped "/" (e.g. CIDR 0.0.0.0/0) causes Mermaid "Syntax error in text".
// Prefer a fullwidth solidus over HTML entities (#47;) — entities are unreliable
// across Mermaid/CDN versions when opening reports via file://.
func escapeMermaidLabel(s string) string {
	r := strings.NewReplacer(
		`"`, "'",
		`/`, "／", // U+FF0F fullwidth solidus — safe in Mermaid node text
	)
	return r.Replace(s)
}

func portResultLabel(p analyzer.PortResult) string {
	if p.Port == 0 || p.Protocol == "*" {
		return "any"
	}
	return fmt.Sprintf("%d/%s", p.Port, p.Protocol)
}

// portLabel lists Allow ports for an edge (comma-separated). Falls back to any.
func portLabel(pr *analyzer.PairResult) string {
	if pr == nil || len(pr.Ports) == 0 {
		return "any"
	}
	var parts []string
	for _, p := range pr.Ports {
		if p.Verdict != analyzer.VerdictAllow {
			continue
		}
		parts = append(parts, portResultLabel(p))
	}
	if len(parts) == 0 {
		// Deny-only edge (mermaid-full): show denied ports
		for _, p := range pr.Ports {
			parts = append(parts, portResultLabel(p))
		}
	}
	if len(parts) == 0 {
		return "any"
	}
	// Prefer concrete ports over "any" when both appear as Allow.
	concrete := make([]string, 0, len(parts))
	hasAny := false
	for _, s := range parts {
		if s == "any" {
			hasAny = true
			continue
		}
		concrete = append(concrete, s)
	}
	if len(concrete) > 0 {
		return strings.Join(concrete, ",")
	}
	if hasAny {
		return "any"
	}
	return strings.Join(parts, ",")
}

func shortLayer(layer string) string {
	switch layer {
	case "ANP":
		return "ANP"
	case "NetworkPolicy":
		return "NP"
	case "BANP":
		return "BANP"
	default:
		return ""
	}
}

// primaryLayer picks the layer for edge/table tags: prefer a non-default Allow
// (policy-decided concrete ports) over a default-allow "any".
func primaryLayer(pr *analyzer.PairResult) string {
	if pr == nil || len(pr.Ports) == 0 {
		return ""
	}
	var fallback string
	for _, p := range pr.Ports {
		if p.Verdict != analyzer.VerdictAllow {
			continue
		}
		if p.Layer != "default" && p.Layer != "" {
			return p.Layer
		}
		if fallback == "" {
			fallback = p.Layer
		}
	}
	if fallback != "" {
		return fallback
	}
	return pr.Ports[0].Layer
}

// edgeLabel returns "port [LAYER]" or just "port" when layer is default/empty.
func edgeLabel(pr *analyzer.PairResult) string {
	port := portLabel(pr)
	sl := shortLayer(primaryLayer(pr))
	if sl == "" {
		return port
	}
	return port + " [" + sl + "]"
}

// mermaidFlowchartBody returns the raw "flowchart LR ..." content (no ``` fences).
// Allow edges only; Deny edges are omitted. Edge labels include port/layer.
func mermaidFlowchartBody(m *analyzer.Matrix) string {
	return mermaidFlowchartBodyOpts(m, true)
}

// mermaidFlowchartBodyOpts is like mermaidFlowchartBody.
// withEdgeLabels=false omits |label| on arrows (used by HTML, where labels
// are shown in a side panel instead of on Mermaid SVG edges).
func mermaidFlowchartBodyOpts(m *analyzer.Matrix, withEdgeLabels bool) string {
	var sb strings.Builder

	if len(m.Groups) == 0 {
		sb.WriteString("flowchart LR\n")
		sb.WriteString("  %% no workload groups found\n")
		return sb.String()
	}

	// Count allow edges for the large-graph warning.
	allowCount := 0
	for _, src := range m.Groups {
		dstResults := m.Results[src.Key()]
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				continue
			}
			if pr, ok := dstResults[dst.Key()]; ok && pr.Overall == analyzer.VerdictAllow {
				allowCount++
			}
		}
	}

	sb.WriteString("flowchart LR\n")

	if allowCount > 20 {
		sb.WriteString("  %% WARNING: many connections. Use -o table for the full Allow/Deny matrix,\n")
		// Do NOT write raw "<...>" here — inside HTML <pre class=\"mermaid\"> the browser
		// treats it as a tag and Mermaid then fails with TAGSTART / Syntax error.
		sb.WriteString("  %% or --focus / -n to narrow scope.\n")
	}
	sb.WriteString("\n")

	// Namespace subgraphs (title shows selector labels when label-based).
	nsByGroups := groupByNamespace(m.Groups)
	for _, ns := range sortedNamespaces(nsByGroups) {
		safeNS := sanitizeID(ns)
		title := ns
		if gs := nsByGroups[ns]; len(gs) > 0 {
			title = gs[0].SubgraphCaption()
		}
		sb.WriteString(fmt.Sprintf("  subgraph %s[\"%s\"]\n", safeNS, escapeMermaidLabel(title)))
		for _, g := range nsByGroups[ns] {
			id := sanitizeID(g.Key())
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", id, escapeMermaidLabel(g.NodeCaption())))
		}
		sb.WriteString("  end\n")
	}
	sb.WriteString("\n")

	// Allow edges only. Skip CIDR zones as sources (they are destinations only)
	// and, for synthesized matrices, skip default-layer edges that drown out policy intent.
	for _, src := range m.Groups {
		if analyzer.IsNetworkZone(src) {
			continue
		}
		srcID := sanitizeID(src.Key())
		dstResults, ok := m.Results[src.Key()]
		if !ok {
			continue
		}
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				continue
			}
			pr, ok := dstResults[dst.Key()]
			if !ok || pr.Overall != analyzer.VerdictAllow {
				continue
			}
			if m.Synthesized && isDefaultLayer(pr) {
				continue
			}
			dstID := sanitizeID(dst.Key())
			if withEdgeLabels {
				sb.WriteString(fmt.Sprintf("  %s -->|\"%s\"| %s\n", srcID, escapeMermaidLabel(edgeLabel(pr)), dstID))
			} else {
				sb.WriteString(fmt.Sprintf("  %s --> %s\n", srcID, dstID))
			}
		}
	}

	sb.WriteString("\n")
	sb.WriteString("  %% Only allowed connections shown. Use -o table for full Allow/Deny matrix.\n")

	return sb.String()
}

// RenderMermaid writes an allow-only flowchart grouped by namespace.
// Deny connections are intentionally omitted — use -o table for the full matrix.
func RenderMermaid(m *analyzer.Matrix, w io.Writer) {
	fmt.Fprintln(w, "```mermaid")
	fmt.Fprint(w, mermaidFlowchartBody(m))
	fmt.Fprintln(w, "```")
}

// RenderMermaidFull renders both Allow (-->) and Deny (--x) edges.
// Warns when the diagram will be difficult to read.
func RenderMermaidFull(m *analyzer.Matrix, w io.Writer) {
	if len(m.Groups) == 0 {
		fmt.Fprintln(w, "```mermaid")
		fmt.Fprintln(w, "flowchart LR")
		fmt.Fprintln(w, "  %% no workload groups found")
		fmt.Fprintln(w, "```")
		return
	}

	totalEdges := len(m.Groups) * (len(m.Groups) - 1)
	large := len(m.Groups) > 6 || totalEdges > 20
	if large {
		fmt.Fprintf(os.Stderr,
			"Warning: %d groups / %d edges — mermaid-full will be hard to read. Consider -o table or -o mermaid.\n",
			len(m.Groups), totalEdges)
	}

	fmt.Fprintln(w, "```mermaid")
	fmt.Fprintln(w, "flowchart LR")
	if large {
		fmt.Fprintln(w, "  %% WARNING: large graph — readability may be poor.")
		fmt.Fprintln(w, "  %% Consider: -o table (full matrix) or -o mermaid (allow-only).")
	}
	fmt.Fprintln(w)

	// Namespace subgraphs (title shows selector labels when label-based).
	nsByGroups := groupByNamespace(m.Groups)
	for _, ns := range sortedNamespaces(nsByGroups) {
		safeNS := sanitizeID(ns)
		title := ns
		if gs := nsByGroups[ns]; len(gs) > 0 {
			title = gs[0].SubgraphCaption()
		}
		fmt.Fprintf(w, "  subgraph %s[\"%s\"]\n", safeNS, escapeMermaidLabel(title))
		for _, g := range nsByGroups[ns] {
			id := sanitizeID(g.Key())
			fmt.Fprintf(w, "    %s[\"%s\"]\n", id, escapeMermaidLabel(g.NodeCaption()))
		}
		fmt.Fprintln(w, "  end")
	}
	fmt.Fprintln(w)

	for _, src := range m.Groups {
		srcID := sanitizeID(src.Key())
		dstResults, ok := m.Results[src.Key()]
		if !ok {
			continue
		}
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				continue
			}
			pr, ok := dstResults[dst.Key()]
			if !ok {
				continue
			}
			dstID := sanitizeID(dst.Key())
			label := escapeMermaidLabel(edgeLabel(pr))
			switch pr.Overall {
			case analyzer.VerdictAllow:
				fmt.Fprintf(w, "  %s -->|\"%s\"| %s\n", srcID, label, dstID)
			case analyzer.VerdictDeny:
				fmt.Fprintf(w, "  %s --x|\"%s\"| %s\n", srcID, label, dstID)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  %% ─── Legend ─────────────────────────────────────────")
	fmt.Fprintln(w, "  %% -->  = Allow (traffic permitted)")
	fmt.Fprintln(w, "  %% --x  = Deny  (traffic blocked, X at destination)")
	fmt.Fprintln(w, "  %% Edge label: port [layer]  e.g. any [ANP], 8080/TCP [NP]")
	fmt.Fprintln(w, "```")
}

func isDefaultLayer(pr *analyzer.PairResult) bool {
	if pr == nil || len(pr.Ports) == 0 {
		return true
	}
	// Synthesized graphs hide edges only when every Allow is default.
	hasPolicyAllow := false
	hasDefaultAllow := false
	for _, p := range pr.Ports {
		if p.Verdict != analyzer.VerdictAllow {
			continue
		}
		if p.Layer == "default" || p.Layer == "" {
			hasDefaultAllow = true
		} else {
			hasPolicyAllow = true
		}
	}
	if hasPolicyAllow {
		return false
	}
	return hasDefaultAllow || primaryLayer(pr) == "default" || primaryLayer(pr) == ""
}

func groupByNamespace(groups []analyzer.WorkloadGroup) map[string][]analyzer.WorkloadGroup {
	m := make(map[string][]analyzer.WorkloadGroup)
	for _, g := range groups {
		m[g.Namespace] = append(m[g.Namespace], g)
	}
	return m
}

func sortedNamespaces(m map[string][]analyzer.WorkloadGroup) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
