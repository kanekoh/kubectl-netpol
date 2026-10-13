package visualizer

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/kanekoh/kubectl-netpol/pkg/analyzer"
)

const (
	checkMark = "✓" // ✓
	crossMark = "✗" // ✗
	question  = "?"
	dash      = "-"
)

func verdictSymbol(v analyzer.Verdict) string {
	switch v {
	case analyzer.VerdictAllow:
		return checkMark
	case analyzer.VerdictDeny:
		return crossMark
	default:
		return question
	}
}

func layerTag(ports []analyzer.PortResult) string {
	if len(ports) == 0 {
		return ""
	}
	layer := ""
	for _, p := range ports {
		if p.Verdict != analyzer.VerdictAllow {
			continue
		}
		if p.Layer != "default" && p.Layer != "" {
			return "[" + p.Layer + "]"
		}
		if layer == "" {
			layer = p.Layer
		}
	}
	if layer != "" {
		return "[" + layer + "]"
	}
	return "[" + ports[0].Layer + "]"
}

func portSummary(ports []analyzer.PortResult) string {
	var allow, deny []string
	for _, p := range ports {
		lbl := "any"
		if p.Port != 0 && p.Protocol != "*" {
			lbl = fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		}
		switch p.Verdict {
		case analyzer.VerdictAllow:
			if lbl != "any" {
				allow = append(allow, lbl)
			}
		case analyzer.VerdictDeny:
			if lbl != "any" {
				deny = append(deny, lbl)
			}
		}
	}
	switch {
	case len(allow) > 0 && len(deny) > 0:
		return strings.Join(allow, ",")
	case len(allow) > 0:
		return strings.Join(allow, ",")
	case len(deny) > 0:
		return strings.Join(deny, ",")
	default:
		return ""
	}
}

// RenderTable writes a human-readable connectivity matrix to w.
func RenderTable(m *analyzer.Matrix, w io.Writer) {
	if len(m.Groups) == 0 {
		fmt.Fprintln(w, "No workload groups found.")
		return
	}

	fmt.Fprintln(w, "ZONE CONNECTIVITY MATRIX")
	fmt.Fprintln(w, "========================")
	if m.Synthesized {
		fmt.Fprintln(w, "Policy-only zones (synthesized from selectors)")
	} else {
		fmt.Fprintln(w, "Pods grouped by: namespace/label")
	}
	fmt.Fprintln(w, "Zone prefixes:")
	fmt.Fprintln(w, "  ns:<name>     = selected by Namespace name")
	fmt.Fprintln(w, "  labels:k=v    = selected by Namespace labels")
	fmt.Fprintln(w, "  cidr:<ip/len> = IP peer from networks:/ipBlock (column = destination only)")
	fmt.Fprintln(w, "                 Read rows→cidr as egress to that CIDR. Not \"inbound from that IP\".")
	fmt.Fprintln(w, "                 CIDR may be API VIP, VPC endpoint, or 0.0.0.0/0 — not inherently external.")
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Header row
	header := "Source \\ Destination"
	for _, g := range m.Groups {
		header += "\t" + g.DisplayName()
	}
	fmt.Fprintln(tw, header)

	// Separator
	sep := strings.Repeat("-", len("Source \\ Destination"))
	for range m.Groups {
		sep += "\t" + strings.Repeat("-", 20)
	}
	fmt.Fprintln(tw, sep)

	// Data rows — CIDR zones are destination columns only (not sources).
	for _, src := range m.Groups {
		if analyzer.IsNetworkZone(src) {
			continue
		}
		row := src.DisplayName()
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				row += "\t" + dash
				continue
			}
			dstResults, ok := m.Results[src.Key()]
			if !ok {
				row += "\t" + question
				continue
			}
			pr, ok := dstResults[dst.Key()]
			if !ok {
				row += "\t" + question
				continue
			}
			cell := verdictSymbol(pr.Overall) + " " + layerTag(pr.Ports)
			if ps := portSummary(pr.Ports); ps != "" {
				cell += " " + ps
			}
			row += "\t" + cell
		}
		fmt.Fprintln(tw, row)
	}

	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Legend:")
	fmt.Fprintf(w, "  %s = Allow   %s = Deny   %s = Unknown\n", checkMark, crossMark, question)
	fmt.Fprintln(w, "  [ANP] = AdminNetworkPolicy   [NetworkPolicy] = NetworkPolicy")
	fmt.Fprintln(w, "  [BANP] = BaselineAdminNetworkPolicy   [default] = Kubernetes default allow")
}
