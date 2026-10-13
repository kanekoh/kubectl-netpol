package analyzer

import (
	"sort"
	"strings"
)

// WorkloadGroup represents a group of pods sharing the same namespace and app label.
type WorkloadGroup struct {
	Namespace string
	Name      string // e.g. "app=frontend" or "unlabeled"
	Labels    map[string]string
	// NSLabels are the namespace labels (selector identity for policy-only zones).
	NSLabels map[string]string
}

// Key returns a unique string key for this group.
func (w WorkloadGroup) Key() string {
	return w.Namespace + "/" + w.Name
}

// SelectorNSLabels returns namespace labels that identify the zone by selector,
// excluding kubernetes.io/metadata.name (that is name-based identity).
func (w WorkloadGroup) SelectorNSLabels() map[string]string {
	if len(w.NSLabels) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range w.NSLabels {
		if k == "kubernetes.io/metadata.name" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// FormatLabels returns a stable short "k=v, k2=v2" string (key suffix after /).
func FormatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		short := k
		if i := strings.LastIndex(k, "/"); i >= 0 {
			short = k[i+1:]
		}
		parts = append(parts, short+"="+labels[k])
	}
	return strings.Join(parts, ", ")
}

// DisplayName returns a human-readable zone identity.
//
//	cidr:     cidr:10.0.0.0/8   (ANP/BANP/NP networks:/ipBlock peer — IP dst, not a Namespace)
//	name:     ns:openshift-ingress/all-pods
//	labels:   labels:user-project=true/all-pods
func (w WorkloadGroup) DisplayName() string {
	if IsNetworkZone(w) {
		return "cidr:" + NetworkCIDR(w)
	}
	if sel := FormatLabels(w.SelectorNSLabels()); sel != "" {
		return "labels:" + sel + "/" + w.Name
	}
	return "ns:" + w.Namespace + "/" + w.Name
}

// NodeCaption is the Mermaid/HTML node label (workload + optional selector labels).
func (w WorkloadGroup) NodeCaption() string {
	if IsNetworkZone(w) {
		return NetworkCIDR(w)
	}
	cap := w.Name
	if sel := FormatLabels(w.SelectorNSLabels()); sel != "" {
		cap = cap + " | " + sel
	}
	return cap
}

// SubgraphCaption is the Mermaid subgraph title for this group's namespace.
// Label-based zones prefer the selector labels; name-based keep the namespace name.
func (w WorkloadGroup) SubgraphCaption() string {
	if IsNetworkZone(w) {
		// Clarify: CIDR peers are IP destinations from networks:, not "external-only".
		return "cidr (networks: IP peer)"
	}
	if sel := FormatLabels(w.SelectorNSLabels()); sel != "" {
		return sel
	}
	return w.Namespace
}

// Verdict represents the connectivity verdict for a pair.
type Verdict int

const (
	VerdictAllow   Verdict = iota
	VerdictDeny
	VerdictUnknown
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "Allow"
	case VerdictDeny:
		return "Deny"
	default:
		return "Unknown"
	}
}

// PortResult represents the verdict for a specific port.
type PortResult struct {
	Port     int32
	Protocol string
	Verdict  Verdict
	Layer    string // "ANP", "NetworkPolicy", "BANP", "default"
	Reason   string
}

// PairResult represents the connectivity result between two workload groups.
type PairResult struct {
	Src     WorkloadGroup
	Dst     WorkloadGroup
	Ports   []PortResult
	Overall Verdict // Allow if any port allowed, Deny if all denied
}

// Matrix represents the full connectivity matrix across all groups.
type Matrix struct {
	Groups  []WorkloadGroup
	Results map[string]map[string]*PairResult // src.Key() → dst.Key() → result
	// Synthesized is true when groups were derived from policy selectors (no pods).
	Synthesized bool
}

// Options controls fetching and analysis behaviour.
type Options struct {
	Namespace string
	LabelKey  string
	ShowAll   bool
}
