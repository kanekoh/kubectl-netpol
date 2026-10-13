package visualizer

import (
	"fmt"
	"strings"

	"github.com/kanekoh/kubectl-netpol/pkg/analyzer"
)

// ApplyFocus filters m to nodes matching selector and their direct Allow neighbors.
//
// Selector forms:
//
//	ns=<namespace>            — all groups in that namespace
//	<key>=<value>             — groups where Labels[key] == value (any label key)
//	<namespace>/<key>=<value> — exact group (namespace + label expression)
func ApplyFocus(m *analyzer.Matrix, selector string) (*analyzer.Matrix, error) {
	if selector == "" {
		return m, nil
	}

	focusKeys, err := matchGroups(m.Groups, selector)
	if err != nil {
		return nil, err
	}
	if len(focusKeys) == 0 {
		return nil, fmt.Errorf("no groups match selector %q", selector)
	}

	// Collect direct Allow neighbors of every focus node.
	keepKeys := make(map[string]bool)
	for k := range focusKeys {
		keepKeys[k] = true
	}
	for srcKey, srcResults := range m.Results {
		for dstKey, pr := range srcResults {
			if pr.Overall != analyzer.VerdictAllow {
				continue
			}
			if focusKeys[srcKey] || focusKeys[dstKey] {
				keepKeys[srcKey] = true
				keepKeys[dstKey] = true
			}
		}
	}

	// Build filtered groups (preserving original order).
	var filteredGroups []analyzer.WorkloadGroup
	for _, g := range m.Groups {
		if keepKeys[g.Key()] {
			filteredGroups = append(filteredGroups, g)
		}
	}

	// Build filtered results.
	filteredResults := make(map[string]map[string]*analyzer.PairResult)
	for srcKey, srcResults := range m.Results {
		if !keepKeys[srcKey] {
			continue
		}
		for dstKey, pr := range srcResults {
			if !keepKeys[dstKey] {
				continue
			}
			if filteredResults[srcKey] == nil {
				filteredResults[srcKey] = make(map[string]*analyzer.PairResult)
			}
			filteredResults[srcKey][dstKey] = pr
		}
	}

	return &analyzer.Matrix{
		Groups:  filteredGroups,
		Results: filteredResults,
	}, nil
}

// CountAllowEdges counts Allow edges in a Matrix (used for focus stats reporting).
func CountAllowEdges(m *analyzer.Matrix) int {
	count := 0
	for _, srcResults := range m.Results {
		for _, pr := range srcResults {
			if pr.Overall == analyzer.VerdictAllow {
				count++
			}
		}
	}
	return count
}

// matchGroups returns the set of group keys that match selector.
//
//	ns=<namespace>            → namespace match
//	<key>=<value>             → label match (any key)
//	<namespace>/<key>=<value> → exact group key match
func matchGroups(groups []analyzer.WorkloadGroup, selector string) (map[string]bool, error) {
	result := make(map[string]bool)

	// Case 1: exact group — "<namespace>/<key>=<value>"
	// Namespace names are [a-z0-9-] (RFC 1123). If the part before the first "/"
	// contains a dot (e.g. "kubernetes.io/name=x"), it is a label key with a
	// prefix — fall through to Case 3 (label key=value) instead.
	if slashIdx := strings.Index(selector, "/"); slashIdx >= 0 {
		ns := selector[:slashIdx]
		labelExpr := selector[slashIdx+1:]
		if strings.Contains(ns, ".") {
			// Label key with prefix: treat the whole string as <key>=<value>
			goto labelSelector
		}
		if !strings.Contains(labelExpr, "=") {
			return nil, fmt.Errorf("invalid selector %q: part after '/' must be <key>=<value>", selector)
		}
		// Group.Key() == namespace + "/" + name  (name is the label expression like "app=api")
		wantKey := ns + "/" + labelExpr
		for _, g := range groups {
			if g.Key() == wantKey {
				result[g.Key()] = true
			}
		}
		return result, nil
	}

	// Case 2: namespace selector
	if strings.HasPrefix(selector, "ns=") {
		ns := strings.TrimPrefix(selector, "ns=")
		for _, g := range groups {
			if g.Namespace == ns {
				result[g.Key()] = true
			}
		}
		return result, nil
	}

	// Case 3: <key>=<value> — any label key (including prefixed keys like kubernetes.io/name)
labelSelector:
	eqIdx := strings.Index(selector, "=")
	if eqIdx < 0 {
		return nil, fmt.Errorf("invalid selector %q: expected ns=<ns>, <key>=<value>, or <namespace>/<key>=<value>", selector)
	}
	labelKey := selector[:eqIdx]
	labelVal := selector[eqIdx+1:]
	if labelKey == "" {
		return nil, fmt.Errorf("invalid selector %q: label key must not be empty", selector)
	}
	for _, g := range groups {
		if v, ok := g.Labels[labelKey]; ok && v == labelVal {
			result[g.Key()] = true
		}
		// Also match when Name == "key=value" (fallback for groups built without Labels map).
		if g.Name == selector {
			result[g.Key()] = true
		}
	}
	return result, nil
}
