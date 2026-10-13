package analyzer

import (
	"sort"

	corev1 "k8s.io/api/core/v1"
)

// groupPods groups running pods by {namespace}/{labelKey}={labelValue}.
// Pods without the target label use the first available label or fall back to "unlabeled".
func groupPods(pods []corev1.Pod, labelKey string) []WorkloadGroup {
	seen := make(map[string]*WorkloadGroup)

	for i := range pods {
		pod := &pods[i]
		// Include Running pods and pods with no phase set (e.g. offline/testdata mode)
		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != "" {
			continue
		}

		ns := pod.Namespace
		var name string

		if v, ok := pod.Labels[labelKey]; ok {
			name = labelKey + "=" + v
		} else if len(pod.Labels) > 0 {
			// Use the first available label (sorted for determinism)
			keys := make([]string, 0, len(pod.Labels))
			for k := range pod.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			k := keys[0]
			name = k + "=" + pod.Labels[k]
		} else {
			name = "unlabeled"
		}

		key := ns + "/" + name
		if _, exists := seen[key]; !exists {
			// Snapshot labels from the first pod in the group
			lbls := make(map[string]string, len(pod.Labels))
			for k, v := range pod.Labels {
				lbls[k] = v
			}
			seen[key] = &WorkloadGroup{
				Namespace: ns,
				Name:      name,
				Labels:    lbls,
			}
		}
	}

	groups := make([]WorkloadGroup, 0, len(seen))
	for _, g := range seen {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Key() < groups[j].Key()
	})
	return groups
}

// enrichNSLabels attaches namespace labels onto each group for display.
func enrichNSLabels(groups []WorkloadGroup, namespaces []corev1.Namespace) {
	for i := range groups {
		if len(groups[i].NSLabels) > 0 {
			continue
		}
		groups[i].NSLabels = getNamespaceLabels(groups[i].Namespace, namespaces)
	}
}

// groupReferencedByPolicies returns true when at least one NetworkPolicy, ANP, or BANP
// could potentially select the group (conservative check based on namespace).
func groupReferencedByPolicies(g WorkloadGroup, fr *FetchResult) bool {
	for _, np := range fr.NetworkPolicies {
		if np.Namespace == g.Namespace {
			return true
		}
	}
	for _, anp := range fr.ANPs {
		if anpSubjectMatchesGroup(anp.Spec.Subject, g, fr.Namespaces) {
			return true
		}
	}
	for _, banp := range fr.BANPs {
		if banpSubjectMatchesGroup(banp.Spec.Subject, g, fr.Namespaces) {
			return true
		}
	}
	return false
}

// evaluatePort runs the 3-layer policy logic for one port/protocol query.
func evaluatePort(src, dst WorkloadGroup, fr *FetchResult, q PortQuery) PortResult {
	pr := PortResult{Port: q.Port, Protocol: q.Protocol}

	anpVerdict, anpReason, anpDecided := EvaluateANP(src, dst, fr.ANPs, fr.Namespaces, q)
	if anpDecided {
		pr.Verdict = anpVerdict
		pr.Layer = "ANP"
		pr.Reason = anpReason
		return pr
	}

	npVerdict, npDecided := EvaluateNetworkPolicy(src, dst, fr.NetworkPolicies, fr.Namespaces, q)
	if npDecided {
		reason := "NetworkPolicy"
		if anpReason != "" {
			reason = anpReason + " → " + reason
		}
		pr.Verdict = npVerdict
		pr.Layer = "NetworkPolicy"
		pr.Reason = reason
		return pr
	}

	banpVerdict, banpReason, banpDecided := EvaluateBANP(src, dst, fr.BANPs, fr.Namespaces, q)
	if banpDecided {
		pr.Verdict = banpVerdict
		pr.Layer = "BANP"
		pr.Reason = banpReason
		return pr
	}

	pr.Verdict = VerdictAllow
	pr.Layer = "default"
	pr.Reason = "no policy applies — Kubernetes default allow"
	return pr
}

func overallFromPorts(ports []PortResult) Verdict {
	anyAllow, anyDeny := false, false
	for _, p := range ports {
		switch p.Verdict {
		case VerdictAllow:
			anyAllow = true
		case VerdictDeny:
			anyDeny = true
		}
	}
	if anyAllow {
		return VerdictAllow
	}
	if anyDeny {
		return VerdictDeny
	}
	return VerdictUnknown
}

// EvaluatePair evaluates the 3-layer policy logic for each relevant port on src→dst.
func EvaluatePair(src, dst WorkloadGroup, fr *FetchResult) *PairResult {
	pr := &PairResult{Src: src, Dst: dst}
	for _, q := range collectPortQueries(src, dst, fr) {
		pr.Ports = append(pr.Ports, evaluatePort(src, dst, fr, q))
	}
	pr.Overall = overallFromPorts(pr.Ports)
	return pr
}

// BuildMatrix groups pods into WorkloadGroups and evaluates all src→dst pairs.
// When no pods are loaded but policies exist, zones are synthesized from selectors.
func BuildMatrix(fr *FetchResult, opts Options) *Matrix {
	var groups []WorkloadGroup
	synthesized := false

	if len(fr.Pods) == 0 && HasPolicies(fr) {
		synth, g := SynthesizeFromPolicies(fr)
		// Persist synthesized namespaces onto the caller's FetchResult so
		// verify (and other callers) see the same label sets as the matrix.
		fr.Namespaces = synth.Namespaces
		groups = g
		synthesized = true
	} else {
		groups = groupPods(fr.Pods, opts.LabelKey)

		// Filter groups to those referenced by at least one policy, unless --all
		// Skip filtering for synthesized zones (all are policy-derived).
		if !opts.ShowAll {
			var filtered []WorkloadGroup
			for _, g := range groups {
				if groupReferencedByPolicies(g, fr) {
					filtered = append(filtered, g)
				}
			}
			// If no groups have policies, fall back to showing all (avoids empty output)
			if len(filtered) > 0 {
				groups = filtered
			}
		}
	}

	enrichNSLabels(groups, fr.Namespaces)

	m := &Matrix{
		Groups:      groups,
		Results:     make(map[string]map[string]*PairResult),
		Synthesized: synthesized,
	}

	for _, src := range groups {
		// CIDR (networks:) peers are destinations only. Evaluating them as
		// sources yields meaningless "default allow" (no ANP/BANP subject matches
		// a CIDR zone) and looks like "traffic from that IP is permitted".
		if IsNetworkZone(src) {
			continue
		}
		m.Results[src.Key()] = make(map[string]*PairResult)
		for _, dst := range groups {
			if src.Key() == dst.Key() {
				continue // self-pair — skip
			}
			m.Results[src.Key()][dst.Key()] = EvaluatePair(src, dst, fr)
		}
	}

	return m
}
