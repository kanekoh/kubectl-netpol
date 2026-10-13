package analyzer

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

const (
	// NetworkZoneNamespace is the synthetic namespace for CIDR (networks:) peers.
	NetworkZoneNamespace = "_network"
	// AllPodsGroupName is used when a zone represents an entire namespace (no pod selector).
	AllPodsGroupName = "all-pods"
)

// SynthesizeFromPolicies derives Namespaces and WorkloadGroups from policy selectors
// when no pods are available. Returns an updated FetchResult (namespaces merged) and groups.
func SynthesizeFromPolicies(fr *FetchResult) (*FetchResult, []WorkloadGroup) {
	nsByName := map[string]*corev1.Namespace{}
	for i := range fr.Namespaces {
		ns := fr.Namespaces[i]
		cp := ns
		nsByName[ns.Name] = &cp
	}

	groupsByKey := map[string]WorkloadGroup{}

	addNS := func(name string, labels map[string]string) {
		if name == "" || name == NetworkZoneNamespace {
			return
		}
		lbls := copyLabels(labels)
		if lbls == nil {
			lbls = map[string]string{}
		}
		lbls["kubernetes.io/metadata.name"] = name
		if existing, ok := nsByName[name]; ok {
			for k, v := range lbls {
				if existing.Labels == nil {
					existing.Labels = map[string]string{}
				}
				if _, has := existing.Labels[k]; !has {
					existing.Labels[k] = v
				}
			}
			return
		}
		nsByName[name] = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: lbls,
			},
		}
	}

	addGroup := func(ns, name string, podLabels map[string]string) {
		if ns == "" || name == "" {
			return
		}
		key := ns + "/" + name
		if _, ok := groupsByKey[key]; ok {
			return
		}
		var nsLbls map[string]string
		if existing, ok := nsByName[ns]; ok {
			nsLbls = copyLabels(existing.Labels)
		}
		groupsByKey[key] = WorkloadGroup{
			Namespace: ns,
			Name:      name,
			Labels:    copyLabels(podLabels),
			NSLabels:  nsLbls,
		}
	}

	addNSZone := func(labels map[string]string) {
		name := namespaceNameFromLabels(labels)
		addNS(name, labels)
		addGroup(name, AllPodsGroupName, nil)
	}

	addCIDR := func(cidr string) {
		if cidr == "" {
			return
		}
		name := "cidr=" + cidr
		addGroup(NetworkZoneNamespace, name, map[string]string{"cidr": cidr})
	}

	// --- Collect from ANPs ---
	for _, anp := range fr.ANPs {
		collectANPSubject(anp.Spec.Subject, addNSZone, addGroup, addNS)
		for _, rule := range anp.Spec.Ingress {
			for _, peer := range rule.From {
				collectANPIngressPeer(peer, addNSZone, addGroup, addNS)
			}
		}
		for _, rule := range anp.Spec.Egress {
			for _, peer := range rule.To {
				collectANPEgressPeer(peer, addNSZone, addGroup, addNS, addCIDR)
			}
		}
	}

	// --- Collect from BANPs ---
	for _, banp := range fr.BANPs {
		collectANPSubject(banp.Spec.Subject, addNSZone, addGroup, addNS)
		for _, rule := range banp.Spec.Ingress {
			for _, peer := range rule.From {
				collectANPIngressPeer(peer, addNSZone, addGroup, addNS)
			}
		}
		for _, rule := range banp.Spec.Egress {
			for _, peer := range rule.To {
				collectANPEgressPeer(peer, addNSZone, addGroup, addNS, addCIDR)
			}
		}
	}

	// --- Collect from NetworkPolicies ---
	for _, np := range fr.NetworkPolicies {
		collectNetworkPolicy(np, addNSZone, addGroup, addNS, addCIDR)
	}

	// Materialize namespaces into FetchResult
	out := *fr
	out.Namespaces = make([]corev1.Namespace, 0, len(nsByName))
	for _, ns := range nsByName {
		out.Namespaces = append(out.Namespaces, *ns)
	}
	sort.Slice(out.Namespaces, func(i, j int) bool {
		return out.Namespaces[i].Name < out.Namespaces[j].Name
	})

	groups := make([]WorkloadGroup, 0, len(groupsByKey))
	for _, g := range groupsByKey {
		// Refresh NSLabels from final namespace map (covers late addNS merges).
		if ns, ok := nsByName[g.Namespace]; ok {
			g.NSLabels = copyLabels(ns.Labels)
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Key() < groups[j].Key()
	})

	return &out, groups
}

func collectANPSubject(
	subject anpv1alpha1.AdminNetworkPolicySubject,
	addNSZone func(map[string]string),
	addGroup func(ns, name string, podLabels map[string]string),
	addNS func(name string, labels map[string]string),
) {
	if subject.Namespaces != nil {
		for _, lbls := range expandLabelSelector(subject.Namespaces) {
			addNSZone(lbls)
		}
		return
	}
	if subject.Pods != nil {
		collectNamespacedPod(&subject.Pods.NamespaceSelector, &subject.Pods.PodSelector, addNSZone, addGroup, addNS)
	}
}

func collectANPIngressPeer(
	peer anpv1alpha1.AdminNetworkPolicyIngressPeer,
	addNSZone func(map[string]string),
	addGroup func(ns, name string, podLabels map[string]string),
	addNS func(name string, labels map[string]string),
) {
	if peer.Namespaces != nil {
		for _, lbls := range expandLabelSelector(peer.Namespaces) {
			addNSZone(lbls)
		}
		return
	}
	if peer.Pods != nil {
		collectNamespacedPod(&peer.Pods.NamespaceSelector, &peer.Pods.PodSelector, addNSZone, addGroup, addNS)
	}
}

func collectANPEgressPeer(
	peer anpv1alpha1.AdminNetworkPolicyEgressPeer,
	addNSZone func(map[string]string),
	addGroup func(ns, name string, podLabels map[string]string),
	addNS func(name string, labels map[string]string),
	addCIDR func(string),
) {
	if peer.Namespaces != nil {
		for _, lbls := range expandLabelSelector(peer.Namespaces) {
			addNSZone(lbls)
		}
	}
	if peer.Pods != nil {
		collectNamespacedPod(&peer.Pods.NamespaceSelector, &peer.Pods.PodSelector, addNSZone, addGroup, addNS)
	}
	for _, cidr := range peer.Networks {
		addCIDR(string(cidr))
	}
}

func collectNamespacedPod(
	nsSel *metav1.LabelSelector,
	podSel *metav1.LabelSelector,
	addNSZone func(map[string]string),
	addGroup func(ns, name string, podLabels map[string]string),
	addNS func(name string, labels map[string]string),
) {
	nsLabelSets := expandLabelSelector(nsSel)
	if len(nsLabelSets) == 0 {
		// Empty namespace selector → matches all; no zone from ns alone.
		// Still need a concrete ns if we have pod labels — skip without ns hint.
		return
	}
	podLabelSets := expandLabelSelector(podSel)
	if len(podLabelSets) == 0 {
		podLabelSets = []map[string]string{nil}
	}
	for _, nsLbls := range nsLabelSets {
		nsName := namespaceNameFromLabels(nsLbls)
		addNS(nsName, nsLbls)
		for _, podLbls := range podLabelSets {
			if podLbls == nil || len(podLbls) == 0 {
				addGroup(nsName, AllPodsGroupName, nil)
			} else {
				addGroup(nsName, groupNameFromPodLabels(podLbls), podLbls)
			}
		}
	}
}

func collectNetworkPolicy(
	np netv1.NetworkPolicy,
	addNSZone func(map[string]string),
	addGroup func(ns, name string, podLabels map[string]string),
	addNS func(name string, labels map[string]string),
	addCIDR func(string),
) {
	nsName := np.Namespace
	if nsName == "" {
		nsName = "default"
	}
	addNS(nsName, map[string]string{"kubernetes.io/metadata.name": nsName})

	podSets := expandLabelSelector(&np.Spec.PodSelector)
	if len(podSets) == 0 {
		addGroup(nsName, AllPodsGroupName, nil)
	} else {
		for _, pl := range podSets {
			if len(pl) == 0 {
				addGroup(nsName, AllPodsGroupName, nil)
			} else {
				addGroup(nsName, groupNameFromPodLabels(pl), pl)
			}
		}
	}

	for _, rule := range np.Spec.Ingress {
		for _, peer := range rule.From {
			collectNPPeer(peer, np.Namespace, addNSZone, addGroup, addNS, addCIDR)
		}
	}
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			collectNPPeer(peer, np.Namespace, addNSZone, addGroup, addNS, addCIDR)
		}
	}
}

func collectNPPeer(
	peer netv1.NetworkPolicyPeer,
	policyNamespace string,
	addNSZone func(map[string]string),
	addGroup func(ns, name string, podLabels map[string]string),
	addNS func(name string, labels map[string]string),
	addCIDR func(string),
) {
	if peer.IPBlock != nil {
		addCIDR(peer.IPBlock.CIDR)
		return
	}
	if peer.NamespaceSelector != nil {
		nsSets := expandLabelSelector(peer.NamespaceSelector)
		podSets := []map[string]string{nil}
		if peer.PodSelector != nil {
			podSets = expandLabelSelector(peer.PodSelector)
			if len(podSets) == 0 {
				podSets = []map[string]string{nil}
			}
		}
		for _, nsLbls := range nsSets {
			nsName := namespaceNameFromLabels(nsLbls)
			addNS(nsName, nsLbls)
			for _, pl := range podSets {
				if pl == nil || len(pl) == 0 {
					addGroup(nsName, AllPodsGroupName, nil)
				} else {
					addGroup(nsName, groupNameFromPodLabels(pl), pl)
				}
			}
		}
		return
	}
	// podSelector only — same namespace as policy
	nsName := policyNamespace
	if nsName == "" {
		nsName = "default"
	}
	addNS(nsName, map[string]string{"kubernetes.io/metadata.name": nsName})
	if peer.PodSelector != nil {
		for _, pl := range expandLabelSelector(peer.PodSelector) {
			if len(pl) == 0 {
				addGroup(nsName, AllPodsGroupName, nil)
			} else {
				addGroup(nsName, groupNameFromPodLabels(pl), pl)
			}
		}
	} else {
		addGroup(nsName, AllPodsGroupName, nil)
	}
}

// expandLabelSelector turns a LabelSelector into one or more concrete label maps.
// Empty selectors (match all) return nil — callers must not create zones from them.
// NotIn / Exists / DoesNotExist do not expand the cartesian product; a base map is kept
// so evaluation can still match representative zones from other rules.
func expandLabelSelector(sel *metav1.LabelSelector) []map[string]string {
	if sel == nil {
		return nil
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return nil // empty = match all → no zone
	}

	bases := []map[string]string{copyLabels(sel.MatchLabels)}
	if bases[0] == nil {
		bases[0] = map[string]string{}
	}

	for _, expr := range sel.MatchExpressions {
		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			if len(expr.Values) == 0 {
				continue
			}
			next := make([]map[string]string, 0, len(bases)*len(expr.Values))
			for _, base := range bases {
				for _, v := range expr.Values {
					m := copyLabels(base)
					m[expr.Key] = v
					next = append(next, m)
				}
			}
			bases = next
		case metav1.LabelSelectorOpNotIn, metav1.LabelSelectorOpExists, metav1.LabelSelectorOpDoesNotExist:
			// Keep current bases as representatives; matching is done at evaluation time.
			continue
		default:
			continue
		}
	}

	// Deduplicate by fingerprint
	seen := map[string]struct{}{}
	var out []map[string]string
	for _, m := range bases {
		fp := labelFingerprint(m)
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, m)
	}
	return out
}

func namespaceNameFromLabels(labels map[string]string) string {
	if labels != nil {
		if n, ok := labels["kubernetes.io/metadata.name"]; ok && n != "" {
			return sanitizeK8sName(n)
		}
	}
	if len(labels) == 0 {
		return "synth-any"
	}
	slug := labelSlug(labels)
	name := "synth-" + slug
	if len(name) > 63 {
		sum := sha1.Sum([]byte(labelFingerprint(labels)))
		name = "synth-" + hex.EncodeToString(sum[:6])
	}
	return sanitizeK8sName(name)
}

func groupNameFromPodLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return AllPodsGroupName
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

func labelSlug(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		shortKey := k
		if i := strings.LastIndex(k, "/"); i >= 0 {
			shortKey = k[i+1:]
		}
		parts = append(parts, shortKey+"-"+labels[k])
	}
	s := strings.Join(parts, "-")
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == '-' || r == '_' || r == '.':
			return '-'
		default:
			return '-'
		}
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		sum := sha1.Sum([]byte(labelFingerprint(labels)))
		return hex.EncodeToString(sum[:6])
	}
	return s
}

func labelFingerprint(labels map[string]string) string {
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
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

func sanitizeK8sName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		case r == '_' || r == '/' || r == '=':
			b.WriteByte('-')
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-.")
	if s == "" {
		s = "synth"
	}
	if len(s) > 63 {
		s = s[:63]
		s = strings.TrimRight(s, "-.")
	}
	return s
}

func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// IsNetworkZone reports whether the group represents a CIDR (networks:) peer.
func IsNetworkZone(g WorkloadGroup) bool {
	return g.Namespace == NetworkZoneNamespace && strings.HasPrefix(g.Name, "cidr=")
}

// NetworkCIDR returns the CIDR string for a network zone, or empty if not a network zone.
func NetworkCIDR(g WorkloadGroup) string {
	if !IsNetworkZone(g) {
		return ""
	}
	return strings.TrimPrefix(g.Name, "cidr=")
}

// HasPolicies reports whether the fetch result contains any network policy resources.
func HasPolicies(fr *FetchResult) bool {
	return len(fr.NetworkPolicies) > 0 || len(fr.ANPs) > 0 || len(fr.BANPs) > 0
}
