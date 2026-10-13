package analyzer

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// sortedANPs returns ANPs sorted by priority ascending (lowest number = evaluated first).
func sortedANPs(anps []anpv1alpha1.AdminNetworkPolicy) []anpv1alpha1.AdminNetworkPolicy {
	sorted := make([]anpv1alpha1.AdminNetworkPolicy, len(anps))
	copy(sorted, anps)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Spec.Priority < sorted[j].Spec.Priority
	})
	return sorted
}

// anpSubjectMatchesGroup checks whether an ANP/BANP subject selects the given workload group.
//
// AdminNetworkPolicySubject.Namespaces is a *metav1.LabelSelector that matches namespace labels.
// AdminNetworkPolicySubject.Pods is a *NamespacedPod with NamespaceSelector+PodSelector.
func anpSubjectMatchesGroup(subject anpv1alpha1.AdminNetworkPolicySubject, group WorkloadGroup, namespaces []corev1.Namespace) bool {
	if IsNetworkZone(group) {
		return false
	}
	if subject.Namespaces != nil {
		sel, err := metav1.LabelSelectorAsSelector(subject.Namespaces)
		if err != nil {
			return false
		}
		nsLabels := getNamespaceLabels(group.Namespace, namespaces)
		return sel.Matches(labels.Set(nsLabels))
	}
	if subject.Pods != nil {
		nsSel, err := metav1.LabelSelectorAsSelector(&subject.Pods.NamespaceSelector)
		if err != nil {
			return false
		}
		nsLabels := getNamespaceLabels(group.Namespace, namespaces)
		if !nsSel.Matches(labels.Set(nsLabels)) {
			return false
		}
		podSel, err := metav1.LabelSelectorAsSelector(&subject.Pods.PodSelector)
		if err != nil {
			return false
		}
		return podSel.Matches(labels.Set(group.Labels))
	}
	return false
}

// anpIngressPeerMatchesGroup checks whether an ANP ingress peer matches the source group.
//
// AdminNetworkPolicyIngressPeer.Namespaces is *metav1.LabelSelector (namespace label selector).
// AdminNetworkPolicyIngressPeer.Pods is *NamespacedPod (namespace + pod selectors).
func anpIngressPeerMatchesGroup(peer anpv1alpha1.AdminNetworkPolicyIngressPeer, group WorkloadGroup, namespaces []corev1.Namespace) bool {
	if IsNetworkZone(group) {
		return false
	}
	if peer.Namespaces != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.Namespaces)
		if err != nil {
			return false
		}
		nsLabels := getNamespaceLabels(group.Namespace, namespaces)
		return sel.Matches(labels.Set(nsLabels))
	}
	if peer.Pods != nil {
		nsSel, err := metav1.LabelSelectorAsSelector(&peer.Pods.NamespaceSelector)
		if err != nil {
			return false
		}
		nsLabels := getNamespaceLabels(group.Namespace, namespaces)
		if !nsSel.Matches(labels.Set(nsLabels)) {
			return false
		}
		podSel, err := metav1.LabelSelectorAsSelector(&peer.Pods.PodSelector)
		if err != nil {
			return false
		}
		return podSel.Matches(labels.Set(group.Labels))
	}
	return false
}

// anpEgressPeerMatchesGroup checks whether an ANP egress peer matches the destination group.
//
// Networks peers match synthetic CIDR zones (_network/cidr=<CIDR>) by exact string equality.
// Nodes peers are not implemented.
func anpEgressPeerMatchesGroup(peer anpv1alpha1.AdminNetworkPolicyEgressPeer, group WorkloadGroup, namespaces []corev1.Namespace) bool {
	if len(peer.Networks) > 0 {
		cidr := NetworkCIDR(group)
		if cidr == "" {
			return false
		}
		for _, n := range peer.Networks {
			if string(n) == cidr {
				return true
			}
		}
		return false
	}
	if IsNetworkZone(group) {
		return false
	}
	if peer.Namespaces != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.Namespaces)
		if err != nil {
			return false
		}
		nsLabels := getNamespaceLabels(group.Namespace, namespaces)
		return sel.Matches(labels.Set(nsLabels))
	}
	if peer.Pods != nil {
		nsSel, err := metav1.LabelSelectorAsSelector(&peer.Pods.NamespaceSelector)
		if err != nil {
			return false
		}
		nsLabels := getNamespaceLabels(group.Namespace, namespaces)
		if !nsSel.Matches(labels.Set(nsLabels)) {
			return false
		}
		podSel, err := metav1.LabelSelectorAsSelector(&peer.Pods.PodSelector)
		if err != nil {
			return false
		}
		return podSel.Matches(labels.Set(group.Labels))
	}
	// Nodes peers are not implemented
	return false
}

// anpActionToVerdict converts an ANP rule action to a (verdict, decided) pair.
// Pass returns decided=false, indicating the next layer should be consulted.
func anpActionToVerdict(action anpv1alpha1.AdminNetworkPolicyRuleAction) (Verdict, bool) {
	switch action {
	case anpv1alpha1.AdminNetworkPolicyRuleActionAllow:
		return VerdictAllow, true
	case anpv1alpha1.AdminNetworkPolicyRuleActionDeny:
		return VerdictDeny, true
	case anpv1alpha1.AdminNetworkPolicyRuleActionPass:
		return VerdictUnknown, false
	default:
		return VerdictUnknown, false
	}
}

// EvaluateANP evaluates the AdminNetworkPolicy layer for an src→dst pair on q.
// Returns (verdict, reason, decided). decided=false means Pass or no match.
func EvaluateANP(src, dst WorkloadGroup, anps []anpv1alpha1.AdminNetworkPolicy, namespaces []corev1.Namespace, q PortQuery) (Verdict, string, bool) {
	for _, anp := range sortedANPs(anps) {
		// ANP ingress rules — subject selects dst
		if anpSubjectMatchesGroup(anp.Spec.Subject, dst, namespaces) {
			for _, rule := range anp.Spec.Ingress {
				if !anpPortsMatch(rule.Ports, q) {
					continue
				}
				for _, peer := range rule.From {
					if anpIngressPeerMatchesGroup(peer, src, namespaces) {
						verdict, decided := anpActionToVerdict(rule.Action)
						reason := fmt.Sprintf("ANP %q ingress rule (priority %d, action %s)", anp.Name, anp.Spec.Priority, rule.Action)
						if decided {
							return verdict, reason, true
						}
						return VerdictUnknown, reason + " [Pass]", false
					}
				}
			}
		}

		// ANP egress rules — subject selects src
		if anpSubjectMatchesGroup(anp.Spec.Subject, src, namespaces) {
			for _, rule := range anp.Spec.Egress {
				if !anpPortsMatch(rule.Ports, q) {
					continue
				}
				for _, peer := range rule.To {
					if anpEgressPeerMatchesGroup(peer, dst, namespaces) {
						verdict, decided := anpActionToVerdict(rule.Action)
						reason := fmt.Sprintf("ANP %q egress rule (priority %d, action %s)", anp.Name, anp.Spec.Priority, rule.Action)
						if decided {
							return verdict, reason, true
						}
						return VerdictUnknown, reason + " [Pass]", false
					}
				}
			}
		}
	}

	return VerdictUnknown, "", false
}
