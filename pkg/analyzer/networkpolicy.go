package analyzer

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// getNamespaceLabels returns the labels of the named namespace from the cached list.
// Shared by networkpolicy.go, anp.go, and banp.go (same package).
func getNamespaceLabels(nsName string, namespaces []corev1.Namespace) map[string]string {
	for _, ns := range namespaces {
		if ns.Name == nsName {
			return ns.Labels
		}
	}
	return map[string]string{"kubernetes.io/metadata.name": nsName}
}

// podSelectedByNP returns true when group's namespace and labels match np's podSelector.
func podSelectedByNP(group WorkloadGroup, np netv1.NetworkPolicy) bool {
	if np.Namespace != group.Namespace {
		return false
	}
	sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		return false
	}
	return sel.Matches(labels.Set(group.Labels))
}

// hasIngressPolicy returns true when the NP includes Ingress in its PolicyTypes
// (or when PolicyTypes is empty, which implies Ingress).
func hasIngressPolicy(np netv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return true
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == netv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

// hasEgressPolicy returns true when the NP explicitly includes Egress in PolicyTypes.
func hasEgressPolicy(np netv1.NetworkPolicy) bool {
	for _, t := range np.Spec.PolicyTypes {
		if t == netv1.PolicyTypeEgress {
			return true
		}
	}
	return false
}

// npPeerMatchesGroup checks whether a NetworkPolicyPeer matches the given workload group.
//
// Semantics per the Kubernetes NetworkPolicy spec:
//   - podSelector only (no namespaceSelector) → pods in policyNamespace with those labels
//   - namespaceSelector only → all pods in matching namespaces
//   - both → pods with those labels in matching namespaces
func npPeerMatchesGroup(peer netv1.NetworkPolicyPeer, group WorkloadGroup, policyNamespace string, namespaces []corev1.Namespace) bool {
	if peer.IPBlock != nil {
		// IP block rules are not relevant for pod-to-pod matching
		return false
	}

	if peer.NamespaceSelector == nil {
		// podSelector only — must be in the policy's own namespace
		if group.Namespace != policyNamespace {
			return false
		}
		if peer.PodSelector != nil {
			sel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
			if err != nil {
				return false
			}
			return sel.Matches(labels.Set(group.Labels))
		}
		return true
	}

	// NamespaceSelector is set — check the group's namespace labels
	nsSel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
	if err != nil {
		return false
	}
	nsLabels := getNamespaceLabels(group.Namespace, namespaces)
	if !nsSel.Matches(labels.Set(nsLabels)) {
		return false
	}

	// Also check pod labels if podSelector is set
	if peer.PodSelector != nil {
		podSel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return false
		}
		return podSel.Matches(labels.Set(group.Labels))
	}

	return true
}

// ingressRuleMatchesSrc returns true when at least one From peer in the rule matches src.
func ingressRuleMatchesSrc(rule netv1.NetworkPolicyIngressRule, src WorkloadGroup, policyNamespace string, namespaces []corev1.Namespace) bool {
	if len(rule.From) == 0 {
		return true // empty From = allow all
	}
	for _, peer := range rule.From {
		if npPeerMatchesGroup(peer, src, policyNamespace, namespaces) {
			return true
		}
	}
	return false
}

// egressRuleMatchesDst returns true when at least one To peer in the rule matches dst.
func egressRuleMatchesDst(rule netv1.NetworkPolicyEgressRule, dst WorkloadGroup, policyNamespace string, namespaces []corev1.Namespace) bool {
	if len(rule.To) == 0 {
		return true // empty To = allow all
	}
	for _, peer := range rule.To {
		if npPeerMatchesGroup(peer, dst, policyNamespace, namespaces) {
			return true
		}
	}
	return false
}

// evaluateNPIngress checks whether NetworkPolicy ingress rules allow src→dst on q.
// Returns (verdict, decided): decided=false means no NP selects dst, caller proceeds.
func evaluateNPIngress(src, dst WorkloadGroup, nps []netv1.NetworkPolicy, namespaces []corev1.Namespace, q PortQuery) (Verdict, bool) {
	var applicable []netv1.NetworkPolicy
	for _, np := range nps {
		if hasIngressPolicy(np) && podSelectedByNP(dst, np) {
			applicable = append(applicable, np)
		}
	}
	if len(applicable) == 0 {
		return VerdictUnknown, false
	}
	for _, np := range applicable {
		for _, rule := range np.Spec.Ingress {
			if ingressRuleMatchesSrc(rule, src, np.Namespace, namespaces) && npPortsMatch(rule.Ports, q) {
				return VerdictAllow, true
			}
		}
	}
	return VerdictDeny, true
}

// evaluateNPEgress checks whether NetworkPolicy egress rules allow src→dst on q.
func evaluateNPEgress(src, dst WorkloadGroup, nps []netv1.NetworkPolicy, namespaces []corev1.Namespace, q PortQuery) (Verdict, bool) {
	var applicable []netv1.NetworkPolicy
	for _, np := range nps {
		if hasEgressPolicy(np) && podSelectedByNP(src, np) {
			applicable = append(applicable, np)
		}
	}
	if len(applicable) == 0 {
		return VerdictUnknown, false
	}
	for _, np := range applicable {
		for _, rule := range np.Spec.Egress {
			if egressRuleMatchesDst(rule, dst, np.Namespace, namespaces) && npPortsMatch(rule.Ports, q) {
				return VerdictAllow, true
			}
		}
	}
	return VerdictDeny, true
}

// EvaluateNetworkPolicy evaluates the NetworkPolicy layer for an src→dst pair on q.
// Returns (verdict, decided) — if decided=false, caller proceeds to BANP.
func EvaluateNetworkPolicy(src, dst WorkloadGroup, nps []netv1.NetworkPolicy, namespaces []corev1.Namespace, q PortQuery) (Verdict, bool) {
	ingressVerdict, ingressDecided := evaluateNPIngress(src, dst, nps, namespaces, q)
	egressVerdict, egressDecided := evaluateNPEgress(src, dst, nps, namespaces, q)

	if !ingressDecided && !egressDecided {
		return VerdictUnknown, false
	}
	if !ingressDecided {
		return egressVerdict, true
	}
	if !egressDecided {
		return ingressVerdict, true
	}
	// Both decided: Allow only when both layers allow
	if ingressVerdict == VerdictAllow && egressVerdict == VerdictAllow {
		return VerdictAllow, true
	}
	return VerdictDeny, true
}
