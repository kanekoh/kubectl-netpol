package analyzer

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// banpActionToVerdict converts a BANP rule action to a verdict.
// BANP has no Pass action — every matched rule is final.
func banpActionToVerdict(action anpv1alpha1.BaselineAdminNetworkPolicyRuleAction) Verdict {
	switch action {
	case anpv1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
		return VerdictAllow
	case anpv1alpha1.BaselineAdminNetworkPolicyRuleActionDeny:
		return VerdictDeny
	default:
		return VerdictUnknown
	}
}

// banpIngressPeerMatchesGroup checks whether a BANP ingress peer matches the source group.
// BANP reuses AdminNetworkPolicyIngressPeer from the ANP API.
func banpIngressPeerMatchesGroup(peer anpv1alpha1.AdminNetworkPolicyIngressPeer, group WorkloadGroup, namespaces []corev1.Namespace) bool {
	return anpIngressPeerMatchesGroup(peer, group, namespaces)
}

// banpEgressPeerMatchesGroup checks whether a BANP egress peer matches the destination group.
func banpEgressPeerMatchesGroup(peer anpv1alpha1.AdminNetworkPolicyEgressPeer, group WorkloadGroup, namespaces []corev1.Namespace) bool {
	return anpEgressPeerMatchesGroup(peer, group, namespaces)
}

// banpSubjectMatchesGroup checks whether the BANP subject selects the given group.
// BANP reuses AdminNetworkPolicySubject from the ANP API.
func banpSubjectMatchesGroup(subject anpv1alpha1.AdminNetworkPolicySubject, group WorkloadGroup, namespaces []corev1.Namespace) bool {
	return anpSubjectMatchesGroup(subject, group, namespaces)
}

// EvaluateBANP evaluates the BANP layer for an src→dst pair on q.
// BANP has no Pass — every matching rule is final.
// Returns (verdict, reason, decided). decided=false when no BANP matches.
func EvaluateBANP(src, dst WorkloadGroup, banps []anpv1alpha1.BaselineAdminNetworkPolicy, namespaces []corev1.Namespace, q PortQuery) (Verdict, string, bool) {
	for _, banp := range banps {
		// Ingress rules targeting dst
		if banpSubjectMatchesGroup(banp.Spec.Subject, dst, namespaces) {
			for _, rule := range banp.Spec.Ingress {
				if !anpPortsMatch(rule.Ports, q) {
					continue
				}
				for _, peer := range rule.From {
					if banpIngressPeerMatchesGroup(peer, src, namespaces) {
						verdict := banpActionToVerdict(rule.Action)
						reason := fmt.Sprintf("BANP %q ingress rule (action %s)", banp.Name, rule.Action)
						return verdict, reason, true
					}
				}
			}
		}

		// Egress rules from src
		if banpSubjectMatchesGroup(banp.Spec.Subject, src, namespaces) {
			for _, rule := range banp.Spec.Egress {
				if !anpPortsMatch(rule.Ports, q) {
					continue
				}
				for _, peer := range rule.To {
					if banpEgressPeerMatchesGroup(peer, dst, namespaces) {
						verdict := banpActionToVerdict(rule.Action)
						reason := fmt.Sprintf("BANP %q egress rule (action %s)", banp.Name, rule.Action)
						return verdict, reason, true
					}
				}
			}
		}
	}

	return VerdictUnknown, "", false
}
