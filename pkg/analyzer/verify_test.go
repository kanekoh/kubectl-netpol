package analyzer

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func TestVerify_ShadowedAllow_ANPDenyOverNP(t *testing.T) {
	fr := &FetchResult{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "quarantine", Labels: map[string]string{"kubernetes.io/metadata.name": "quarantine"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "backend", Labels: map[string]string{"kubernetes.io/metadata.name": "backend"}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "quarantine", Labels: map[string]string{"app": "compromised"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "backend", Labels: map[string]string{"app": "api"}}},
		},
		ANPs: []anpv1alpha1.AdminNetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "quarantine-lockdown"},
			Spec: anpv1alpha1.AdminNetworkPolicySpec{
				Priority: 5,
				Subject: anpv1alpha1.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "quarantine"}},
				},
				Egress: []anpv1alpha1.AdminNetworkPolicyEgressRule{{
					Action: anpv1alpha1.AdminNetworkPolicyRuleActionDeny,
					To: []anpv1alpha1.AdminNetworkPolicyEgressPeer{{
						Namespaces: &metav1.LabelSelector{},
					}},
				}},
			},
		}},
		NetworkPolicies: []netv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: "backend"},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				Ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "quarantine"}},
					}},
				}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			},
		}},
	}

	findings := Verify(fr, Options{LabelKey: "app", ShowAll: true})
	var shadowed int
	for _, f := range findings {
		if f.Code == "shadowed-allow" && f.Severity == SeverityWarning {
			shadowed++
		}
	}
	if shadowed == 0 {
		t.Fatalf("expected shadowed-allow warning, got %#v", findings)
	}
}

func TestVerify_NPOverridesBANP(t *testing.T) {
	fr := &FetchResult{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "payments", Labels: map[string]string{"kubernetes.io/metadata.name": "payments"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "payment-gateway", Labels: map[string]string{"kubernetes.io/metadata.name": "payment-gateway"}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "payments", Labels: map[string]string{"app": "payment-api"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "payment-gateway", Labels: map[string]string{"app": "gateway"}}},
		},
		NetworkPolicies: []netv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-gw", Namespace: "payments"},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "payment-api"}},
				Ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "payment-gateway"}},
					}},
				}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			},
		}},
		BANPs: []anpv1alpha1.BaselineAdminNetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: anpv1alpha1.BaselineAdminNetworkPolicySpec{
				Subject: anpv1alpha1.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "payments"}},
				},
				Ingress: []anpv1alpha1.BaselineAdminNetworkPolicyIngressRule{{
					Action: anpv1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
					From: []anpv1alpha1.AdminNetworkPolicyIngressPeer{{
						Namespaces: &metav1.LabelSelector{},
					}},
				}},
			},
		}},
	}

	findings := Verify(fr, Options{LabelKey: "app", ShowAll: true})
	found := false
	for _, f := range findings {
		if f.Code == "np-overrides-banp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected np-overrides-banp, got %#v", findings)
	}
}
