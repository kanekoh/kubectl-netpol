package analyzer

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func TestSynthesizeFromPolicies_ANPBANP(t *testing.T) {
	fr := &FetchResult{
		ANPs: []anpv1alpha1.AdminNetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-from-platform"},
				Spec: anpv1alpha1.AdminNetworkPolicySpec{
					Priority: 20,
					Subject: anpv1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{
							MatchLabels: map[string]string{"user-project": "true"},
						},
					},
					Ingress: []anpv1alpha1.AdminNetworkPolicyIngressRule{{
						Action: anpv1alpha1.AdminNetworkPolicyRuleActionAllow,
						From: []anpv1alpha1.AdminNetworkPolicyIngressPeer{{
							Namespaces: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{{
									Key:      "kubernetes.io/metadata.name",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"openshift-ingress"},
								}},
							},
						}},
					}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-egress"},
				Spec: anpv1alpha1.AdminNetworkPolicySpec{
					Priority: 21,
					Subject: anpv1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{
							MatchLabels: map[string]string{"user-project": "true"},
						},
					},
					Egress: []anpv1alpha1.AdminNetworkPolicyEgressRule{{
						Action: anpv1alpha1.AdminNetworkPolicyRuleActionAllow,
						To: []anpv1alpha1.AdminNetworkPolicyEgressPeer{{
							Networks: []anpv1alpha1.CIDR{"172.20.0.1/32"},
						}},
					}},
				},
			},
		},
		BANPs: []anpv1alpha1.BaselineAdminNetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: anpv1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: anpv1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{
							MatchLabels: map[string]string{"user-project": "true"},
						},
					},
					Egress: []anpv1alpha1.BaselineAdminNetworkPolicyEgressRule{{
						Action: anpv1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
						To: []anpv1alpha1.AdminNetworkPolicyEgressPeer{{
							Networks: []anpv1alpha1.CIDR{"0.0.0.0/0"},
						}},
					}},
				},
			},
		},
	}

	out, groups := SynthesizeFromPolicies(fr)
	if len(groups) < 3 {
		t.Fatalf("expected at least 3 groups, got %d: %#v", len(groups), groups)
	}

	m := BuildMatrix(fr, Options{})
	if !m.Synthesized {
		t.Fatal("expected Synthesized=true")
	}
	if len(m.Groups) == 0 {
		t.Fatal("expected non-empty matrix groups")
	}

	// Find keys
	var ingress, user, cidrAllow, cidrDeny string
	for _, g := range m.Groups {
		switch {
		case g.Namespace == "openshift-ingress":
			ingress = g.Key()
		case g.Namespace == NetworkZoneNamespace && g.Name == "cidr=172.20.0.1/32":
			cidrAllow = g.Key()
		case g.Namespace == NetworkZoneNamespace && g.Name == "cidr=0.0.0.0/0":
			cidrDeny = g.Key()
		case g.Name == AllPodsGroupName:
			nsLbls := getNamespaceLabels(g.Namespace, out.Namespaces)
			if nsLbls["user-project"] == "true" && nsLbls["environment"] == "" {
				user = g.Key()
			}
		}
	}
	if ingress == "" || user == "" || cidrAllow == "" {
		t.Fatalf("missing zones ingress=%q user=%q cidrAllow=%q groups=%v", ingress, user, cidrAllow, m.Groups)
	}

	if pr := m.Results[ingress][user]; pr == nil || pr.Overall != VerdictAllow || pr.Ports[0].Layer != "ANP" {
		t.Fatalf("openshift-ingress→user: want ANP Allow, got %#v", pr)
	}
	if pr := m.Results[user][cidrAllow]; pr == nil || pr.Overall != VerdictAllow || pr.Ports[0].Layer != "ANP" {
		t.Fatalf("user→172.20.0.1/32: want ANP Allow, got %#v", pr)
	}
	if cidrDeny != "" {
		if pr := m.Results[user][cidrDeny]; pr == nil || pr.Overall != VerdictDeny || pr.Ports[0].Layer != "BANP" {
			t.Fatalf("user→0.0.0.0/0: want BANP Deny, got %#v", pr)
		}
	}
}

func TestExpandLabelSelector_EmptyIsNil(t *testing.T) {
	if got := expandLabelSelector(&metav1.LabelSelector{}); got != nil {
		t.Fatalf("empty selector should yield nil zones, got %#v", got)
	}
}
