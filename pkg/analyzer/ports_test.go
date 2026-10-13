package analyzer

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func TestNPPortsMatch(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port8080 := intstr.FromInt(8080)
	ports := []netv1.NetworkPolicyPort{{
		Protocol: &tcp,
		Port:     &port8080,
	}}

	if !npPortsMatch(nil, PortQuery{Port: 9999, Protocol: "TCP"}) {
		t.Fatal("nil ports should match all")
	}
	if !npPortsMatch(ports, PortQuery{Port: 8080, Protocol: "TCP"}) {
		t.Fatal("8080/TCP should match")
	}
	if npPortsMatch(ports, PortQuery{Port: 9999, Protocol: "TCP"}) {
		t.Fatal("9999/TCP should not match explicit 8080")
	}
	if npPortsMatch(ports, PortQuery{Port: 0, Protocol: "*"}) {
		t.Fatal("any should not match explicit port list")
	}
}

func TestEvaluatePair_PortAwareNP(t *testing.T) {
	fr := &FetchResult{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "frontend", Labels: map[string]string{"kubernetes.io/metadata.name": "frontend"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "backend", Labels: map[string]string{"kubernetes.io/metadata.name": "backend"}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "frontend", Labels: map[string]string{"app": "web"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "backend", Labels: map[string]string{"app": "api"}}},
		},
		NetworkPolicies: []netv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-frontend", Namespace: "backend"},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				Ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "frontend"}},
					}},
					Ports: []netv1.NetworkPolicyPort{{
						Protocol: func() *corev1.Protocol { p := corev1.ProtocolTCP; return &p }(),
						Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 8080},
					}},
				}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			},
		}},
	}

	m := BuildMatrix(fr, Options{LabelKey: "app", ShowAll: true})
	src := "frontend/app=web"
	dst := "backend/app=api"
	pr := m.Results[src][dst]
	if pr == nil {
		t.Fatal("missing pair result")
	}
	if pr.Overall != VerdictAllow {
		t.Fatalf("overall want Allow, got %s ports=%#v", pr.Overall, pr.Ports)
	}

	var got8080, gotAny *PortResult
	for i := range pr.Ports {
		p := &pr.Ports[i]
		if p.Port == 8080 && p.Protocol == "TCP" {
			got8080 = p
		}
		if p.Port == 0 && p.Protocol == "*" {
			gotAny = p
		}
	}
	if got8080 == nil || got8080.Verdict != VerdictAllow || got8080.Layer != "NetworkPolicy" {
		t.Fatalf("8080/TCP want NP Allow, got %#v", got8080)
	}
	if gotAny == nil || gotAny.Verdict != VerdictDeny || gotAny.Layer != "NetworkPolicy" {
		t.Fatalf("any want NP Deny, got %#v", gotAny)
	}
}

func TestEvaluatePair_ANPPortSelective(t *testing.T) {
	ports := []anpv1alpha1.AdminNetworkPolicyPort{{
		PortNumber: &anpv1alpha1.Port{Protocol: corev1.ProtocolTCP, Port: 80},
	}}
	fr := &FetchResult{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "ingress", Labels: map[string]string{"team": "ingress", "kubernetes.io/metadata.name": "ingress"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"team": "app", "kubernetes.io/metadata.name": "app"}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ingress", Labels: map[string]string{"app": "router"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "app", Labels: map[string]string{"app": "web"}}},
		},
		ANPs: []anpv1alpha1.AdminNetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-80"},
			Spec: anpv1alpha1.AdminNetworkPolicySpec{
				Priority: 10,
				Subject: anpv1alpha1.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "app"}},
				},
				Ingress: []anpv1alpha1.AdminNetworkPolicyIngressRule{{
					Action: anpv1alpha1.AdminNetworkPolicyRuleActionAllow,
					From: []anpv1alpha1.AdminNetworkPolicyIngressPeer{{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "ingress"}},
					}},
					Ports: &ports,
				}},
			},
		}},
	}

	m := BuildMatrix(fr, Options{LabelKey: "app", ShowAll: true})
	pr := m.Results["ingress/app=router"]["app/app=web"]
	if pr == nil || pr.Overall != VerdictAllow {
		t.Fatalf("want Overall Allow, got %#v", pr)
	}
	found80 := false
	for _, p := range pr.Ports {
		if p.Port == 80 && p.Protocol == "TCP" {
			found80 = true
			if p.Verdict != VerdictAllow || p.Layer != "ANP" {
				t.Fatalf("80/TCP want ANP Allow, got %#v", p)
			}
		}
	}
	if !found80 {
		t.Fatalf("expected 80/TCP in ports %#v", pr.Ports)
	}
}
