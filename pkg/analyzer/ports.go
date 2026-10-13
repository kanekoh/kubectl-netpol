package analyzer

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// PortQuery is a concrete port/protocol to evaluate.
// Port=0 and Protocol="*" means "other / unspecified" traffic (not covered by
// an explicit port list on a rule).
type PortQuery struct {
	Port     int32
	Protocol string // "TCP", "UDP", "SCTP", or "*"
}

func (q PortQuery) Key() string {
	return fmt.Sprintf("%d/%s", q.Port, q.Protocol)
}

func (q PortQuery) Label() string {
	if q.Port == 0 || q.Protocol == "*" {
		return "any"
	}
	return fmt.Sprintf("%d/%s", q.Port, q.Protocol)
}

// anpPortsMatch reports whether an ANP/BANP rule's Ports select q.
// nil / empty Ports = all ports. NamedPort is ignored for numeric queries (※未対応).
func anpPortsMatch(ports *[]anpv1alpha1.AdminNetworkPolicyPort, q PortQuery) bool {
	if ports == nil || len(*ports) == 0 {
		return true
	}
	// Explicit port lists do not match the catch-all "any" query.
	if q.Port == 0 || q.Protocol == "*" {
		return false
	}
	for _, p := range *ports {
		if p.PortNumber != nil {
			proto := string(p.PortNumber.Protocol)
			if proto == "" {
				proto = string(corev1.ProtocolTCP)
			}
			if !strings.EqualFold(proto, q.Protocol) {
				continue
			}
			if p.PortNumber.Port == q.Port {
				return true
			}
		}
		if p.PortRange != nil {
			proto := string(p.PortRange.Protocol)
			if proto == "" {
				proto = string(corev1.ProtocolTCP)
			}
			if !strings.EqualFold(proto, q.Protocol) {
				continue
			}
			if q.Port >= p.PortRange.Start && q.Port <= p.PortRange.End {
				return true
			}
		}
		// NamedPort: no numeric match
	}
	return false
}

// npPortsMatch reports whether a NetworkPolicy rule's Ports select q.
func npPortsMatch(ports []netv1.NetworkPolicyPort, q PortQuery) bool {
	if len(ports) == 0 {
		return true
	}
	if q.Port == 0 || q.Protocol == "*" {
		return false
	}
	for _, p := range ports {
		proto := string(corev1.ProtocolTCP)
		if p.Protocol != nil {
			proto = string(*p.Protocol)
		}
		if !strings.EqualFold(proto, q.Protocol) {
			continue
		}
		if p.Port == nil {
			return true
		}
		if p.Port.Type != intstr.Int {
			continue // named port — skip for numeric query
		}
		start := p.Port.IntVal
		end := start
		if p.EndPort != nil {
			end = *p.EndPort
		}
		if q.Port >= start && q.Port <= end {
			return true
		}
	}
	return false
}

func collectANPPorts(ports *[]anpv1alpha1.AdminNetworkPolicyPort, add func(PortQuery)) {
	if ports == nil || len(*ports) == 0 {
		return
	}
	for _, p := range *ports {
		if p.PortNumber != nil {
			proto := string(p.PortNumber.Protocol)
			if proto == "" {
				proto = string(corev1.ProtocolTCP)
			}
			add(PortQuery{Port: p.PortNumber.Port, Protocol: proto})
		}
		if p.PortRange != nil {
			proto := string(p.PortRange.Protocol)
			if proto == "" {
				proto = string(corev1.ProtocolTCP)
			}
			// Represent range by endpoints (full expansion can be huge).
			add(PortQuery{Port: p.PortRange.Start, Protocol: proto})
			add(PortQuery{Port: p.PortRange.End, Protocol: proto})
		}
	}
}

func collectNPPorts(ports []netv1.NetworkPolicyPort, add func(PortQuery)) {
	for _, p := range ports {
		proto := string(corev1.ProtocolTCP)
		if p.Protocol != nil {
			proto = string(*p.Protocol)
		}
		if p.Port == nil {
			continue
		}
		if p.Port.Type != intstr.Int {
			continue
		}
		start := p.Port.IntVal
		end := start
		if p.EndPort != nil {
			end = *p.EndPort
		}
		add(PortQuery{Port: start, Protocol: proto})
		if end != start {
			add(PortQuery{Port: end, Protocol: proto})
		}
	}
}

// collectPortQueries returns explicit ports from rules that match src/dst peers,
// plus the catch-all any (0/*).
func collectPortQueries(src, dst WorkloadGroup, fr *FetchResult) []PortQuery {
	seen := map[string]PortQuery{}
	add := func(q PortQuery) {
		seen[q.Key()] = q
	}
	add(PortQuery{Port: 0, Protocol: "*"})

	for _, anp := range fr.ANPs {
		if anpSubjectMatchesGroup(anp.Spec.Subject, dst, fr.Namespaces) {
			for _, rule := range anp.Spec.Ingress {
				for _, peer := range rule.From {
					if anpIngressPeerMatchesGroup(peer, src, fr.Namespaces) {
						collectANPPorts(rule.Ports, add)
					}
				}
			}
		}
		if anpSubjectMatchesGroup(anp.Spec.Subject, src, fr.Namespaces) {
			for _, rule := range anp.Spec.Egress {
				for _, peer := range rule.To {
					if anpEgressPeerMatchesGroup(peer, dst, fr.Namespaces) {
						collectANPPorts(rule.Ports, add)
					}
				}
			}
		}
	}

	for _, banp := range fr.BANPs {
		if banpSubjectMatchesGroup(banp.Spec.Subject, dst, fr.Namespaces) {
			for _, rule := range banp.Spec.Ingress {
				for _, peer := range rule.From {
					if banpIngressPeerMatchesGroup(peer, src, fr.Namespaces) {
						collectANPPorts(rule.Ports, add)
					}
				}
			}
		}
		if banpSubjectMatchesGroup(banp.Spec.Subject, src, fr.Namespaces) {
			for _, rule := range banp.Spec.Egress {
				for _, peer := range rule.To {
					if banpEgressPeerMatchesGroup(peer, dst, fr.Namespaces) {
						collectANPPorts(rule.Ports, add)
					}
				}
			}
		}
	}

	for _, np := range fr.NetworkPolicies {
		if hasIngressPolicy(np) && podSelectedByNP(dst, np) {
			for _, rule := range np.Spec.Ingress {
				if ingressRuleMatchesSrc(rule, src, np.Namespace, fr.Namespaces) {
					collectNPPorts(rule.Ports, add)
				}
			}
		}
		if hasEgressPolicy(np) && podSelectedByNP(src, np) {
			for _, rule := range np.Spec.Egress {
				if egressRuleMatchesDst(rule, dst, np.Namespace, fr.Namespaces) {
					collectNPPorts(rule.Ports, add)
				}
			}
		}
	}

	out := make([]PortQuery, 0, len(seen))
	for _, q := range seen {
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}
