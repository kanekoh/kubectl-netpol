package analyzer

import (
	"fmt"
	"sort"
)

// Severity for advisory verify findings.
type Severity string

const (
	SeverityWarning Severity = "Warning"
	SeverityInfo    Severity = "Info"
)

// Finding is one advisory note from verify (not a YAML schema error).
type Finding struct {
	Severity Severity
	Code     string // shadowed-allow | np-overrides-banp | anp-skips-banp-deny
	Src      string
	Dst      string
	Message  string
	Detail   string
}

// Verify walks zone pairs and reports layer conflicts / dead lower-layer rules.
//
// Finding classes (ARCHITECTURE):
//   - Warning shadowed-allow: higher layer Deny, lower layer would Allow
//   - Info np-overrides-banp: NP Allow wins; BANP would Deny (intentional model)
//   - Info anp-skips-banp-deny: ANP Allow wins; BANP would Deny (BANP inert for pair)
func Verify(fr *FetchResult, opts Options) []Finding {
	m := BuildMatrix(fr, opts)
	var findings []Finding

	for _, src := range m.Groups {
		if IsNetworkZone(src) {
			continue
		}
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				continue
			}
			findings = append(findings, verifyPair(src, dst, fr)...)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity == SeverityWarning
		}
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		if findings[i].Src != findings[j].Src {
			return findings[i].Src < findings[j].Src
		}
		return findings[i].Dst < findings[j].Dst
	})
	return findings
}

func verifyPair(src, dst WorkloadGroup, fr *FetchResult) []Finding {
	srcN, dstN := src.DisplayName(), dst.DisplayName()
	var out []Finding
	seen := map[string]bool{} // code|portKey → dedupe identical findings across ports

	for _, q := range collectPortQueries(src, dst, fr) {
		anpV, anpReason, anpDecided := EvaluateANP(src, dst, fr.ANPs, fr.Namespaces, q)
		npV, npDecided := EvaluateNetworkPolicy(src, dst, fr.NetworkPolicies, fr.Namespaces, q)
		banpV, banpReason, banpDecided := EvaluateBANP(src, dst, fr.BANPs, fr.Namespaces, q)
		portNote := q.Label()

		add := func(f Finding) {
			key := f.Code + "|" + q.Key() + "|" + f.Message
			if seen[key] {
				return
			}
			seen[key] = true
			if f.Detail == "" {
				f.Detail = "port " + portNote
			} else {
				f.Detail = "port " + portNote + "; " + f.Detail
			}
			out = append(out, f)
		}

		// --- Shadowed Allow: higher Deny hides lower Allow ---
		if anpDecided && anpV == VerdictDeny {
			if npDecided && npV == VerdictAllow {
				add(Finding{
					Severity: SeverityWarning,
					Code:     "shadowed-allow",
					Src:      srcN,
					Dst:      dstN,
					Message:  "NetworkPolicy Allow is unreachable — ANP Deny matches first. Confirm intentional?",
					Detail:   fmt.Sprintf("ANP: %s; NP would Allow", anpReason),
				})
			}
			if banpDecided && banpV == VerdictAllow {
				add(Finding{
					Severity: SeverityWarning,
					Code:     "shadowed-allow",
					Src:      srcN,
					Dst:      dstN,
					Message:  "BANP Allow is unreachable — ANP Deny matches first. Confirm intentional?",
					Detail:   fmt.Sprintf("ANP: %s; BANP: %s", anpReason, banpReason),
				})
			}
		}

		if (!anpDecided || anpV == VerdictUnknown) && npDecided && npV == VerdictDeny {
			if banpDecided && banpV == VerdictAllow {
				add(Finding{
					Severity: SeverityWarning,
					Code:     "shadowed-allow",
					Src:      srcN,
					Dst:      dstN,
					Message:  "BANP Allow is unreachable — NetworkPolicy Deny matches first. Confirm intentional?",
					Detail:   fmt.Sprintf("NP Deny; BANP: %s", banpReason),
				})
			}
		}

		// --- Info: lower Deny never reached because higher Allow ---
		if anpDecided && anpV == VerdictAllow && banpDecided && banpV == VerdictDeny {
			add(Finding{
				Severity: SeverityInfo,
				Code:     "anp-skips-banp-deny",
				Src:      srcN,
				Dst:      dstN,
				Message:  "BANP Deny is not evaluated for this pair — ANP Allow already decided. OK if ANP is the intended grant.",
				Detail:   fmt.Sprintf("ANP: %s; BANP would: %s", anpReason, banpReason),
			})
		}

		if (!anpDecided || anpV == VerdictUnknown) && npDecided && npV == VerdictAllow && banpDecided && banpV == VerdictDeny {
			add(Finding{
				Severity: SeverityInfo,
				Code:     "np-overrides-banp",
				Src:      srcN,
				Dst:      dstN,
				Message:  "NetworkPolicy Allow overrides BANP Deny (NP is evaluated before BANP). Typical allow-list pattern — confirm intentional.",
				Detail:   fmt.Sprintf("NP Allow; BANP would: %s", banpReason),
			})
		}
	}

	return out
}
