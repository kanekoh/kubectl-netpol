package visualizer

import "testing"

func TestEscapeMermaidLabel_CIDR(t *testing.T) {
	got := escapeMermaidLabel("cidr=0.0.0.0/0")
	want := "cidr=0.0.0.0／0"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSanitizeID_LeadingUnderscore(t *testing.T) {
	got := sanitizeID("_network/cidr=0.0.0.0/0")
	if got[0] == '_' {
		t.Fatalf("ID must not start with underscore: %q", got)
	}
	if got != "n_network_cidr_0_0_0_0_0" {
		t.Fatalf("got %q", got)
	}
}
