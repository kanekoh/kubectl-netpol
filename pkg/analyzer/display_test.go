package analyzer

import "testing"

func TestNodeCaption_LabelBased(t *testing.T) {
	g := WorkloadGroup{
		Namespace: "synth-user-project-true",
		Name:      AllPodsGroupName,
		NSLabels: map[string]string{
			"kubernetes.io/metadata.name": "synth-user-project-true",
			"user-project":                "true",
			"environment":                 "dev",
		},
	}
	got := g.NodeCaption()
	want := "all-pods | environment=dev, user-project=true"
	if got != want {
		t.Fatalf("NodeCaption=%q want %q", got, want)
	}
	if g.SubgraphCaption() != "environment=dev, user-project=true" {
		t.Fatalf("SubgraphCaption=%q", g.SubgraphCaption())
	}
}

func TestNodeCaption_NameBased(t *testing.T) {
	g := WorkloadGroup{
		Namespace: "openshift-ingress",
		Name:      AllPodsGroupName,
		NSLabels: map[string]string{
			"kubernetes.io/metadata.name": "openshift-ingress",
		},
	}
	if g.NodeCaption() != "all-pods" {
		t.Fatalf("NodeCaption=%q", g.NodeCaption())
	}
	if g.SubgraphCaption() != "openshift-ingress" {
		t.Fatalf("SubgraphCaption=%q", g.SubgraphCaption())
	}
	if g.DisplayName() != "ns:openshift-ingress/all-pods" {
		t.Fatalf("DisplayName=%q", g.DisplayName())
	}
}

func TestDisplayName_LabelBased(t *testing.T) {
	g := WorkloadGroup{
		Namespace: "synth-user-project-true",
		Name:      AllPodsGroupName,
		NSLabels: map[string]string{
			"kubernetes.io/metadata.name": "synth-user-project-true",
			"user-project":                "true",
		},
	}
	want := "labels:user-project=true/all-pods"
	if g.DisplayName() != want {
		t.Fatalf("DisplayName=%q want %q", g.DisplayName(), want)
	}
}
