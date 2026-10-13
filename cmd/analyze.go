package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kanekoh/kubectl-netpol/pkg/analyzer"
	"github.com/kanekoh/kubectl-netpol/pkg/visualizer"
)

type analyzeOptions struct {
	namespace  string
	output     string
	labelKey   string
	kubeconfig string
	showAll    bool
	fromDir    string
	focus      string
}

var rootCmd = &cobra.Command{
	Use:   "kubectl-netpol",
	Short: "Analyze Kubernetes network policies (ANP, NetworkPolicy, BANP)",
	Long: `kubectl-netpol connects to your cluster, fetches all network-related policies,
groups workloads by label, and outputs a human-readable connectivity matrix.

Use as a kubectl plugin: kubectl netpol analyze`,
}

// Execute runs the root command (called from main).
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newVerifyCmd())
}

func newAnalyzeCmd() *cobra.Command {
	opts := analyzeOptions{}

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze network policy connectivity between workloads",
		Long: `Fetches NetworkPolicy, AdminNetworkPolicy, and BaselineAdminNetworkPolicy
resources from the cluster, groups pods by label, evaluates the 3-layer policy
logic (ANP → NetworkPolicy → BANP), and outputs a zone connectivity matrix.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(cmd, opts)
		},
	}

	defaultKubeconfig := ""
	if home, err := os.UserHomeDir(); err == nil {
		defaultKubeconfig = filepath.Join(home, ".kube", "config")
	}

	cmd.Flags().StringVarP(&opts.namespace, "namespace", "n", "", "Filter to a specific namespace (default: all namespaces)")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "table", "Output format: table, mermaid, mermaid-full, html, json")
	cmd.Flags().StringVar(&opts.labelKey, "label-key", "app", "Pod label key used for workload grouping")
	cmd.Flags().StringVar(&opts.kubeconfig, "kubeconfig", defaultKubeconfig, "Path to kubeconfig file")
	cmd.Flags().BoolVar(&opts.showAll, "all", false, "Show all groups, not just those referenced by a policy")
	cmd.Flags().StringVar(&opts.fromDir, "from-dir", "", "Load resources from YAML files in this directory (offline mode, no cluster required)")
	cmd.Flags().StringVar(&opts.focus, "focus", "", "Focus selector: ns=<ns>, <key>=<value>, or <namespace>/<key>=<value>")

	return cmd
}

func runAnalyze(cmd *cobra.Command, opts analyzeOptions) error {
	ctx := cmd.Context()

	fetchOpts := analyzer.Options{
		Namespace: opts.namespace,
		LabelKey:  opts.labelKey,
		ShowAll:   opts.showAll,
	}

	var fr *analyzer.FetchResult
	var err error

	if opts.fromDir != "" {
		// Offline mode: load from YAML files
		fmt.Fprintf(os.Stderr, "Loading resources from directory: %s\n", opts.fromDir)
		fr, err = analyzer.LoadFromDir(opts.fromDir)
		if err != nil {
			return fmt.Errorf("loading from directory: %w", err)
		}
	} else {
		// Live mode: connect to cluster
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		if opts.kubeconfig != "" {
			loadingRules.ExplicitPath = opts.kubeconfig
		}
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		restConfig, err := kubeConfig.ClientConfig()
		if err != nil {
			return fmt.Errorf("loading kubeconfig: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Fetching resources from cluster...\n")
		fr, err = analyzer.Fetch(ctx, restConfig, fetchOpts)
		if err != nil {
			return fmt.Errorf("fetching resources: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Found %d pods, %d namespaces, %d NetworkPolicies, %d ANPs, %d BANPs\n",
		len(fr.Pods), len(fr.Namespaces), len(fr.NetworkPolicies), len(fr.ANPs), len(fr.BANPs))

	// Build matrix
	m := analyzer.BuildMatrix(fr, fetchOpts)

	if len(m.Groups) == 0 {
		fmt.Fprintln(os.Stderr, "No workload groups found. Try --all to show all pods, or add Pod/Namespace YAML for offline mode.")
		return nil
	}

	if m.Synthesized {
		fmt.Fprintf(os.Stderr, "Synthesized %d zones from policies (no pods loaded)\n", len(m.Groups))
	}

	fmt.Fprintf(os.Stderr, "Evaluating %d workload groups (%d pairs)...\n",
		len(m.Groups), len(m.Groups)*(len(m.Groups)-1))

	// Apply --focus filter (mermaid and html only; table stays full).
	if opts.focus != "" {
		switch opts.output {
		case "mermaid", "mermaid-full", "html":
			filtered, err := visualizer.ApplyFocus(m, opts.focus)
			if err != nil {
				return fmt.Errorf("focus: %w", err)
			}
			if len(filtered.Groups) == 0 {
				fmt.Fprintf(os.Stderr, "focus: %s — no matching nodes found\n", opts.focus)
				os.Exit(1)
			}
			allowEdges := visualizer.CountAllowEdges(filtered)
			fmt.Fprintf(os.Stderr, "focus: %s — %d nodes, %d edges shown\n",
				opts.focus, len(filtered.Groups), allowEdges)
			m = filtered
		default:
			fmt.Fprintf(os.Stderr, "Note: --focus is only applied to -o mermaid, -o mermaid-full, and -o html (ignored for %s)\n", opts.output)
		}
	}

	// Render output
	switch opts.output {
	case "table", "":
		visualizer.RenderTable(m, os.Stdout)
	case "mermaid":
		visualizer.RenderMermaid(m, os.Stdout)
	case "mermaid-full":
		visualizer.RenderMermaidFull(m, os.Stdout)
	case "html":
		visualizer.RenderHTML(m, os.Stdout)
	case "json":
		return renderJSON(m)
	default:
		return fmt.Errorf("unknown output format %q (valid: table, mermaid, mermaid-full, html, json)", opts.output)
	}

	return nil
}

type jsonOutput struct {
	Groups []jsonGroup `json:"groups"`
	Pairs  []jsonPair  `json:"pairs"`
}

type jsonGroup struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
}

type jsonPort struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
	Verdict  string `json:"verdict"`
	Layer    string `json:"layer,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type jsonPair struct {
	Src     string     `json:"src"`
	Dst     string     `json:"dst"`
	Verdict string     `json:"verdict"`
	Layer   string     `json:"layer,omitempty"`
	Reason  string     `json:"reason,omitempty"`
	Ports   []jsonPort `json:"ports,omitempty"`
}

func renderJSON(m *analyzer.Matrix) error {
	out := jsonOutput{}
	for _, g := range m.Groups {
		out.Groups = append(out.Groups, jsonGroup{
			Namespace: g.Namespace,
			Name:      g.Name,
			Labels:    g.Labels,
		})
	}
	for _, src := range m.Groups {
		dstResults, ok := m.Results[src.Key()]
		if !ok {
			continue
		}
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				continue
			}
			pr, ok := dstResults[dst.Key()]
			if !ok {
				continue
			}
			jp := jsonPair{
				Src:     src.Key(),
				Dst:     dst.Key(),
				Verdict: pr.Overall.String(),
			}
			for _, p := range pr.Ports {
				jp.Ports = append(jp.Ports, jsonPort{
					Port:     p.Port,
					Protocol: p.Protocol,
					Verdict:  p.Verdict.String(),
					Layer:    p.Layer,
					Reason:   p.Reason,
				})
			}
			// Backward-compatible summary: first Allow port, else first port.
			for _, p := range pr.Ports {
				if p.Verdict == analyzer.VerdictAllow {
					jp.Layer = p.Layer
					jp.Reason = p.Reason
					break
				}
			}
			if jp.Layer == "" && len(pr.Ports) > 0 {
				jp.Layer = pr.Ports[0].Layer
				jp.Reason = pr.Ports[0].Reason
			}
			out.Pairs = append(out.Pairs, jp)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
