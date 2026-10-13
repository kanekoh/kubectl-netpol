package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kanekoh/kubectl-netpol/pkg/analyzer"
)

type verifyOptions struct {
	namespace  string
	labelKey   string
	kubeconfig string
	showAll    bool
	fromDir    string
	strict     bool
	warningsOnly bool
}

func newVerifyCmd() *cobra.Command {
	opts := verifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Advisory checks for shadowed Allows and layer overrides",
		Long: `Evaluates ANP → NetworkPolicy → BANP per zone pair and reports:

  Warning  shadowed-allow     — higher-layer Deny hides a lower-layer Allow
  Info     np-overrides-banp  — NP Allow wins over BANP Deny (model-correct)
  Info     anp-skips-banp-deny — ANP Allow means BANP Deny is never consulted

These are review aids ("confirm intentional?"), not YAML schema errors.
Exit 0 when only Info, or when Warnings exist unless --strict.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, opts)
		},
	}

	defaultKubeconfig := ""
	if home, err := os.UserHomeDir(); err == nil {
		defaultKubeconfig = filepath.Join(home, ".kube", "config")
	}

	cmd.Flags().StringVarP(&opts.namespace, "namespace", "n", "", "Filter to a specific namespace (default: all)")
	cmd.Flags().StringVar(&opts.labelKey, "label-key", "app", "Pod label key used for workload grouping")
	cmd.Flags().StringVar(&opts.kubeconfig, "kubeconfig", defaultKubeconfig, "Path to kubeconfig file")
	cmd.Flags().BoolVar(&opts.showAll, "all", false, "Include groups not referenced by policies")
	cmd.Flags().StringVar(&opts.fromDir, "from-dir", "", "Load resources from YAML directory (offline)")
	cmd.Flags().BoolVar(&opts.strict, "strict", false, "Exit 1 when any Warning finding exists")
	cmd.Flags().BoolVar(&opts.warningsOnly, "warnings-only", false, "Print only Warning findings (hide Info)")

	return cmd
}

func runVerify(cmd *cobra.Command, opts verifyOptions) error {
	ctx := cmd.Context()
	fetchOpts := analyzer.Options{
		Namespace: opts.namespace,
		LabelKey:  opts.labelKey,
		ShowAll:   opts.showAll,
	}

	var fr *analyzer.FetchResult
	var err error

	if opts.fromDir != "" {
		fmt.Fprintf(os.Stderr, "Loading resources from directory: %s\n", opts.fromDir)
		fr, err = analyzer.LoadFromDir(opts.fromDir)
		if err != nil {
			return fmt.Errorf("loading from directory: %w", err)
		}
	} else {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		if opts.kubeconfig != "" {
			loadingRules.ExplicitPath = opts.kubeconfig
		}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
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

	findings := analyzer.Verify(fr, fetchOpts)
	if opts.warningsOnly {
		var filtered []analyzer.Finding
		for _, f := range findings {
			if f.Severity == analyzer.SeverityWarning {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	warnN, infoN := 0, 0
	for _, f := range findings {
		switch f.Severity {
		case analyzer.SeverityWarning:
			warnN++
		case analyzer.SeverityInfo:
			infoN++
		}
	}

	if len(findings) == 0 {
		fmt.Println("No advisory findings.")
		return nil
	}

	fmt.Printf("VERIFY FINDINGS (%d warning, %d info)\n", warnN, infoN)
	fmt.Println("====================================")
	fmt.Println("Tone: please confirm these are intentional. Not schema/lint failures.")
	fmt.Println()

	for i, f := range findings {
		fmt.Printf("%d. [%s] %s\n", i+1, f.Severity, f.Code)
		fmt.Printf("   %s → %s\n", f.Src, f.Dst)
		fmt.Printf("   %s\n", f.Message)
		if f.Detail != "" {
			fmt.Printf("   detail: %s\n", f.Detail)
		}
		fmt.Println()
	}

	if opts.strict && warnN > 0 {
		return fmt.Errorf("%d warning finding(s) with --strict", warnN)
	}
	return nil
}
