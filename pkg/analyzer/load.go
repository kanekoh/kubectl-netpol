package analyzer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	"sigs.k8s.io/yaml"
)

type resourceMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// LoadFromDir reads all YAML files in dir and returns a FetchResult without
// connecting to a cluster. Files named "expected.yaml" are skipped.
func LoadFromDir(dir string) (*FetchResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	result := &FetchResult{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		if name == "expected.yaml" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}

		if err := parseYAMLDocs(data, result); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
	}

	return result, nil
}

// parseYAMLDocs splits a multi-document YAML byte slice on "---" and routes
// each document into the appropriate slice of result.
func parseYAMLDocs(data []byte, result *FetchResult) error {
	// Normalize Windows line endings and split on document separator
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	docs := bytes.Split(data, []byte("\n---"))

	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		// Strip leading "---" if present (first document)
		doc = bytes.TrimPrefix(doc, []byte("---"))
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		var meta resourceMeta
		if err := yaml.Unmarshal(doc, &meta); err != nil || meta.Kind == "" {
			continue
		}

		switch meta.Kind {
		case "Namespace":
			var obj corev1.Namespace
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				return fmt.Errorf("Namespace: %w", err)
			}
			result.Namespaces = append(result.Namespaces, obj)

		case "Pod":
			var obj corev1.Pod
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				return fmt.Errorf("Pod: %w", err)
			}
			result.Pods = append(result.Pods, obj)

		case "NetworkPolicy":
			var obj netv1.NetworkPolicy
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				return fmt.Errorf("NetworkPolicy: %w", err)
			}
			result.NetworkPolicies = append(result.NetworkPolicies, obj)

		case "AdminNetworkPolicy":
			var obj anpv1alpha1.AdminNetworkPolicy
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				return fmt.Errorf("AdminNetworkPolicy: %w", err)
			}
			result.ANPs = append(result.ANPs, obj)

		case "BaselineAdminNetworkPolicy":
			var obj anpv1alpha1.BaselineAdminNetworkPolicy
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				return fmt.Errorf("BaselineAdminNetworkPolicy: %w", err)
			}
			result.BANPs = append(result.BANPs, obj)
		}
	}
	return nil
}
