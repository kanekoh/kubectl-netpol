package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	anpv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

var (
	anpGVR = schema.GroupVersionResource{
		Group:    "policy.networking.k8s.io",
		Version:  "v1alpha1",
		Resource: "adminnetworkpolicies",
	}
	banpGVR = schema.GroupVersionResource{
		Group:    "policy.networking.k8s.io",
		Version:  "v1alpha1",
		Resource: "baselineadminnetworkpolicies",
	}
)

// FetchResult holds all Kubernetes resources needed for analysis.
type FetchResult struct {
	Namespaces      []corev1.Namespace
	Pods            []corev1.Pod
	NetworkPolicies []netv1.NetworkPolicy
	ANPs            []anpv1alpha1.AdminNetworkPolicy
	BANPs           []anpv1alpha1.BaselineAdminNetworkPolicy
}

// Fetch retrieves all relevant resources from the cluster.
func Fetch(ctx context.Context, config *rest.Config, opts Options) (*FetchResult, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}

	result := &FetchResult{}

	// Namespaces (always cluster-scoped)
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	result.Namespaces = nsList.Items

	// Pods (optionally filtered by namespace)
	podList, err := clientset.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}
	result.Pods = podList.Items

	// NetworkPolicies (optionally filtered by namespace)
	npList, err := clientset.NetworkingV1().NetworkPolicies(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing networkpolicies: %w", err)
	}
	result.NetworkPolicies = npList.Items

	// ANPs are cluster-scoped — may not be installed
	anps, err := fetchANPs(ctx, dynamicClient)
	if err != nil {
		log.Printf("Warning: could not fetch AdminNetworkPolicies (CRD may not be installed): %v", err)
	} else {
		result.ANPs = anps
	}

	// BANPs are cluster-scoped — may not be installed
	banps, err := fetchBANPs(ctx, dynamicClient)
	if err != nil {
		log.Printf("Warning: could not fetch BaselineAdminNetworkPolicies (CRD may not be installed): %v", err)
	} else {
		result.BANPs = banps
	}

	return result, nil
}

func fetchANPs(ctx context.Context, dc dynamic.Interface) ([]anpv1alpha1.AdminNetworkPolicy, error) {
	list, err := dc.Resource(anpGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var result []anpv1alpha1.AdminNetworkPolicy
	for _, item := range list.Items {
		var anp anpv1alpha1.AdminNetworkPolicy
		raw, err := json.Marshal(item.Object)
		if err != nil {
			log.Printf("Warning: could not marshal ANP %s: %v", item.GetName(), err)
			continue
		}
		if err := json.Unmarshal(raw, &anp); err != nil {
			log.Printf("Warning: could not unmarshal ANP %s: %v", item.GetName(), err)
			continue
		}
		result = append(result, anp)
	}
	return result, nil
}

func fetchBANPs(ctx context.Context, dc dynamic.Interface) ([]anpv1alpha1.BaselineAdminNetworkPolicy, error) {
	list, err := dc.Resource(banpGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var result []anpv1alpha1.BaselineAdminNetworkPolicy
	for _, item := range list.Items {
		var banp anpv1alpha1.BaselineAdminNetworkPolicy
		raw, err := json.Marshal(item.Object)
		if err != nil {
			log.Printf("Warning: could not marshal BANP %s: %v", item.GetName(), err)
			continue
		}
		if err := json.Unmarshal(raw, &banp); err != nil {
			log.Printf("Warning: could not unmarshal BANP %s: %v", item.GetName(), err)
			continue
		}
		result = append(result, banp)
	}
	return result, nil
}
