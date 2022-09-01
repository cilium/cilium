// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

// IsEnabled checks if Cilium is being used in tandem with Kubernetes.
func IsEnabled() bool {
	// If clients have been set, then consider k8s enabled regardless
	// of config.
	return k8sCLI.Interface != nil
}
