// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium-cli/k8s"
)

var (
	ContextName string
	Namespace   string

	K8sClient *k8s.Client

	// Version is the Version string of the cilium-cli itself
	Version string
)

// SetVersion sets the Version string for the cilium command
func SetVersion(v string) {
	Version = v
}
