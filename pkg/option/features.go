// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import "cmp"

// NetworkPolicyEnabled returns true if the network policy enforcement
// system is enabled for K8s, Cilium and Cilium Clusterwide network policies.
func NetworkPolicyEnabled(cfg *DaemonConfig) bool {
	return cmp.Or(
		cfg.EnablePolicy != NeverEnforce,
		cfg.EnableK8sNetworkPolicy,
		cfg.EnableCiliumNetworkPolicy,
		cfg.EnableCiliumClusterwideNetworkPolicy,
		!cfg.DisableCiliumEndpointCRD,
		cfg.IdentityAllocationMode != IdentityAllocationModeCRD,
	)
}
