// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import "github.com/cilium/cilium/pkg/option"

func netPolicySystemIsEnabled(cfg *option.DaemonConfig) bool {
	conditions := []bool{
		cfg.EnablePolicy != option.NeverEnforce,
		cfg.EnableK8sNetworkPolicy,
		cfg.EnableCiliumNetworkPolicy,
		cfg.EnableCiliumClusterwideNetworkPolicy,
		!cfg.DisableCiliumEndpointCRD,
		cfg.IdentityAllocationMode != option.IdentityAllocationModeCRD,
	}

	for _, condition := range conditions {
		if condition {
			return true
		}
	}

	return false
}
