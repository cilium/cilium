// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func GetReferencedTLSContext(pol *types.SlimCNP) []*api.TLSContext {
	var referencedTLS []*api.TLSContext

	specs := pol.Specs
	if pol.Spec != nil {
		specs = append(specs, pol.Spec)
	}

	for _, spec := range specs {
		for _, rule := range spec.Egress {
			referencedTLS = append(referencedTLS, getReferencedTLSContextFromPortRule(rule.ToPorts)...)
		}

		for _, rule := range spec.Ingress {
			referencedTLS = append(referencedTLS, getReferencedTLSContextFromPortRule(rule.ToPorts)...)
		}
	}

	return referencedTLS
}

func getReferencedTLSContextFromPortRule(ports api.PortRules) []*api.TLSContext {
	var referencedTLS []*api.TLSContext

	for _, port := range ports {
		if port.OriginatingTLS != nil && port.OriginatingTLS.Secret != nil {
			referencedTLS = append(referencedTLS, port.OriginatingTLS)
		}

		if port.TerminatingTLS != nil && port.TerminatingTLS.Secret != nil {
			referencedTLS = append(referencedTLS, port.TerminatingTLS)
		}
	}

	return referencedTLS
}
