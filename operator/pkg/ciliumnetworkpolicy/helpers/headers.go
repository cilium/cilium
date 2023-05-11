package helpers

import (
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func GetReferencedHeaderMatchSecrets(pol *types.SlimCNP) []*api.Secret {
	var referencedSecrets []*api.Secret

	specs := pol.Specs
	if pol.Spec != nil {
		specs = append(specs, pol.Spec)
	}

	for _, spec := range specs {
		for _, rule := range spec.Egress {
			referencedSecrets = append(referencedSecrets, getHeaderMatchSecretsFromPortRule(rule.ToPorts)...)
		}

		for _, rule := range spec.Ingress {
			referencedSecrets = append(referencedSecrets, getHeaderMatchSecretsFromPortRule(rule.ToPorts)...)
		}
	}

	return referencedSecrets
}

func getHeaderMatchSecretsFromPortRule(ports api.PortRules) []*api.Secret {
	var referencedSecrets []*api.Secret

	for _, port := range ports {
		if port.Rules == nil {
			continue
		}

		for _, httpRule := range port.Rules.HTTP {
			for _, hm := range httpRule.HeaderMatches {
				if hm.Secret != nil {
					referencedSecrets = append(referencedSecrets, hm.Secret)
				}
			}
		}
	}

	return referencedSecrets
}
