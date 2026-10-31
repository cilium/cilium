// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"log/slog"
	"slices"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// getTLSSecretsFromPortRule returns all Secrets referenced by the TLS contexts of a port rule,
// including trust bundles of kind Secret.
func getTLSSecretsFromPortRule(port api.PortRule) []types.NamespacedName {
	var secrets []types.NamespacedName

	for _, tls := range []*api.TLSContext{port.TerminatingTLS, port.OriginatingTLS} {
		if tls == nil {
			continue
		}
		if tls.Secret != nil {
			secrets = append(secrets, types.NamespacedName{
				Namespace: tls.Secret.Namespace,
				Name:      tls.Secret.Name,
			})
		}
		if tb := tls.TrustBundle; tb != nil && (tb.Kind == "" || tb.Kind == api.TrustBundleKindSecret) {
			secrets = append(secrets, types.NamespacedName{
				Namespace: tb.Namespace,
				Name:      tb.Name,
			})
		}
	}

	return secrets
}

// GetReferencedTLSSecretsFromPortRules finds all TLS Secrets referenced by a set of port rules.
func GetReferencedTLSSecretsFromPortRules(ports api.PortRules, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	for _, port := range ports {
		for _, s := range getTLSSecretsFromPortRule(port) {
			reqs = append(reqs, reconcile.Request{NamespacedName: s})
			logger.Debug("Enqueued secret reconciliation for network policy", logfields.Name, s)
		}
	}

	return reqs
}

// GetReferencedSecretsFromHeaderRules finds all Header Secrets referenced by a set of port rules.
func GetReferencedSecretsFromHeaderRules(ports api.PortRules, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	for _, port := range ports {
		if port.Rules == nil {
			continue
		}

		for _, httpRule := range port.Rules.HTTP {
			for _, hm := range httpRule.HeaderMatches {
				if hm.Secret != nil {
					s := types.NamespacedName{
						Namespace: hm.Secret.Namespace,
						Name:      hm.Secret.Name,
					}
					reqs = append(reqs, reconcile.Request{NamespacedName: s})
				}
			}
		}
	}

	return reqs
}

// IsSecretReferencedByPortRule checks if a given Secret is referenced in any rule
// in the supplied set of PortRules, whether that is in a TLS or header-value sense.
func IsSecretReferencedByPortRule(ports api.PortRules, logger *slog.Logger, secretName types.NamespacedName) bool {
	for _, port := range ports {

		// First, check for TLS Secrets
		if slices.Contains(getTLSSecretsFromPortRule(port), secretName) {
			return true
		}

		// Otherwise, check for HTTP header secrets
		if port.Rules == nil {
			continue
		}

		for _, httpRule := range port.Rules.HTTP {
			for _, hm := range httpRule.HeaderMatches {
				if hm.Secret != nil {
					if secretName.Namespace == hm.Secret.Namespace &&
						secretName.Name == hm.Secret.Name {
						return true
					}
				}
			}
		}
	}
	return false
}
