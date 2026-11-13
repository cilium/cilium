// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"iter"
	"log/slog"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// tlsSecretsFromPortRule returns an iterator over all Secrets referenced by the TLS
// contexts of a port rule, including trust bundles.
func tlsSecretsFromPortRule(port api.PortRule) iter.Seq[types.NamespacedName] {
	return func(yield func(types.NamespacedName) bool) {
		for _, tls := range []*api.TLSContext{port.TerminatingTLS, port.OriginatingTLS} {
			if tls == nil {
				continue
			}
			if tls.Secret != nil && !yield(types.NamespacedName(*tls.Secret)) {
				return
			}
			if tls.TrustBundle != nil && !yield(types.NamespacedName(*tls.TrustBundle)) {
				return
			}
		}
	}
}

// GetReferencedTLSSecretsFromPortRules finds all TLS Secrets referenced by a set of port rules.
func GetReferencedTLSSecretsFromPortRules(ports api.PortRules, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	for _, port := range ports {
		for s := range tlsSecretsFromPortRule(port) {
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
		for s := range tlsSecretsFromPortRule(port) {
			if s == secretName {
				return true
			}
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
