// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// GetReferencedTLSSecretsFromPortRules finds all TLS Secrets referenced by a set of port rules.
func GetReferencedTLSSecretsFromPortRules(ports api.PortRules, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	for _, port := range ports {
		if port.TerminatingTLS != nil && port.TerminatingTLS.Secret != nil {
			s := types.NamespacedName{
				Namespace: port.TerminatingTLS.Secret.Namespace,
				Name:      port.TerminatingTLS.Secret.Name,
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: s})
			logger.Debug("Enqueued secret reconciliation for network policy", logfields.Name, s)
		}

		if port.OriginatingTLS != nil && port.OriginatingTLS.Secret != nil {
			s := types.NamespacedName{
				Namespace: port.OriginatingTLS.Secret.Namespace,
				Name:      port.OriginatingTLS.Secret.Name,
			}
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
		if port.TerminatingTLS != nil && port.TerminatingTLS.Secret != nil {
			if secretName.Namespace == port.TerminatingTLS.Secret.Namespace &&
				secretName.Name == port.TerminatingTLS.Secret.Name {
				return true
			}
		}
		if port.OriginatingTLS != nil && port.OriginatingTLS.Secret != nil {
			if secretName.Namespace == port.OriginatingTLS.Secret.Namespace &&
				secretName.Name == port.OriginatingTLS.Secret.Name {
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
