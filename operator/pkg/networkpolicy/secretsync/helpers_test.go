// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/policy/api"
)

func trustBundlePortRules() api.PortRules {
	return api.PortRules{{
		TerminatingTLS: &api.TLSContext{
			Secret:      &api.Secret{Namespace: "ns", Name: "terminating"},
			TrustBundle: &api.TrustBundle{Namespace: "ns", Name: "client-ca"},
		},
		OriginatingTLS: &api.TLSContext{
			Secret:      &api.Secret{Namespace: "ns", Name: "client-identity"},
			TrustBundle: &api.TrustBundle{Kind: api.TrustBundleKindSecret, Namespace: "ns", Name: "upstream-ca"},
		},
	}}
}

func TestGetReferencedTLSSecretsFromPortRulesTrustBundle(t *testing.T) {
	reqs := GetReferencedTLSSecretsFromPortRules(trustBundlePortRules(), hivetest.Logger(t))

	var names []types.NamespacedName
	for _, r := range reqs {
		names = append(names, r.NamespacedName)
	}
	require.ElementsMatch(t, []types.NamespacedName{
		{Namespace: "ns", Name: "terminating"},
		{Namespace: "ns", Name: "client-ca"},
		{Namespace: "ns", Name: "client-identity"},
		{Namespace: "ns", Name: "upstream-ca"},
	}, names)
}

func TestIsSecretReferencedByPortRuleTrustBundle(t *testing.T) {
	logger := hivetest.Logger(t)
	ports := trustBundlePortRules()

	for _, name := range []string{"terminating", "client-ca", "client-identity", "upstream-ca"} {
		require.True(t, IsSecretReferencedByPortRule(ports, logger, types.NamespacedName{Namespace: "ns", Name: name}), name)
	}
	require.False(t, IsSecretReferencedByPortRule(ports, logger, types.NamespacedName{Namespace: "ns", Name: "other"}))
	require.False(t, IsSecretReferencedByPortRule(ports, logger, types.NamespacedName{Namespace: "other", Name: "upstream-ca"}))
}
