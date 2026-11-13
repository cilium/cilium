// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func checkMarshalUnmarshal(t *testing.T, r *Rule) {
	jsonData, err := json.Marshal(r)
	require.NoError(t, err)

	newRule := Rule{}
	err = json.Unmarshal(jsonData, &newRule)
	require.NoError(t, err)

	require.Equal(t, newRule.EndpointSelector.LabelSelector == nil, r.EndpointSelector.LabelSelector == nil)
	require.Equal(t, newRule.NodeSelector.LabelSelector == nil, r.NodeSelector.LabelSelector == nil)
}

// This test ensures that the NodeSelector and EndpointSelector fields are kept
// empty when the rule is marshalled/unmarshalled.
func TestJSONMarshalling(t *testing.T) {
	validEndpointRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(t, &validEndpointRule)

	validNodeRule := Rule{
		NodeSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(t, &validNodeRule)
}

func TestRuleTrustBundleValidation(t *testing.T) {
	tlsRule := func(ingress bool, secretNamespace string, trustBundle *Secret) *Rule {
		tls := &TLSContext{Secret: &Secret{Namespace: secretNamespace, Name: "identity"}, TrustBundle: trustBundle}
		port := PortRule{Ports: []PortProtocol{{Port: "443", Protocol: ProtoTCP}}}
		if ingress {
			port.TerminatingTLS = tls
			return &Rule{Ingress: []IngressRule{{ToPorts: PortRules{port}}}}
		}
		port.OriginatingTLS = tls
		return &Rule{Egress: []EgressRule{{ToPorts: PortRules{port}}}}
	}
	bundle := &Secret{Namespace: "shared", Name: "bundle"}

	for _, tc := range []struct {
		name                 string
		secretNamespace      string
		trustBundle          *Secret
		wantNamespaceErr     string
		wantNoTrustBundleErr bool
	}{
		{name: "same namespace", secretNamespace: "ns", trustBundle: bundle, wantNoTrustBundleErr: true},
		{name: "implicit namespace", trustBundle: bundle, wantNoTrustBundleErr: true},
		{
			name: "other namespace", secretNamespace: "other", trustBundle: bundle, wantNoTrustBundleErr: true,
			wantNamespaceErr: "TLS secret other/identity must be in the policy namespace ns when trustBundle is set",
		},
		{name: "other namespace without trust bundle", secretNamespace: "other"},
		{
			name: "trust bundle without namespace", secretNamespace: "ns", trustBundle: &Secret{Name: "bundle"}, wantNoTrustBundleErr: true,
			wantNamespaceErr: "trustBundle bundle must have a namespace",
		},
	} {
		for _, ingress := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ingress=%t", tc.name, ingress), func(t *testing.T) {
				rule := tlsRule(ingress, tc.secretNamespace, tc.trustBundle)

				err := rule.ValidateTrustBundleNamespace("ns")
				if tc.wantNamespaceErr != "" {
					require.EqualError(t, err, tc.wantNamespaceErr)
				} else {
					require.NoError(t, err)
				}

				err = rule.ValidateNoTrustBundle()
				if tc.wantNoTrustBundleErr {
					require.EqualError(t, err, "trustBundle is not supported in cluster-scoped policies")
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}
