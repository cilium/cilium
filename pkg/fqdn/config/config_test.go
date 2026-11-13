// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestGetFQDNPolicyDNSSelectors(t *testing.T) {
	dnsRules := api.PortRulesDNS{{MatchName: "example.com"}}

	// Expected Pod Selector for service resolution:
	expectedLabelsDefault := map[string]slim_metav1.MatchLabelsValue{
		"k8s-app":                  "kube-dns",
		k8sConst.PodNamespaceLabel: "kube-system",
	}
	expectedSelectorDefault := types.NewLabelSelector(api.NewESFromK8sLabelSelector(
		labels.LabelSourceK8sKeyPrefix,
		&slim_metav1.LabelSelector{
			MatchLabels: expectedLabelsDefault,
		},
	))

	mockResolver := ServiceResolver(func(ns, name string) (map[string]string, []string) {
		if ns == "kube-system" && name == "kube-dns" {
			return map[string]string{"k8s-app": "kube-dns"}, nil
		}
		return nil, nil
	})

	tests := []struct {
		name              string
		config            FQDNPolicyDNSServerConfig
		resolver          ServiceResolver
		dnsRules          api.PortRulesDNS
		expectedSelectors types.Selectors
		expectedPortRules api.PortRules
	}{
		{
			name:              "Default configuration (disabled)",
			config:            DefaultFQDNPolicyDNSServerConfig,
			dnsRules:          dnsRules,
			expectedSelectors: nil,
			expectedPortRules: makeExpectedPortRules("53", dnsRules),
		},
		{
			name: "IP configuration only",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerIPs:  []string{"1.1.1.1", "8.8.8.8"},
				FQDNPolicyDNSServerPort: 5353,
			},
			dnsRules: dnsRules,
			expectedSelectors: types.Selectors{
				types.ToSelector(api.CIDR("1.1.1.1")),
				types.ToSelector(api.CIDR("8.8.8.8")),
			},
			expectedPortRules: makeExpectedPortRules("5353", dnsRules),
		},
		{
			name: "Service configuration resolved via ServiceResolver",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerService: "kube-system/kube-dns",
				FQDNPolicyDNSServerPort:    53,
			},
			resolver: mockResolver,
			dnsRules: dnsRules,
			expectedSelectors: types.Selectors{
				expectedSelectorDefault,
			},
			expectedPortRules: makeExpectedPortRules("53", dnsRules),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsSelectors, portRules := tt.config.DNSSelectors(tt.resolver, tt.dnsRules)
			assert.Equal(t, tt.expectedSelectors, dnsSelectors)
			assert.Equal(t, tt.expectedPortRules, portRules)
		})
	}
}

func makeExpectedPortRules(port string, dnsRules api.PortRulesDNS) api.PortRules {
	return api.PortRules{{
		Ports: []api.PortProtocol{
			{Port: port, Protocol: api.ProtoUDP},
			{Port: port, Protocol: api.ProtoTCP},
		},
		Rules: &api.L7Rules{DNS: dnsRules},
	}}
}
