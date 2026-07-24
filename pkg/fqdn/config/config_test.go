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

	// Expected Pod Selector for default config:
	expectedLabelsDefault := map[string]slim_metav1.MatchLabelsValue{
		"k8s-app":                  "kube-dns",
		k8sConst.PodNamespaceLabel: "kube-system",
	}
	expectedSelectorDefault := types.ToSelector(api.NewESFromK8sLabelSelector(
		labels.LabelSourceK8sKeyPrefix,
		&slim_metav1.LabelSelector{
			MatchLabels: expectedLabelsDefault,
		},
	))

	// Expected Pod Selector for combined config:
	expectedLabelsCombined := map[string]slim_metav1.MatchLabelsValue{
		"app":                      "coredns",
		k8sConst.PodNamespaceLabel: "custom-dns",
	}
	expectedSelectorCombined := types.ToSelector(api.NewESFromK8sLabelSelector(
		labels.LabelSourceK8sKeyPrefix,
		&slim_metav1.LabelSelector{
			MatchLabels: expectedLabelsCombined,
		},
	))

	tests := []struct {
		name              string
		config            FQDNPolicyDNSServerConfig
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
			name: "Pod labels and namespace configuration",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerNamespace: "kube-system",
				FQDNPolicyDNSServerPodLabel:  map[string]string{"k8s-app": "kube-dns"},
				FQDNPolicyDNSServerPort:      53,
			},
			dnsRules:          dnsRules,
			expectedSelectors: types.Selectors{expectedSelectorDefault},
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
			name: "Namespace and Pod labels and IPs combined",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerIPs:       []string{"1.1.1.1"},
				FQDNPolicyDNSServerNamespace: "custom-dns",
				FQDNPolicyDNSServerPodLabel:  map[string]string{"app": "coredns"},
				FQDNPolicyDNSServerPort:      53,
			},
			dnsRules: dnsRules,
			expectedSelectors: types.Selectors{
				expectedSelectorCombined,
				types.ToSelector(api.CIDR("1.1.1.1")),
			},
			expectedPortRules: makeExpectedPortRules("53", dnsRules),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsSelectors, portRules := tt.config.DNSSelectors(tt.dnsRules)
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
