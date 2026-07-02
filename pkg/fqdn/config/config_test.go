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
	// Save the global config and restore it after the test
	origConfig := GlobalFQDNPolicyDNSLookupConfig
	defer func() {
		GlobalFQDNPolicyDNSLookupConfig = origConfig
	}()

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
		config            FQDNPolicyDNSLookupConfig
		dnsRules          api.PortRulesDNS
		expectedSelectors types.Selectors
		expectedPortRules api.PortRules
	}{
		{
			name:              "Default configuration",
			config:            DefaultFQDNPolicyDNSLookupConfig,
			dnsRules:          dnsRules,
			expectedSelectors: types.Selectors{expectedSelectorDefault},
			expectedPortRules: makeExpectedPortRules("53", dnsRules),
		},
		{
			name: "IP configuration only",
			config: FQDNPolicyDNSLookupConfig{
				FQDNPolicyDNSLookupIPs:  []string{"1.1.1.1", "8.8.8.8"},
				FQDNPolicyDNSLookupPort: 5353,
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
			config: FQDNPolicyDNSLookupConfig{
				FQDNPolicyDNSLookupIPs:       []string{"1.1.1.1"},
				FQDNPolicyDNSLookupNamespace: "custom-dns",
				FQDNPolicyDNSLookupPodLabels: map[string]string{"app": "coredns"},
				FQDNPolicyDNSLookupPort:      53,
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
			GlobalFQDNPolicyDNSLookupConfig = tt.config
			dnsSelectors, portRules := GetFQDNPolicyDNSSelectors(tt.dnsRules)
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
