// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestDNSServerRules(t *testing.T) {
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

	// mockResolver translates each service port p to backend port p+1000.
	mockResolver := ServiceResolver(func(ns, name string, servicePorts []uint16) ServiceBackends {
		switch {
		case ns == "kube-system" && name == "kube-dns":
			var ports []api.PortProtocol
			for _, p := range servicePorts {
				ports = append(ports, makeExpectedPorts(strconv.Itoa(int(p)+1000))...)
			}
			return ServiceBackends{PodSelector: map[string]string{"k8s-app": "kube-dns"}, Ports: ports}
		case ns == "kube-system" && name == "no-backends":
			return ServiceBackends{PodSelector: map[string]string{"k8s-app": "kube-dns"}}
		}
		return ServiceBackends{}
	})

	// Expected Pod Selector restricted to a cluster:
	expectedSelectorCluster := types.NewLabelSelector(api.NewESFromK8sLabelSelector(
		labels.LabelSourceK8sKeyPrefix,
		&slim_metav1.LabelSelector{
			MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"k8s-app":                   "kube-dns",
				k8sConst.PodNamespaceLabel:  "kube-system",
				k8sConst.PolicyLabelCluster: "cluster1",
			},
		},
	))

	ipSelectors := types.Selectors{
		types.ToSelector(api.CIDR("1.1.1.1")),
		types.ToSelector(api.CIDR("8.8.8.8")),
	}

	tests := []struct {
		name        string
		config      FQDNPolicyDNSServerConfig
		clusterName string
		expected    []DNSServerRule
	}{
		{
			name:     "Default configuration (disabled)",
			config:   DefaultFQDNPolicyDNSServerConfig,
			expected: nil,
		},
		{
			name: "IP configuration with multiple ports",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerIPs:   []string{"1.1.1.1", "8.8.8.8"},
				FQDNPolicyDNSServerPorts: []string{"53", "5353"},
			},
			expected: []DNSServerRule{{
				L3: ipSelectors,
				L4: makeExpectedPortRules(dnsRules, append(makeExpectedPorts("53"), makeExpectedPorts("5353")...)...),
			}},
		},
		{
			name: "Service ports translated to backend ports",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerService: "kube-system/kube-dns",
				FQDNPolicyDNSServerPorts:   []string{"53"},
			},
			expected: []DNSServerRule{{
				L3: types.Selectors{expectedSelectorDefault},
				L4: makeExpectedPortRules(dnsRules, makeExpectedPorts("1053")...),
			}},
		},
		{
			name: "Service pods restricted to the local cluster",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerService: "kube-system/kube-dns",
				FQDNPolicyDNSServerIPs:     []string{"1.1.1.1", "8.8.8.8"},
				FQDNPolicyDNSServerPorts:   []string{"53"},
			},
			clusterName: "cluster1",
			expected: []DNSServerRule{
				{
					L3: types.Selectors{expectedSelectorCluster},
					L4: makeExpectedPortRules(dnsRules, makeExpectedPorts("1053")...),
				},
				{
					// IPs are not restricted to a cluster.
					L3: ipSelectors,
					L4: makeExpectedPortRules(dnsRules, makeExpectedPorts("53")...),
				},
			},
		},
		{
			name: "Service without backend ports",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerService: "kube-system/no-backends",
				FQDNPolicyDNSServerPorts:   []string{"53"},
			},
			expected: nil,
		},
		{
			name: "Service and IPs",
			config: FQDNPolicyDNSServerConfig{
				FQDNPolicyDNSServerService: "kube-system/kube-dns",
				FQDNPolicyDNSServerIPs:     []string{"1.1.1.1", "8.8.8.8"},
				FQDNPolicyDNSServerPorts:   []string{"53"},
			},
			expected: []DNSServerRule{
				{
					L3: types.Selectors{expectedSelectorDefault},
					L4: makeExpectedPortRules(dnsRules, makeExpectedPorts("1053")...),
				},
				{
					L3: ipSelectors,
					L4: makeExpectedPortRules(dnsRules, makeExpectedPorts("53")...),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.DNSServerRules(mockResolver, dnsRules, tt.clusterName))
		})
	}
}

func makeExpectedPorts(port string) []api.PortProtocol {
	return []api.PortProtocol{
		{Port: port, Protocol: api.ProtoUDP},
		{Port: port, Protocol: api.ProtoTCP},
	}
}

func makeExpectedPortRules(dnsRules api.PortRulesDNS, ports ...api.PortProtocol) api.PortRules {
	return api.PortRules{{
		Ports: ports,
		Rules: &api.L7Rules{DNS: dnsRules},
	}}
}

func TestParseServiceRef(t *testing.T) {
	tests := []struct {
		svcRef    string
		namespace string
		name      string
		wantErr   bool
	}{
		{svcRef: "kube-system/kube-dns", namespace: "kube-system", name: "kube-dns"},
		{svcRef: "kube-dns", wantErr: true},
		{svcRef: "", wantErr: true},
		{svcRef: "/kube-dns", wantErr: true},
		{svcRef: "kube-system/", wantErr: true},
		{svcRef: "a/b/c", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.svcRef, func(t *testing.T) {
			ns, name, err := ParseServiceRef(tt.svcRef)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.namespace, ns)
			assert.Equal(t, tt.name, name)
		})
	}
}

func TestValidate(t *testing.T) {
	valid := func(svc string, ports ...string) FQDNPolicyDNSServerConfig {
		return FQDNPolicyDNSServerConfig{FQDNPolicyDNSServerService: svc, FQDNPolicyDNSServerPorts: ports}
	}
	require.NoError(t, DefaultFQDNPolicyDNSServerConfig.Validate())
	require.NoError(t, valid("kube-system/kube-dns", "53").Validate())
	require.NoError(t, valid("kube-system/kube-dns", "53", "5353").Validate())
	require.Error(t, valid("kube-dns", "53").Validate())
	require.Error(t, valid("kube-system/kube-dns").Validate())
	require.Error(t, valid("kube-system/kube-dns", "dns").Validate())

	withIPs := func(ips ...string) FQDNPolicyDNSServerConfig {
		return FQDNPolicyDNSServerConfig{FQDNPolicyDNSServerIPs: ips, FQDNPolicyDNSServerPorts: []string{"53"}}
	}
	require.NoError(t, withIPs("10.0.0.10", "fd00::10").Validate())
	require.Error(t, withIPs("10.0.0.10", "not-an-ip").Validate())
	require.Error(t, withIPs("10.0.0.0/24").Validate())
}

func TestPorts(t *testing.T) {
	tests := []struct {
		ports   []string
		want    []uint16
		wantErr bool
	}{
		{ports: []string{"53"}, want: []uint16{53}},
		{ports: []string{"53", " 5353"}, want: []uint16{53, 5353}},
		{ports: nil, wantErr: true},
		{ports: []string{"0"}, wantErr: true},
		{ports: []string{"65536"}, wantErr: true},
		{ports: []string{"53-60"}, wantErr: true},
		{ports: []string{"dns"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.ports, ","), func(t *testing.T) {
			got, err := FQDNPolicyDNSServerConfig{FQDNPolicyDNSServerPorts: tt.ports}.Ports()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
