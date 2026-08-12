// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
