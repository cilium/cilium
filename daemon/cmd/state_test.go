// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

func TestNeedsEndpointRoutingOnHost(t *testing.T) {
	oldIPAM := option.Config.IPAM
	oldInstallUplinkRoutes := option.Config.InstallUplinkRoutesForDelegatedIPAM
	defer func() {
		option.Config.IPAM = oldIPAM
		option.Config.InstallUplinkRoutesForDelegatedIPAM = oldInstallUplinkRoutes
	}()

	tests := []struct {
		name                                string
		ipam                                string
		installUplinkRoutesForDelegatedIPAM bool
		want                                bool
	}{
		{
			name: "ENI IPAM",
			ipam: ipamOption.IPAMENI,
			want: true,
		},
		{
			name: "Azure IPAM",
			ipam: ipamOption.IPAMAzure,
			want: true,
		},
		{
			name: "AlibabaCloud IPAM",
			ipam: ipamOption.IPAMAlibabaCloud,
			want: true,
		},
		{
			name: "cluster pool CIDR IPAM",
			ipam: ipamOption.IPAMKubernetes,
			want: false,
		},
		{
			name: "CRD IPAM",
			ipam: ipamOption.IPAMCRD,
			want: false,
		},
		{
			name:                                "delegated plugin without uplink routes",
			ipam:                                ipamOption.IPAMDelegatedPlugin,
			installUplinkRoutesForDelegatedIPAM: false,
			want:                                false,
		},
		{
			name:                                "delegated plugin with uplink routes",
			ipam:                                ipamOption.IPAMDelegatedPlugin,
			installUplinkRoutesForDelegatedIPAM: true,
			want:                                true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.IPAM = tt.ipam
			option.Config.InstallUplinkRoutesForDelegatedIPAM = tt.installUplinkRoutesForDelegatedIPAM

			d := &Daemon{}
			require.Equal(t, tt.want, d.needsEndpointRoutingOnHost())
		})
	}
}
