// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_validateENIConfig(t *testing.T) {
	type args struct {
		node *ciliumv2.CiliumNode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    string
	}{
		{
			name: "Consistent ENI config",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								iputil.AddrFrom(netip.MustParseAddr("10.1.1.226")): ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: awsTypes.ENIStatus{
							ENIs: map[string]awsTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									IP: iputil.AddrFrom(netip.MustParseAddr("10.1.1.225")),
									Subnet: awsTypes.AwsSubnet{
										CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24")),
									},
									Addresses: addrs(
										"10.1.1.226",
										"10.1.1.229",
									),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ENI not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								iputil.AddrFrom(netip.MustParseAddr("10.1.1.226")): ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: awsTypes.ENIStatus{
							ENIs: map[string]awsTypes.ENI{
								"eni-2": {
									ID: "eni-2",
									IP: iputil.AddrFrom(netip.MustParseAddr("10.1.1.225")),
									Subnet: awsTypes.AwsSubnet{
										CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24")),
									},
									Addresses: addrs(
										"10.1.1.226",
										"10.1.1.229",
									),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "ENI eni-1 not found in status",
		},
		{
			name: "ENI IP not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								iputil.AddrFrom(netip.MustParseAddr("10.1.1.227")): ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: awsTypes.ENIStatus{
							ENIs: map[string]awsTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									IP: iputil.AddrFrom(netip.MustParseAddr("10.1.1.225")),
									Subnet: awsTypes.AwsSubnet{
										CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24")),
									},
									Addresses: addrs(
										"10.1.1.226",
										"10.1.1.229",
									),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "ENI eni-1 does not have address 10.1.1.227",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateENIConfig(tt.args.node)
			require.Equal(t, tt.wantErr, got != nil, "error: %v", got)
			if tt.wantErr {
				require.Equal(t, tt.want, got.Error())
			}
		})
	}
}
