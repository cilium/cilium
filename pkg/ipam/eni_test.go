// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
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
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Missing VPC Primary CIDR",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID: "vpc-1",
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "VPC Primary CIDR not set for ENI eni-1",
		},
		{
			name: "VPC CIDRs contain invalid value",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "VPC CIDR not set for ENI eni-1",
		},
		{
			name: "ENI not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-2": {
									ID: "eni-2",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
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
								"10.1.1.227": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
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

func TestBuildENIAllocationResult(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	node.Status.ENI.ENIs = map[string]eniTypes.ENI{
		"eni-1": {
			ID:  "eni-1",
			MAC: "aa:bb:cc:dd:ee:01",
			Addresses: []string{
				"10.1.1.10",
				"10.1.1.11",
			},
			Number: 1,
			Subnet: eniTypes.AwsSubnet{
				CIDR: "10.1.1.0/24",
			},
			VPC: eniTypes.AwsVPC{
				PrimaryCIDR: "10.1.0.0/16",
				CIDRs:       []string{"10.2.0.0/16"},
			},
		},
		"eni-2": {
			ID:  "eni-2",
			MAC: "aa:bb:cc:dd:ee:02",
			Addresses: []string{
				"10.3.1.20",
			},
			Number: 2,
			Subnet: eniTypes.AwsSubnet{
				CIDR: "10.3.1.0/24",
			},
			VPC: eniTypes.AwsVPC{
				PrimaryCIDR: "10.1.0.0/16",
				CIDRs:       []string{"10.2.0.0/16"},
			},
		},
	}

	conf := &option.DaemonConfig{}
	logger := hivetest.Logger(t)

	t.Run("secondary IP on eni-1", func(t *testing.T) {
		result, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.1.1.10"), node, conf, nil)
		require.NoError(t, err)
		require.Equal(t, "aa:bb:cc:dd:ee:01", result.PrimaryMAC)
		require.Equal(t, "1", result.InterfaceNumber)
		require.Equal(t, netip.MustParseAddr("10.1.1.1"), result.GatewayIP)
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.1.0.0/16"))
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.2.0.0/16"))
	})

	t.Run("secondary IP on eni-2", func(t *testing.T) {
		result, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.3.1.20"), node, conf, nil)
		require.NoError(t, err)
		require.Equal(t, "aa:bb:cc:dd:ee:02", result.PrimaryMAC)
		require.Equal(t, "2", result.InterfaceNumber)
		require.Equal(t, netip.MustParseAddr("10.3.1.1"), result.GatewayIP)
	})

	t.Run("unknown IP returns error", func(t *testing.T) {
		_, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.99.99.99"), node, conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find ENI for IP")
	})

	t.Run("native routing CIDR is appended", func(t *testing.T) {
		confWithNative := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: cidr.MustParseCIDR("10.0.0.0/8"),
		}
		result, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.1.1.10"), node, confWithNative, nil)
		require.NoError(t, err)
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.0.0.0/8"))
	})
}

func TestBuildENIAllocationResultPrefixDelegation(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	node.Status.ENI.ENIs = map[string]eniTypes.ENI{
		"eni-1": {
			ID:  "eni-1",
			MAC: "aa:bb:cc:dd:ee:01",
			Prefixes: []string{
				"10.1.1.0/28",
				"10.1.1.16/28",
			},
			Number: 1,
			Subnet: eniTypes.AwsSubnet{
				CIDR: "10.1.1.0/24",
			},
			VPC: eniTypes.AwsVPC{
				PrimaryCIDR: "10.1.0.0/16",
			},
		},
	}

	conf := &option.DaemonConfig{}
	logger := hivetest.Logger(t)

	t.Run("IP in first prefix", func(t *testing.T) {
		result, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.1.1.5"), node, conf, nil)
		require.NoError(t, err)
		require.Equal(t, "aa:bb:cc:dd:ee:01", result.PrimaryMAC)
		require.Equal(t, "1", result.InterfaceNumber)
	})

	t.Run("IP in second prefix", func(t *testing.T) {
		result, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.1.1.20"), node, conf, nil)
		require.NoError(t, err)
		require.Equal(t, "aa:bb:cc:dd:ee:01", result.PrimaryMAC)
	})

	t.Run("IP outside all prefixes", func(t *testing.T) {
		_, err := buildENIAllocationResult(logger, netip.MustParseAddr("10.1.1.32"), node, conf, nil)
		require.Error(t, err)
	})
}

func TestEniContainsIP(t *testing.T) {
	eni := eniTypes.ENI{
		IP:        "10.0.0.100",
		Addresses: []string{"10.0.0.1", "10.0.0.2"},
		Prefixes:  []string{"10.0.1.0/28"},
	}

	// Primary IP match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.100")))

	// Secondary address match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.1")))
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.2")))
	require.False(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.3")))

	// Prefix match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.1.0")))
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.1.15")))
	require.False(t, eniContainsIP(eni, netip.MustParseAddr("10.0.1.16")))

	// Empty ENI
	require.False(t, eniContainsIP(eniTypes.ENI{}, netip.MustParseAddr("10.0.0.1")))
}
