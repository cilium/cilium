// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	cnifake "github.com/cilium/cilium/daemon/cmd/cni/fake"
	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/nodediscovery"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// netConfManager serves a fixed CNI configuration file.
type netConfManager struct {
	cnifake.FakeCNIConfigManager
	conf *cnitypes.NetConf
}

func (m *netConfManager) GetCustomNetConf() *cnitypes.NetConf { return m.conf }

// TestApplyInstanceFactsNotOverridable asserts that the fields of ENISpec
// which describe the instance rather than a configuration choice keep their
// IMDS values, even when the CNI configuration file sets all of them.
//
// NetConf embeds the whole ENISpec (plugins/cilium-cni/types/types.go), so
// every field of it is CNI-configurable for free, and which ones are actually
// honored is expressed as the order in which applyENISpec() runs
// overrideFromNetConf and applyInstanceFacts. This test turns that ordering
// into a checked invariant.
func TestApplyInstanceFactsNotOverridable(t *testing.T) {
	info := awsMetadata.MetaDataInfo{
		InstanceID:       "i-instance",
		InstanceType:     "m5.large",
		AvailabilityZone: "us-east-1a",
		VPCID:            "vpc-imds",
		SubnetID:         "subnet-imds",
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	in := nodediscovery.ENIMutateInputs{
		Logger: logger,
		CNIConfigManager: &netConfManager{conf: &cnitypes.NetConf{
			ENI: awsTypes.ENISpec{
				VpcID:            "vpc-cni",
				InstanceType:     "c5.xlarge",
				AvailabilityZone: "eu-west-1b",
				NodeSubnetID:     "subnet-cni",
			},
		}},
	}

	node := &ciliumv2.CiliumNode{}
	applyENISpec(in, info, node)

	require.Equal(t, info.InstanceID, node.Spec.InstanceID)
	require.Equal(t, info.VPCID, node.Spec.ENI.VpcID)
	require.Equal(t, info.InstanceType, node.Spec.ENI.InstanceType)
	require.Equal(t, info.AvailabilityZone, node.Spec.ENI.AvailabilityZone)
	require.Equal(t, info.SubnetID, node.Spec.ENI.NodeSubnetID)

	for _, key := range []string{"vpc-id", "instance-type", "availability-zone", "node-subnet-id"} {
		require.Contains(t, logs.String(), "configKey="+key)
	}
}

// TestSeedPoolRequest asserts that applyENISpec seeds the default pool demand
// after the pre-allocate value has been resolved from the agent configuration
// and the CNI configuration file. The seeding logic itself is tested in
// pkg/nodediscovery.
func TestSeedPoolRequest(t *testing.T) {
	defaultPoolDemand := func(ipv4, ipv6 int) []ipamTypes.IPAMPoolRequest {
		return []ipamTypes.IPAMPoolRequest{{
			Pool:   defaults.IPAMDefaultIPPool,
			Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: ipv4, IPv6Addrs: ipv6},
		}}
	}

	tests := []struct {
		name        string
		ipv4, ipv6  bool
		preAllocate int
		netConfPre  int
		want        []ipamTypes.IPAMPoolRequest
	}{
		{
			name: "IPv6-only requests no IPv4",
			ipv6: true,
			want: defaultPoolDemand(0, defaults.IPAMPreAllocation),
		},
		{
			name:        "uses the configured pre-allocate",
			ipv6:        true,
			preAllocate: 4,
			want:        defaultPoolDemand(0, 4),
		},
		{
			name:        "uses the pre-allocate of the CNI configuration file",
			ipv6:        true,
			preAllocate: 4,
			netConfPre:  2,
			want:        defaultPoolDemand(0, 2),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &cnitypes.NetConf{}
			conf.IPAM.PreAllocate = tt.netConfPre
			in := nodediscovery.ENIMutateInputs{
				Logger:           slog.New(slog.DiscardHandler),
				IPAMPreAllocate:  tt.preAllocate,
				IPv4Enabled:      tt.ipv4,
				IPv6Enabled:      tt.ipv6,
				CNIConfigManager: &netConfManager{conf: conf},
			}

			node := &ciliumv2.CiliumNode{}
			applyENISpec(in, awsMetadata.MetaDataInfo{InstanceID: "i-instance"}, node)

			require.Equal(t, tt.want, node.Spec.IPAM.Pools.Requested)
		})
	}
}
