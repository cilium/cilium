// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/alibabacloud/ipam/limits"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestENIIPAMCapacityAccounting(t *testing.T) {
	assert := assert.New(t)
	limits.Update(map[string]ipamTypes.Limits{
		"ecs.g6.large": {
			IPv4:     10,
			Adapters: 3,
		},
	})
	m := ipamTypes.NewInstanceMap()
	resource := &types.ENI{
		NetworkInterfaceID: "eni-1",
		Type:               types.ENITypeSecondary,
		IPv6Prefixes:       []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1:2:3::/80"))},
		PrivateIPSets: []types.PrivateIPSet{
			{
				Primary: true, // one primary IP
			},
		},
	}
	m.Update("vm1", resource.DeepCopy())
	m.Update("vm1", &types.ENI{
		NetworkInterfaceID: "eni-primary",
		Type:               types.ENITypePrimary,
		IPv6Prefixes:       []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1:2:1::/80"))},
	})

	n := &Node{
		logger:     hivetest.Logger(t),
		instanceID: "vm1",
		manager: &InstancesManager{
			instances: m,
		},
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				AlibabaCloud: types.Spec{
					InstanceType: "ecs.g6.large",
				},
			},
		},
	}
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), n.logger)
	assert.NoError(err)
	// 3 ENIs, 10 IPs per ENI, 1 primary IP and one ENI is primary.
	assert.Equal(19, stats.NodeCapacity)
	assert.Equal(1, stats.NodeIPv6Prefixes)
	assert.Equal([]netip.Prefix{resource.IPv6Prefixes[0].Prefix}, n.GetAttachedCIDRs())
}
