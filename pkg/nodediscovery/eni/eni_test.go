// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
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
// honored is expressed as the order in which apply() runs
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
	apply(in, info, node)

	require.Equal(t, info.InstanceID, node.Spec.InstanceID)
	require.Equal(t, info.VPCID, node.Spec.ENI.VpcID)
	require.Equal(t, info.InstanceType, node.Spec.ENI.InstanceType)
	require.Equal(t, info.AvailabilityZone, node.Spec.ENI.AvailabilityZone)
	require.Equal(t, info.SubnetID, node.Spec.ENI.NodeSubnetID)

	for _, key := range []string{"vpc-id", "instance-type", "availability-zone", "node-subnet-id"} {
		require.Contains(t, logs.String(), "configKey="+key)
	}
}

// TestSeedPoolRequest asserts that a CiliumNode is created with a demand for
// the families the agent uses, so that the operator does not pre-allocate
// IPv4 addresses to an IPv6-only node before the multi-pool manager writes the
// actual demand, and that an existing demand is left alone.
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
		existing    []ipamTypes.IPAMPoolRequest
		want        []ipamTypes.IPAMPoolRequest
	}{
		{
			name: "IPv6-only requests no IPv4",
			ipv6: true,
			want: defaultPoolDemand(0, defaults.IPAMPreAllocation),
		},
		{
			name: "IPv4-only requests no IPv6",
			ipv4: true,
			want: defaultPoolDemand(defaults.IPAMPreAllocation, 0),
		},
		{
			name: "dual-stack requests both",
			ipv4: true, ipv6: true,
			want: defaultPoolDemand(defaults.IPAMPreAllocation, defaults.IPAMPreAllocation),
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
		{
			name:     "keeps the demand of the multi-pool manager",
			ipv6:     true,
			existing: defaultPoolDemand(0, 42),
			want:     defaultPoolDemand(0, 42),
		},
		{
			name: "adds the default pool next to other pools",
			ipv6: true,
			existing: []ipamTypes.IPAMPoolRequest{{
				Pool:   "other",
				Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 1},
			}},
			want: append([]ipamTypes.IPAMPoolRequest{{
				Pool:   "other",
				Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 1},
			}}, defaultPoolDemand(0, defaults.IPAMPreAllocation)...),
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
			node.Spec.IPAM.Pools.Requested = tt.existing
			apply(in, awsMetadata.MetaDataInfo{InstanceID: "i-instance"}, node)

			require.Equal(t, tt.want, node.Spec.IPAM.Pools.Requested)
		})
	}
}

// stubMetadata counts the fetches of a metadataClient and can be told to fail
// them.
type stubMetadata struct {
	info     awsMetadata.MetaDataInfo
	err      error
	fetches  atomic.Int32
	newCalls atomic.Int32
}

func (s *stubMetadata) GetInstanceMetadata(context.Context) (awsMetadata.MetaDataInfo, error) {
	s.fetches.Add(1)
	return s.info, s.err
}

func (s *stubMetadata) facts() *instanceFacts {
	return &instanceFacts{newFn: func(context.Context) (metadataClient, error) {
		s.newCalls.Add(1)
		return s, nil
	}}
}

func TestInstanceFactsFetchesOnce(t *testing.T) {
	stub := &stubMetadata{info: awsMetadata.MetaDataInfo{InstanceID: "i-instance"}}
	facts := stub.facts()

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			info, err := facts.get(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, "i-instance", info.InstanceID)
		})
	}
	wg.Wait()

	require.Equal(t, int32(1), stub.fetches.Load())
	require.Equal(t, int32(1), stub.newCalls.Load())
}

// TestInstanceFactsRetriesFailures asserts that a failed fetch is not cached,
// so that the CiliumNode update retried by pkg/nodediscovery can succeed, and
// that the retry reuses the IMDS client.
func TestInstanceFactsRetriesFailures(t *testing.T) {
	tests := map[string]struct {
		info awsMetadata.MetaDataInfo
		err  error
	}{
		"fetch error":       {err: errors.New("i/o timeout")},
		"empty instance ID": {info: awsMetadata.MetaDataInfo{}},
	}

	for name, failure := range tests {
		t.Run(name, func(t *testing.T) {
			stub := &stubMetadata{info: failure.info, err: failure.err}
			facts := stub.facts()

			_, err := facts.get(context.Background())
			require.Error(t, err)

			stub.info, stub.err = awsMetadata.MetaDataInfo{InstanceID: "i-instance"}, nil
			info, err := facts.get(context.Background())
			require.NoError(t, err)
			require.Equal(t, "i-instance", info.InstanceID)

			require.Equal(t, int32(2), stub.fetches.Load())
			require.Equal(t, int32(1), stub.newCalls.Load())
		})
	}
}
