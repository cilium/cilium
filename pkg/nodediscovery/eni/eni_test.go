// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	cnifake "github.com/cilium/cilium/daemon/cmd/cni/fake"
	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
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
