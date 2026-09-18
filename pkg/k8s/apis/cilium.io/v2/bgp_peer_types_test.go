// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
)

func TestCiliumBGPNeighborBFDSetDefaults(t *testing.T) {
	peerConfig := &CiliumBGPPeerConfigSpec{
		BFD: &CiliumBGPNeighborBFD{Enabled: true},
	}

	peerConfig.SetDefaults()

	require.Equal(t, uint32(DefaultBGPBFDTransmitIntervalMilliseconds), peerConfig.BFD.TransmitIntervalMilliseconds)
	require.Equal(t, uint32(DefaultBGPBFDReceiveIntervalMilliseconds), peerConfig.BFD.ReceiveIntervalMilliseconds)
	require.Equal(t, ptr.To[int32](DefaultBGPBFDDetectionMultiplier), peerConfig.BFD.DetectionMultiplier)
}

func TestCiliumBGPNeighborBFDSetDefaultsPreservesValues(t *testing.T) {
	peerConfig := &CiliumBGPPeerConfigSpec{
		BFD: &CiliumBGPNeighborBFD{
			Enabled:                      true,
			TransmitIntervalMilliseconds: 300,
			ReceiveIntervalMilliseconds:  400,
			DetectionMultiplier:          ptr.To[int32](5),
		},
	}

	peerConfig.SetDefaults()

	require.Equal(t, uint32(300), peerConfig.BFD.TransmitIntervalMilliseconds)
	require.Equal(t, uint32(400), peerConfig.BFD.ReceiveIntervalMilliseconds)
	require.Equal(t, int32(5), *peerConfig.BFD.DetectionMultiplier)
}

func TestCiliumBGPPeerConfigSpecSetDefaultsDoesNotEnableBFD(t *testing.T) {
	peerConfig := &CiliumBGPPeerConfigSpec{}

	peerConfig.SetDefaults()

	require.Nil(t, peerConfig.BFD)
}
