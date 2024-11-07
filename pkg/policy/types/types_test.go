// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestKeyMask(t *testing.T) {
	key := IngressKey()
	require.Equal(t, trafficdirection.Ingress, key.TrafficDirection())
	require.Equal(t, uint8(0), key.PortPrefixLen())
	require.Equal(t, uint16(0), key.DestPort)
	require.Equal(t, uint16(0xffff), key.EndPort())

	key = EgressKey().WithIdentity(42).WithTCPPort(80)
	require.Equal(t, trafficdirection.Egress, key.TrafficDirection())
	require.Equal(t, identity.NumericIdentity(42), key.Identity)
	require.Equal(t, u8proto.TCP, key.Nexthdr)
	require.Equal(t, uint8(16), key.PortPrefixLen())
	require.Equal(t, uint16(80), key.DestPort)
	require.Equal(t, uint16(80), key.EndPort())

	// for convenience in testing, 0 prefix len gets translated to 16 when port is non-zero
	key = EgressKey().WithIdentity(42).WithUDPPortPrefix(80, 0)
	require.Equal(t, trafficdirection.Egress, key.TrafficDirection())
	require.Equal(t, identity.NumericIdentity(42), key.Identity)
	require.Equal(t, u8proto.UDP, key.Nexthdr)
	require.Equal(t, uint8(16), key.PortPrefixLen())
	require.Equal(t, uint16(80), key.DestPort)
	require.Equal(t, uint16(80), key.EndPort())

	key = EgressKey().WithIdentity(42).WithSCTPPortPrefix(80, 14)
	require.Equal(t, trafficdirection.Egress, key.TrafficDirection())
	require.Equal(t, identity.NumericIdentity(42), key.Identity)
	require.Equal(t, u8proto.SCTP, key.Nexthdr)
	require.Equal(t, uint8(14), key.PortPrefixLen())
	require.Equal(t, uint16(80), key.DestPort)
	require.Equal(t, uint16(83), key.EndPort())
}
