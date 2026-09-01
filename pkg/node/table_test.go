// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestNodeAddressIndexClusterIdentity(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)

	n := &Node{
		Node: nodeTypes.Node{
			Name:      "node-1",
			ClusterID: 99,
			IPAddresses: []nodeTypes.Address{
				{
					Type: addressing.NodeCiliumInternalIP,
					IP:   net.ParseIP("10.0.0.1"),
				},
				{
					Type: addressing.NodeInternalIP,
					IP:   net.ParseIP("192.0.2.1"),
				},
			},
			IPv4HealthIP:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
			IPv4IngressIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")),
		},
		addressClusterID: 42,
	}
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	tests := []struct {
		name      string
		address   string
		clusterID uint32
		found     bool
	}{
		{"cilium address in cluster", "10.0.0.1", 42, true},
		{"cilium address locally scoped", "10.0.0.1", 0, false},
		{"cilium address from serialized cluster ID", "10.0.0.1", 99, false},
		{"underlay address globally scoped", "192.0.2.1", 0, true},
		{"underlay address in cluster", "192.0.2.1", 42, false},
		{"health address in cluster", "10.0.0.2", 42, true},
		{"ingress address in cluster", "10.0.0.3", 42, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address := cmtypes.AddrClusterFrom(
				netip.MustParseAddr(tt.address),
				tt.clusterID,
			)
			_, _, found := nodes.Get(db.ReadTxn(), NodeByAddress(address))
			require.Equal(t, tt.found, found)
		})
	}
}
