// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func TestNodeTableRow(t *testing.T) {
	n := &Node{Node: types.Node{
		Name:    "node-1",
		Cluster: "cluster-1",
		Source:  source.Kubernetes,
		IPAddresses: []types.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("10.1.0.1")},
		},
	}}
	n.Statuses = n.Statuses.Set("wireguard", reconciler.StatusDone())

	require.Equal(t,
		[]string{"Name", "Source", "Status", "Addresses"},
		n.TableHeader(),
	)
	require.Equal(t,
		[]string{
			"cluster-1/node-1",
			string(source.Kubernetes),
			"Done",
			"CiliumInternalIP:10.1.0.1, InternalIP:10.0.0.1",
		},
		n.TableRow(),
	)
}

func TestNodeTableStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses map[string]reconciler.Status
		want     string
	}{
		{name: "empty", want: "Pending"},
		{
			name: "done",
			statuses: map[string]reconciler.Status{
				"linux-node": reconciler.StatusDone(),
				"wireguard":  reconciler.StatusDone(),
			},
			want: "Done",
		},
		{
			name: "mixed",
			statuses: map[string]reconciler.Status{
				"wireguard":    reconciler.StatusPending(),
				"node-ipcache": reconciler.StatusError(errors.New("failed")),
				"linux-node":   reconciler.StatusRefreshing(),
				"done":         reconciler.StatusDone(),
			},
			want: "Error: node-ipcache; Pending: wireguard; Refreshing: linux-node",
		},
		{
			name: "sorted",
			statuses: map[string]reconciler.Status{
				"z": reconciler.StatusPending(),
				"a": reconciler.StatusPending(),
			},
			want: "Pending: a,z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{}
			for name, status := range tt.statuses {
				n.Statuses = n.Statuses.Set(name, status)
			}
			require.Equal(t, tt.want, n.tableStatus())
		})
	}
}
