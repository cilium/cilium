// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func FuzzNodeHandler(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		nodev1 := nodeTypes.Node{}
		ff.GenerateStruct(&nodev1)
		if nodev1.Name == "" || len(nodev1.IPAddresses) == 0 {
			t.Skip()
		}
		dpConfig := DatapathConfiguration{HostDevice: "veth0"}
		fakeNodeAddressing := fakeTypes.NewNodeAddressing()
		linuxNodeHandler := NewNodeHandler(dpConfig, fakeNodeAddressing, nil, &fakeTypes.MTU{}, new(mockEnqueuer))
		if linuxNodeHandler == nil {
			panic("Should not be nil")
		}
		err := linuxNodeHandler.NodeAdd(nodev1)
		if err != nil {
			t.Skip()
		}
		linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev1, true)
		linuxNodeHandler.NodeDelete(nodev1)
		linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev1, true)
	})
}

type mockEnqueuer struct {
	nh *linuxNodeHandler
}

func (q *mockEnqueuer) Enqueue(n *nodeTypes.Node, refresh bool) {
	if q.nh != nil {
		if err := q.nh.insertNeighbor(context.Background(), n, refresh); err != nil {
			log.Errorf("MockQ NodeNeighborRefresh failed: %s", err)
		}
	}
}
