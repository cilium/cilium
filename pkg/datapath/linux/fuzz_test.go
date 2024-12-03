// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/logging/logfields"
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
		log := hivetest.Logger(f)
		linuxNodeHandler := newNodeHandler(log, dpConfig, nil, new(mockEnqueuer))
		if linuxNodeHandler == nil {
			panic("Should not be nil")
		}
		err := linuxNodeHandler.NodeAdd(nodev1)
		if err != nil {
			t.Skip()
		}
		linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev1)
		linuxNodeHandler.NodeDelete(nodev1)
		linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev1)
	})
}

type mockEnqueuer struct {
	nh *linuxNodeHandler
}

func (q *mockEnqueuer) Enqueue(n *nodeTypes.Node) {
	if q.nh != nil {
		if err := q.nh.insertNeighbor(context.Background(), n); err != nil {
			q.nh.log.Error("MockQ NodeNeighborRefresh failed", logfields.Error, err)
		}
	}
}
