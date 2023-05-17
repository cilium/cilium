// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/datapath/fake"
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
		fakeNodeAddressing := fake.NewNodeAddressing()
		linuxNodeHandler := NewNodeHandler(dpConfig, fakeNodeAddressing, nil)
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
