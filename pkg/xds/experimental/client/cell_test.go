// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package xdsclient

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/node"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	core_v1 "k8s.io/api/core/v1"
)

func TestCell_SuccessfullyRunClient(t *testing.T) {
	var testXDSClient Client
	hLog := hivetest.Logger(t)
	nodeId := "xds-test-node-id"
	h := hive.New(
		cell.Provide(NewDefaultNodeProvider),
		cell.Provide(NewInsecureGRPCOptionsProvider),
		node.LocalNodeStoreCell,
		Cell,
		cell.Invoke(func(localNodeStore *node.LocalNodeStore) {
			localNodeStore.Update(func(n *node.LocalNode) {
				hLog.Info("Update localNodeStore")
				n.Name = "node1"
				if n.Labels == nil {
					n.Labels = make(map[string]string)
				}
				n.Labels[core_v1.LabelTopologyZone] = "zone"
			})

		}),
		cell.Invoke(func(c Client) { testXDSClient = c }),
	)
	hive.AddConfigOverride(
		h,
		func(cfg *Config) {
			cfg.ServerAddr = "dns:///fake-server.com:443"
			cfg.NodeID = nodeId
		})

	if err := h.Populate(hLog); err != nil {
		t.Fatalf("Failed to populate: %s", err)
	}

	if err := h.Start(hLog, context.TODO()); err != nil {
		t.Fatalf("Failed to start: %s", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(hLog, context.TODO()); err != nil {
			t.Fatalf("Failed to stop: %s", err)
		}
	})

	if testXDSClient == nil {
		t.Fatalf("XDS client is nil")
	}
	sotwClient := testXDSClient.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])
	if sotwClient == nil {
		t.Errorf("Client is not state of the world xDS client")
	}
	checkFn := func() error {
		if sotwClient.node == nil {
			return fmt.Errorf("Node for xDS client was not set")
		}
		return nil
	}
	waitForCondition(context.Background(), t, checkFn)
	if sotwClient.node.Id != nodeId {
		t.Fatalf("NodeId mismatch: got %v, want %v", sotwClient.node.Id, nodeId)
	}
}

func TestCell_NoServerProvided(t *testing.T) {
	var testXDSClient Client
	hLog := hivetest.Logger(t)
	h := hive.New(
		cell.Provide(NewDefaultNodeProvider),
		cell.Provide(NewInsecureGRPCOptionsProvider),
		node.LocalNodeStoreCell,
		Cell,
		cell.Invoke(func(localNodeStore *node.LocalNodeStore) {
			localNodeStore.Update(func(n *node.LocalNode) {
				hLog.Info("Update localNodeStore")
				n.Name = "node1"
				if n.Labels == nil {
					n.Labels = make(map[string]string)
				}
				n.Labels[core_v1.LabelTopologyZone] = "zone"
			})

		}),
		cell.Invoke(func(c Client) { testXDSClient = c }),
	)

	if err := h.Start(hLog, context.TODO()); err == nil {
		t.Fatal("hive start should failed due to server misconfiguration")
	}
	t.Cleanup(func() {
		if err := h.Stop(hLog, context.TODO()); err != nil {
			t.Fatalf("Failed to stop: %s", err)
		}
	})

	if testXDSClient != nil {
		t.Fatalf("XDS client should be nil")
	}
}
