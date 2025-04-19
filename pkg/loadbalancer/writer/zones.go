// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
)

// registerNodeZoneWatcher registers a background job that watches the [node.LocalNodeStore]
// for changes to the node's topology zone. When it changes it updates the zone in [Writer]
// and refreshes all frontends to re-select backends.
func registerNodeZoneWatcher(jg job.Group, p zoneWatcherParams) {
	if p.Config.EnableExperimentalLB {
		jg.Add(job.OneShot("zone-watcher", zoneWatcher{p}.run))
	}
}

type zoneWatcherParams struct {
	cell.In

	Config         loadbalancer.Config
	Writer         *Writer
	LocalNodeStore *node.LocalNodeStore
}

type zoneWatcher struct {
	zoneWatcherParams
}

func (zw zoneWatcher) run(ctx context.Context, health cell.Health) error {
	var zone string
	for n := range stream.ToChannel(ctx, zw.LocalNodeStore) {
		newZone := n.Labels[corev1.LabelTopologyZone]
		if newZone == zone {
			continue
		}
		zone = newZone
		zw.Writer.updateZone(zone)
	}
	return nil
}
