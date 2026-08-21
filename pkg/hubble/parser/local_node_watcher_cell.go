// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package parser

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/node"
)

// LocalNodeWatcherCell provides the LocalNodeWatcher. It manages the
// LocalNodeStore subscription via a job.OneShot and provides the watcher
// to the PayloadParser for populating the flow's node_labels field.
var LocalNodeWatcherCell = cell.Provide(newLocalNodeWatcher)

type localNodeWatcherParams struct {
	cell.In

	JobGroup       job.Group
	NodeLocalStore *node.LocalNodeStore
}

func newLocalNodeWatcher(params localNodeWatcherParams) *LocalNodeWatcher {
	watcher := &LocalNodeWatcher{}

	params.JobGroup.Add(job.OneShot(
		"hubble-local-node-watcher",
		func(ctx context.Context, _ cell.Health) error {
			return watcher.Run(ctx, params.NodeLocalStore)
		},
	))

	return watcher
}
