// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/node"
)

type localNodeGetterParams struct {
	cell.In

	JobGroup       job.Group
	NodeLocalStore *node.LocalNodeStore
}

// NewLocalNodeGetter returns a LocalNodeGetter kept up to date with the
// LocalNodeStore by a job.OneShot.
func NewLocalNodeGetter(params localNodeGetterParams) types.LocalNodeGetter {
	watcher := &LocalNodeWatcher{}

	params.JobGroup.Add(job.OneShot(
		"hubble-local-node-watcher",
		func(ctx context.Context, _ cell.Health) error {
			return watcher.Run(ctx, params.NodeLocalStore)
		},
	))

	return watcher
}
