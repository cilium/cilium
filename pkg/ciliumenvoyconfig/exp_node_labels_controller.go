// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"log/slog"
	"maps"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
)

// nodeLabels stores the current node labels. Used in the k8s to CEC table
// reflector to compute [CEC.SelectsLocalNode] field at reflection time.
type nodeLabels struct {
	initialized chan struct{}
	ptr         atomic.Pointer[map[string]string]
}

func (nl *nodeLabels) Load() map[string]string {
	<-nl.initialized
	return *nl.ptr.Load()
}

func (nl *nodeLabels) store(labels map[string]string) {
	nl.ptr.Store(&labels)
}

func newNodeLabels(params nodeLabelControllerParams) *nodeLabels {
	nl := &nodeLabels{
		initialized: make(chan struct{}),
	}
	if !params.ExpConfig.EnableExperimentalLB {
		return nil
	}
	c := &nodeLabelController{nodeLabelControllerParams: params, nodeLabels: nl}
	params.JobGroup.Add(job.Observer("node-labels", c.process, params.LocalNodeStore))

	return nl
}

type nodeLabelControllerParams struct {
	cell.In

	DB       *statedb.DB
	JobGroup job.Group
	Log      *slog.Logger

	ExpConfig      loadbalancer.Config
	LocalNodeStore *node.LocalNodeStore
	CECs           statedb.RWTable[*CEC]
}

// nodeLabelController updates the [nodeLabels] and [CEC.SelectsLocalNode] field when
// the node labels change.
// The [cecController] will recompute when it has been changed.
type nodeLabelController struct {
	nodeLabelControllerParams

	nodeLabels *nodeLabels
}

func (c *nodeLabelController) process(ctx context.Context, localNode node.LocalNode) error {
	newLabels := localNode.Labels
	oldLabels := c.nodeLabels.ptr.Load()

	if oldLabels == nil || !maps.Equal(newLabels, *oldLabels) {
		c.Log.Debug("Labels changed",
			logfields.Old, oldLabels,
			logfields.New, newLabels,
		)

		// Since the labels changed, recompute 'SelectsLocalNode'
		// for all CECs.
		wtxn := c.DB.WriteTxn(c.CECs)

		// Store the new labels so the reflector can compute 'SelectsLocalNode'
		// on the fly. The reflector may already update 'SelectsLocalNode' to the
		// correct value, so the recomputation that follows may be duplicate for
		// some CECs, but that's fine. This is updated with the CEC table lock held
		// and read by CEC reflector with the table lock which ensures consistency.
		// With the Table[Node] changes in https://github.com/cilium/cilium/pull/32144
		// this can be removed and we can instead read the labels directly from the node
		// table.
		labelSet := labels.Set(newLabels)
		c.nodeLabels.store(newLabels)

		for cec := range c.CECs.All(wtxn) {
			if cec.Selector != nil {
				selects := cec.Selector.Matches(labelSet)
				if selects != cec.SelectsLocalNode {
					cec = cec.Clone()
					cec.SelectsLocalNode = selects
					c.CECs.Insert(wtxn, cec)
				}
			}
		}
		wtxn.Commit()

		if oldLabels == nil {
			close(c.nodeLabels.initialized)
		}
	}
	return nil
}
