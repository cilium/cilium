// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"log/slog"
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
)

func registerNodeLabelController(params nodeLabelControllerParams) {
	c := &nodeLabelController{nodeLabelControllerParams: params}
	params.JobGroup.Add(job.OneShot("node-labels", c.run))
}

type nodeLabelControllerParams struct {
	cell.In

	DB       *statedb.DB
	JobGroup job.Group
	Log      *slog.Logger

	ExpConfig loadbalancer.Config
	Nodes     statedb.Table[*node.LocalNode]
	CECs      statedb.RWTable[*CEC]
}

// nodeLabelController updates the [nodeLabels] and [CEC.SelectsLocalNode] field when
// the node labels change.
// The [cecController] will recompute when it has been changed.
type nodeLabelController struct {
	nodeLabelControllerParams
}

func (c *nodeLabelController) run(ctx context.Context, _ cell.Health) error {
	var oldLabels map[string]string
	for {
		wtxn := c.DB.WriteTxn(c.CECs)
		localNode, _, watch, found := c.Nodes.GetWatch(wtxn, node.LocalNodeQuery)
		updated := false
		if found {
			newLabels := localNode.Labels
			if oldLabels == nil || !maps.Equal(newLabels, oldLabels) {
				c.Log.Debug("Labels changed",
					logfields.Old, oldLabels,
					logfields.New, newLabels,
				)
				updated = true

				// Since the labels changed, recompute 'SelectsLocalNode'
				// for all CECs.

				// Store the new labels so the reflector can compute 'SelectsLocalNode'
				// on the fly. The reflector may already update 'SelectsLocalNode' to the
				// correct value, so the recomputation that follows may be duplicate for
				// some CECs, but that's fine. This is updated with the CEC table lock held
				// and read by CEC reflector with the table lock which ensures consistency.
				// With the Table[Node] changes in https://github.com/cilium/cilium/pull/32144
				// this can be removed and we can instead read the labels directly from the node
				// table.
				labelSet := labels.Set(newLabels)

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
			}
			oldLabels = newLabels
			if updated {
				wtxn.Commit()
			} else {
				wtxn.Abort()
			}

			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}

	}
}
