// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/mapreconciler"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var (
	L2ResponderPKIndex     = mapreconciler.PrimaryKeyIndex[l2respondermap.L2ResponderEntry, l2respondermap.L2ResponderKey, l2respondermap.L2ResponderStats]()
	L2ResponderOriginIndex = statedb.Index[l2respondermap.L2ResponderEntry, resource.Key]{
		Name: "origin",
		FromObject: func(e l2respondermap.L2ResponderEntry) index.KeySet {
			return index.StringerSlice(e.Origins)
		},
		FromKey: func(id resource.Key) []byte {
			return index.Stringer(id)
		},
	}
	L2ResponderTableCell = cell.Group(
		statedb.NewTableCell[l2respondermap.L2ResponderEntry]("l2responder-map", L2ResponderPKIndex, L2ResponderOriginIndex),
		cell.Provide(func() statedb.Index[l2respondermap.L2ResponderEntry, l2respondermap.L2ResponderKey] {
			return L2ResponderPKIndex
		}),
	)
)
