// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"iter"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/datapath/plugins/types"
)

const (
	pluginHookStatusTableName = "pluginhooks"
)

var (
	acIndex = statedb.Index[*types.CollectionHookStatus, string]{
		Name: "attachment-context",
		FromObject: func(c *types.CollectionHookStatus) index.KeySet {
			return index.NewKeySet(index.String(c.AttachmentContext.CollectionKey()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

func newHookStatusTable(db *statedb.DB) (*hookStatusTable, error) {
	hookStatuses, err := statedb.NewTable(
		db,
		pluginHookStatusTableName,
		acIndex,
	)
	if err != nil {
		return nil, err
	}

	return &hookStatusTable{
		db:           db,
		hookStatuses: hookStatuses,
	}, nil
}

type hookStatusTable struct {
	db           *statedb.DB
	hookStatuses statedb.RWTable[*types.CollectionHookStatus]
}

func (h *hookStatusTable) Upsert(collHookStatus *types.CollectionHookStatus) {
	wtxn := h.db.WriteTxn(h.hookStatuses)
	h.hookStatuses.Insert(wtxn, collHookStatus)
	wtxn.Commit()
}

func (h *hookStatusTable) Purge(ac *datapathplugins.AttachmentContext) {
	wtxn := h.db.WriteTxn(h.hookStatuses)
	h.hookStatuses.Delete(wtxn, types.NewCollectionHookStatus(ac))
	wtxn.Commit()
}

func (h *hookStatusTable) all() iter.Seq[*types.CollectionHookStatus] {
	return func(yield func(*types.CollectionHookStatus) bool) {
		for collHookStatus, _ := range h.hookStatuses.All(h.db.ReadTxn()) {
			if !yield(collHookStatus) {
				return
			}
		}
	}
}

func (h *hookStatusTable) toHookStatusWriter() types.HooksStatusWriter {
	return h
}
