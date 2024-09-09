// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func newOps(logger logrus.FieldLogger, ipset *ipset, cfg config) *ops {
	return &ops{
		enabled: cfg.NodeIPSetNeeded,
		ipset:   ipset,
	}
}

type ops struct {
	enabled bool
	doPrune atomic.Bool
	ipset   *ipset
}

// UpdateBatch implements reconciler.BatchOperations.
func (ops *ops) UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*tables.IPSetEntry]) {
	if !ops.enabled {
		return
	}

	addrsByName := map[string][]netip.Addr{}
	for _, entry := range batch {
		addrsByName[entry.Object.Name] = append(addrsByName[entry.Object.Name], entry.Object.Addr)
	}
	err := ops.ipset.addBatch(ctx, addrsByName)
	if err != nil {
		// Fail the whole batch.
		for i := range batch {
			batch[i].Result = err
		}
	}
}

// DeleteBatch implements reconciler.BatchOperations.
func (ops *ops) DeleteBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*tables.IPSetEntry]) {
	if !ops.enabled {
		return
	}

	addrsByName := map[string][]netip.Addr{}
	for _, entry := range batch {
		addrsByName[entry.Object.Name] = append(addrsByName[entry.Object.Name], entry.Object.Addr)
	}
	err := ops.ipset.delBatch(ctx, addrsByName)
	if err != nil {
		// Fail the whole batch.
		for i := range batch {
			batch[i].Result = err
		}
	}
}

var _ reconciler.Operations[*tables.IPSetEntry] = &ops{}
var _ reconciler.BatchOperations[*tables.IPSetEntry] = &ops{}

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, entry *tables.IPSetEntry) error {
	panic("Unexpectedly Update() called for reconciliation")
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, entry *tables.IPSetEntry) error {
	panic("Unexpectedly Delete() called for reconciliation")
}

func (ops *ops) Prune(ctx context.Context, _ statedb.ReadTxn, objs iter.Seq2[*tables.IPSetEntry, statedb.Revision]) error {
	if !ops.enabled || !ops.doPrune.Load() {
		return nil
	}

	desiredV4Set, desiredV6Set := sets.Set[netip.Addr]{}, sets.Set[netip.Addr]{}

	for obj := range objs {
		if obj.Name == CiliumNodeIPSetV4 {
			desiredV4Set.Insert(obj.Addr)
		} else if obj.Name == CiliumNodeIPSetV6 {
			desiredV6Set.Insert(obj.Addr)
		}
	}

	return errors.Join(
		reconcile(ctx, ops.ipset, CiliumNodeIPSetV4, INetFamily, desiredV4Set),
		reconcile(ctx, ops.ipset, CiliumNodeIPSetV6, INet6Family, desiredV6Set),
	)
}

func reconcile(
	ctx context.Context,
	ipset *ipset,
	name string,
	family Family,
	desired sets.Set[netip.Addr],
) error {
	// create the IP set if it doesn't exist
	if err := ipset.create(ctx, name, string(family)); err != nil {
		return fmt.Errorf("unable to create ipset %s: %w", name, err)
	}

	curSet, err := ipset.list(ctx, name)
	if err != nil {
		return fmt.Errorf("unable to list ipset %s: %w", name, err)
	}

	toDel := curSet.Difference(desired)
	delBatch := map[string][]netip.Addr{name: toDel.UnsortedList()}
	if err := ipset.delBatch(ctx, delBatch); err != nil {
		return fmt.Errorf("unable to delete from ipset: %w", err)
	}

	toAdd := desired.Difference(curSet)
	addBatch := map[string][]netip.Addr{name: toAdd.UnsortedList()}
	if err := ipset.addBatch(ctx, addBatch); err != nil {
		return fmt.Errorf("unable to delete from ipset: %w", err)
	}
	return nil
}

func (ops *ops) enablePrune() {
	ops.doPrune.Store(true)
}
