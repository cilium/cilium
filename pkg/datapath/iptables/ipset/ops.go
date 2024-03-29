// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func newOps(logger logrus.FieldLogger, ipset *ipset, cfg config) reconciler.Operations[*tables.IPSetEntry] {
	return &ops{
		enabled: cfg.NodeIPSetNeeded,
		ipset:   ipset,
	}
}

type ops struct {
	enabled bool
	ipset   *ipset
}

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, entry *tables.IPSetEntry, changed *bool) error {
	if !ops.enabled {
		return nil
	}

	// create the set if does not exist
	if err := ops.ipset.create(ctx, entry.Name, string(entry.Family)); err != nil {
		return err
	}

	if err := ops.ipset.add(ctx, entry.Name, entry.Addr); err != nil {
		return err
	}

	if changed != nil {
		*changed = true
	}

	return nil
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, entry *tables.IPSetEntry) error {
	if !ops.enabled {
		return nil
	}

	// check that the set exists
	if _, err := ops.ipset.list(ctx, entry.Name); err != nil {
		return nil
	}
	return ops.ipset.del(ctx, entry.Name, entry.Addr)
}

func (ops *ops) Prune(ctx context.Context, _ statedb.ReadTxn, iter statedb.Iterator[*tables.IPSetEntry]) error {
	if !ops.enabled {
		return nil
	}

	desiredV4Set, desiredV6Set := sets.Set[netip.Addr]{}, sets.Set[netip.Addr]{}
	statedb.ProcessEach(iter, func(obj *tables.IPSetEntry, _ uint64) error {
		if obj.Name == CiliumNodeIPSetV4 {
			desiredV4Set.Insert(obj.Addr)
		} else if obj.Name == CiliumNodeIPSetV6 {
			desiredV6Set.Insert(obj.Addr)
		}
		return nil
	})

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
	for addr := range toDel {
		if err := ipset.del(ctx, name, addr); err != nil {
			return fmt.Errorf("unable to delete addr %s from ipset %s: %w", name, addr, err)
		}
	}

	toAdd := desired.Difference(curSet)
	for addr := range toAdd {
		if err := ipset.add(ctx, name, addr); err != nil {
			return fmt.Errorf("unable to add addr %s from ipset %s: %w", name, addr, err)
		}
	}

	return nil
}
