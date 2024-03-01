// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func newOps(logger logrus.FieldLogger, ipset *ipset, cfg config) reconciler.Operations[*tables.IPSet] {
	return &ops{
		enabled: cfg.NodeIPSetNeeded,
		ipset:   ipset,
	}
}

type ops struct {
	enabled bool
	ipset   *ipset
}

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, s *tables.IPSet, changed *bool) error {
	if !ops.enabled {
		return nil
	}

	// create the set if does not exist
	if err := ops.ipset.create(ctx, s.Name, string(s.Family)); err != nil {
		return err
	}

	cur, err := ops.ipset.list(ctx, s.Name)
	if err != nil {
		return fmt.Errorf("failed to list ips in ipset %s: %w", s.Name, err)
	}

	if s.Addrs.Equal(cur) {
		return nil
	}

	// reconcile the set
	toAdd := s.Addrs.Difference(cur).AsSlice()
	for _, addr := range toAdd {
		if err := ops.ipset.add(ctx, s.Name, addr); err != nil {
			return err
		}
	}
	toDel := cur.Difference(s.Addrs).AsSlice()
	for _, addr := range toDel {
		if err := ops.ipset.del(ctx, s.Name, addr); err != nil {
			return err
		}
	}

	if changed != nil {
		*changed = true
	}

	return nil
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, s *tables.IPSet) error {
	return ops.ipset.remove(ctx, s.Name)
}

func (ops *ops) Prune(ctx context.Context, _ statedb.ReadTxn, _ statedb.Iterator[*tables.IPSet]) error {
	// ipsets not managed by Cilium should not be changed
	return nil
}
