// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"math/rand"
	"net/netip"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

var controlCell = cell.Module(
	"control-plane",
	"Backends control-plane",

	cell.Invoke(registerControl),
)

type controlParams struct {
	cell.In

	Backends  statedb.RWTable[Backend]
	DB        *statedb.DB
	Lifecycle cell.Lifecycle
	Log       logrus.FieldLogger
	Registry  job.Registry
	Scope     cell.Scope
}

func registerControl(p controlParams) {
	g := p.Registry.NewGroup(p.Scope)
	c := &control{p}
	g.Add(job.OneShot("control-loop", c.controlLoop))
	p.Lifecycle.Append(g)
}

type control struct {
	controlParams
}

func (c *control) controlLoop(ctx context.Context, health cell.HealthReporter) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}

		txn := c.DB.WriteTxn(c.Backends)

		switch rand.Intn(3) {
		case 0:
			c.deleteBackend(txn)
		case 1:
			c.mutateBackend(txn)
		case 2:
			c.createBackend(txn)
		}

		txn.Commit()
	}
}

func (c *control) createBackend(txn statedb.WriteTxn) {
	b := Backend{
		ID:   BackendID(uuid.NewString()),
		IP:   randomIP(),
		Port: uint16(rand.Uint32()),
	}
	c.Backends.Insert(txn, b)
}

func (c *control) mutateBackend(txn statedb.WriteTxn) {
	iter, _ := c.Backends.All(txn)
	all := statedb.Collect(iter)
	if len(all) > 0 {
		i := rand.Intn(len(all))
		b := all[i]
		b.Port = uint16(rand.Uint32())
		c.Backends.Insert(txn, b)
	}
}

func (c *control) deleteBackend(txn statedb.WriteTxn) {
	iter, _ := c.Backends.All(txn)
	all := statedb.Collect(iter)
	if len(all) > 0 {
		i := rand.Intn(len(all))
		c.Backends.Delete(txn, all[i])
	}
}

func randomIP() netip.Addr {
	n := rand.Uint32()
	return netip.AddrFrom4([4]byte{
		uint8(n & 0xff),
		uint8(n >> 8),
		uint8(n >> 16),
		uint8(n >> 24),
	})
}
