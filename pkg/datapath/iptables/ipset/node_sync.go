// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"iter"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// IPSetFilterFn is a function allowing to optionally filter out the insertion
// of IPSet entries based on node characteristics. The insertion is performed
// if the function returns false, and skipped otherwise.
type IPSetFilterFn func(*nodeTypes.Node) bool

const nodeIPSetSyncInterval = time.Second

type nodeIPSetManager interface {
	NewInitializer() Initializer
	AddToIPSet(name string, family Family, addrs ...netip.Addr)
	RemoveFromIPSet(name string, addrs ...netip.Addr)
}

type nodeIPSetSync struct {
	db          *statedb.DB
	nodes       statedb.Table[*node.Node]
	manager     nodeIPSetManager
	initializer Initializer
	v4          AddrSet
	v6          AddrSet
	filterFn    IPSetFilterFn
}

type nodeIPSetSyncParams struct {
	cell.In

	Jobs     job.Group
	DB       *statedb.DB
	Nodes    statedb.Table[*node.Node]
	Manager  *manager
	Config   config
	FilterFn IPSetFilterFn `optional:"true"`
}

func registerNodeIPSetSync(p nodeIPSetSyncParams) {
	if !p.Config.NodeIPSetNeeded {
		return
	}

	sync := &nodeIPSetSync{
		db:          p.DB,
		nodes:       p.Nodes,
		manager:     p.Manager,
		initializer: p.Manager.NewInitializer(),
		v4:          AddrSet{},
		v6:          AddrSet{},
		filterFn:    p.FilterFn,
	}
	p.Jobs.Add(job.OneShot("node-ipset-sync", sync.run))
}

func (s *nodeIPSetSync) run(ctx context.Context, health cell.Health) error {
	// Waiting for both the local-cluster and ClusterMesh node listings avoids
	// pruning restored IPSet entries before the complete initial node set is
	// available.
	_, watch := s.nodes.Initialized(s.db.ReadTxn())
	select {
	case <-ctx.Done():
		return nil
	case <-watch:
	}

	// Recompute from a snapshot to naturally account for addresses shared by
	// multiple nodes. Rate limiting coalesces bursts of node table updates.
	limiter := rate.NewLimiter(nodeIPSetSyncInterval, 1)
	defer limiter.Stop()

	for {
		txn := s.db.ReadTxn()
		nodes, watch := s.nodes.AllWatch(txn)
		s.update(nodes)
		s.initializer.InitDone()
		health.OK("Node IP sets synchronized")

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
		if err := limiter.Wait(ctx); err != nil {
			return nil
		}
	}
}

func (s *nodeIPSetSync) update(nodes iter.Seq2[*node.Node, statedb.Revision]) {
	v4, v6 := nodeIPSets(nodes, s.filterFn)

	s.manager.AddToIPSet(
		CiliumNodeIPSetV4,
		INetFamily,
		v4.Difference(s.v4).UnsortedList()...,
	)
	s.manager.AddToIPSet(
		CiliumNodeIPSetV6,
		INet6Family,
		v6.Difference(s.v6).UnsortedList()...,
	)
	s.manager.RemoveFromIPSet(
		CiliumNodeIPSetV4,
		s.v4.Difference(v4).UnsortedList()...,
	)
	s.manager.RemoveFromIPSet(
		CiliumNodeIPSetV6,
		s.v6.Difference(v6).UnsortedList()...,
	)

	s.v4 = v4
	s.v6 = v6
}

func nodeIPSets(
	nodes iter.Seq2[*node.Node, statedb.Revision],
	filterFn IPSetFilterFn,
) (v4, v6 AddrSet) {
	v4 = AddrSet{}
	v6 = AddrSet{}
	for n := range nodes {
		if filterFn != nil && filterFn(&n.Node) {
			continue
		}
		for _, address := range n.IPAddresses {
			if address.Type != addressing.NodeInternalIP {
				continue
			}
			addr, ok := netip.AddrFromSlice(address.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() {
				v4.Insert(addr)
			} else {
				v6.Insert(addr)
			}
		}
	}
	return v4, v6
}
