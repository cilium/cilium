// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbordiscovery

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"node-neighbor-discovery",
	"Observes nodes to manage forwardable IPs for the cluster",
	cell.Invoke(registerNodeNeighborDiscovery),
)

const changeRateLimit = 50 * time.Millisecond

type forwardableIPManager interface {
	Set(neighbor.ForwardableIPOwner, iter.Seq[netip.Addr]) error
	FinishInitializer(neighbor.ForwardableIPInitializer)
}

// registerNodeNeighborDiscovery observes the node table if L2 neighbor
// discovery is enabled and maintains the node-owned forwardable IPs.
func registerNodeNeighborDiscovery(
	db *statedb.DB,
	jobs job.Group,
	nodes statedb.Table[*node.Node],
	forwardableIPManager *neighbor.ForwardableIPManager,
	nodeConfigNotifier *manager.NodeConfigNotifier,
) error {
	if !forwardableIPManager.Enabled() {
		return nil
	}

	initializer := forwardableIPManager.RegisterInitializer("node-neighbor-discovery")
	observer, err := newNodeNeighborObserver(db, nodes, forwardableIPManager, initializer)
	if err != nil {
		return fmt.Errorf("creating node change iterator: %w", err)
	}

	nodeConfigNotifier.Subscribe(observer)
	jobs.Add(
		job.OneShot("node-neighbor-discovery", observer.run),
	)
	return nil
}

type nodeNeighborObserver struct {
	db                   *statedb.DB
	nodes                statedb.Table[*node.Node]
	changes              statedb.ChangeIterator[*node.Node]
	forwardableIPManager forwardableIPManager
	initializer          neighbor.ForwardableIPInitializer

	configInitialized chan struct{}
	configInitOnce    sync.Once
}

var _ config.ChangeHandler = (*nodeNeighborObserver)(nil)

func newNodeNeighborObserver(
	db *statedb.DB,
	nodes statedb.Table[*node.Node],
	forwardableIPManager forwardableIPManager,
	initializer neighbor.ForwardableIPInitializer,
) (*nodeNeighborObserver, error) {
	wtxn := db.WriteTxn(nodes)
	changes, err := nodes.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return nil, err
	}

	return &nodeNeighborObserver{
		db:                   db,
		nodes:                nodes,
		changes:              changes,
		forwardableIPManager: forwardableIPManager,
		initializer:          initializer,
		configInitialized:    make(chan struct{}),
	}, nil
}

func (o *nodeNeighborObserver) run(ctx context.Context, _ cell.Health) error {
	defer o.changes.Close()

	limiter := rate.NewLimiter(changeRateLimit, 1)
	defer limiter.Stop()

	txn := o.db.ReadTxn()
	_, initWatch := o.nodes.Initialized(txn)
	configWatch := o.configInitialized
	initDone := false

	for {
		changes, watch := o.changes.Next(txn)
		for change := range changes {
			if err := o.apply(change); err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		case <-initWatch:
			initWatch = nil
		case <-configWatch:
			configWatch = nil
		}

		if !initDone && initWatch == nil && configWatch == nil {
			initDone = true
			o.forwardableIPManager.FinishInitializer(o.initializer)
		}

		if err := limiter.Wait(ctx); err != nil {
			return nil
		}

		txn = o.db.ReadTxn()
	}
}

func (o *nodeNeighborObserver) apply(change statedb.Change[*node.Node]) error {
	n := change.Object
	id := n.Identity()
	ips := nodeIPs(n)
	if change.Deleted || n.Local != nil {
		ips = nil
	}

	owner := neighbor.ForwardableIPOwner{
		Type: neighbor.ForwardableIPOwnerNode,
		ID:   id.String(),
	}
	if err := o.forwardableIPManager.Set(owner, maps.Keys(ips)); err != nil {
		return fmt.Errorf("setting forwardable IPs for node %s: %w", id, err)
	}
	return nil
}

func nodeIPs(n *node.Node) map[netip.Addr]struct{} {
	ips := map[netip.Addr]struct{}{}
	for _, ipv6 := range []bool{false, true} {
		if ip, ok := netip.AddrFromSlice(n.GetNodeIP(ipv6)); ok {
			ips[ip.Unmap()] = struct{}{}
		}
	}
	return ips
}

func (o *nodeNeighborObserver) NodeConfigurationChanged(config.Config) error {
	o.configInitOnce.Do(func() { close(o.configInitialized) })
	return nil
}
