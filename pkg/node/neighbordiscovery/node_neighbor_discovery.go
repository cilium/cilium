// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbordiscovery

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
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
	Insert(netip.Addr, neighbor.ForwardableIPOwner) error
	Delete(netip.Addr, neighbor.ForwardableIPOwner) error
	FinishInitializer(neighbor.ForwardableIPInitializer)
}

// registerNodeNeighborDiscovery observes the node table if L2 neighbor
// discovery is enabled and maintains the node-owned forwardable IPs.
func registerNodeNeighborDiscovery(
	db *statedb.DB,
	jobs job.Group,
	nodes statedb.Table[*node.Node],
	forwardableIPManager *neighbor.ForwardableIPManager,
	nodeConfigNotifier *config.NodeConfigNotifier,
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
		job.OneShot("node-neighbor-discovery-initializer", observer.finishInitialization),
	)
	return nil
}

type nodeNeighborObserver struct {
	db                   *statedb.DB
	nodes                statedb.Table[*node.Node]
	changes              statedb.ChangeIterator[*node.Node]
	forwardableIPManager forwardableIPManager
	initializer          neighbor.ForwardableIPInitializer

	current map[nodeTypes.Identity]map[netip.Addr]struct{}

	nodesInitialized  chan struct{}
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
		current:              map[nodeTypes.Identity]map[netip.Addr]struct{}{},
		nodesInitialized:     make(chan struct{}),
		configInitialized:    make(chan struct{}),
	}, nil
}

func (o *nodeNeighborObserver) run(ctx context.Context, _ cell.Health) error {
	defer o.changes.Close()

	limiter := rate.NewLimiter(changeRateLimit, 1)
	defer limiter.Stop()

	nodesInitialized := false
	for {
		txn := o.db.ReadTxn()
		changes, watch := o.changes.Next(txn)
		for change := range changes {
			if err := o.apply(change); err != nil {
				return err
			}
		}

		var initWatch <-chan struct{}
		if !nodesInitialized {
			initialized, watch := o.nodes.Initialized(txn)
			if initialized {
				nodesInitialized = true
				close(o.nodesInitialized)
			} else {
				initWatch = watch
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		case <-initWatch:
		}
		if err := limiter.Wait(ctx); err != nil {
			return nil
		}
	}
}

func (o *nodeNeighborObserver) apply(change statedb.Change[*node.Node]) error {
	n := change.Object
	id := n.Identity()
	oldIPs := o.current[id]
	newIPs := nodeIPs(n)
	if change.Deleted || n.Local != nil {
		newIPs = nil
	}
	if maps.Equal(oldIPs, newIPs) {
		return nil
	}

	owner := neighbor.ForwardableIPOwner{
		Type: neighbor.ForwardableIPOwnerNode,
		ID:   id.String(),
	}
	var errs error
	for ip := range oldIPs {
		if _, found := newIPs[ip]; found {
			continue
		}
		if err := o.forwardableIPManager.Delete(ip, owner); err != nil {
			errs = errors.Join(errs, fmt.Errorf("deleting forwardable IP for node %s: %w", id, err))
		}
	}
	for ip := range newIPs {
		if _, found := oldIPs[ip]; found {
			continue
		}
		if err := o.forwardableIPManager.Insert(ip, owner); err != nil {
			errs = errors.Join(errs, fmt.Errorf("inserting forwardable IP for node %s: %w", id, err))
		}
	}
	if errs != nil {
		return errs
	}

	if len(newIPs) == 0 {
		delete(o.current, id)
	} else {
		o.current[id] = newIPs
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

func (o *nodeNeighborObserver) finishInitialization(ctx context.Context, _ cell.Health) error {
	select {
	case <-ctx.Done():
		return nil
	case <-o.nodesInitialized:
	}
	select {
	case <-ctx.Done():
		return nil
	case <-o.configInitialized:
	}

	o.forwardableIPManager.FinishInitializer(o.initializer)
	return nil
}

func (o *nodeNeighborObserver) NodeConfigurationChanged(config.Config) error {
	o.configInitOnce.Do(func() { close(o.configInitialized) })
	return nil
}
