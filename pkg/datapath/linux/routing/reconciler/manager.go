// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

type endpointRulesManager struct {
	logger          *slog.Logger
	db              *statedb.DB
	table           statedb.RWTable[*EndpointRules]
	ipam            *ipam.IPAM
	endpointManager endpointmanager.EndpointManager
	restorer        promise.Promise[endpointstate.Restorer]
	initDone        func(statedb.WriteTxn)

	mu           sync.Mutex
	initializing bool
	// pending holds the latest owner-aware operation for each address while
	// endpoint and IPAM restoration are in progress.
	pending map[netip.Addr]pendingEndpointRules
}

type pendingEndpointRules struct {
	owner   string
	deleted bool
}

const internalEndpointOwner = "internal"

var _ endpointmanager.Subscriber = (*endpointRulesManager)(nil)

func newEndpointRulesManager(
	logger *slog.Logger,
	db *statedb.DB,
	table statedb.RWTable[*EndpointRules],
	ipam *ipam.IPAM,
	endpointManager endpointmanager.EndpointManager,
	restorer promise.Promise[endpointstate.Restorer],
) *endpointRulesManager {
	txn := db.WriteTxn(table)
	initDone := table.RegisterInitializer(txn, "endpoint-restoration")
	txn.Commit()

	return &endpointRulesManager{
		logger:          logger,
		db:              db,
		table:           table,
		ipam:            ipam,
		endpointManager: endpointManager,
		restorer:        restorer,
		initDone:        initDone,
		initializing:    true,
		pending:         map[netip.Addr]pendingEndpointRules{},
	}
}

func (mgr *endpointRulesManager) initialize(ctx context.Context, health cell.Health) error {
	// Wait until IPAM has restored the routing metadata needed to reconcile endpoint rules.
	if err := mgr.ipam.WaitForRestoreFinished(ctx); err != nil {
		return err
	}

	restorer, err := mgr.restorer.Await(ctx)
	if err != nil {
		return fmt.Errorf("wait for endpoint restorer: %w", err)
	}
	// Wait until every restored endpoint event is queued before enabling pruning.
	if err := restorer.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return fmt.Errorf("wait for endpoint restoration: %w", err)
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	txn := mgr.db.WriteTxn(mgr.table)
	defer txn.Abort()

	for address, pending := range mgr.pending {
		var err error
		if pending.deleted {
			err = mgr.handleEndpointDeletion(txn, []netip.Addr{address}, pending.owner, nil)
		} else {
			err = mgr.handleEndpointCreation(txn, []netip.Addr{address}, pending.owner)
		}
		if err != nil {
			return err
		}
	}
	mgr.initDone(txn)
	txn.Commit()

	mgr.pending = nil
	mgr.initializing = false

	health.OK(fmt.Sprintf("Published desired routing rules for %d endpoint addresses", mgr.table.NumObjects(mgr.db.ReadTxn())))

	return nil
}

func (mgr *endpointRulesManager) EndpointCreated(ep *endpoint.Endpoint) {
	if endpointRulesRequired(ep) {
		mgr.handle(endpointAddrs(ep), endpointRulesOwner(ep), false, nil)
	}
}

func (mgr *endpointRulesManager) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	mgr.handle(endpointAddrs(ep), endpointRulesOwner(ep), true, conf.EndpointOwnsIP)
}

func (mgr *endpointRulesManager) EndpointRestored(ep *endpoint.Endpoint) {
	if endpointRulesRequired(ep) {
		mgr.handle(endpointAddrs(ep), endpointRulesOwner(ep), false, nil)
	}
}

func (mgr *endpointRulesManager) handle(
	addresses []netip.Addr,
	owner string,
	deleted bool,
	endpointOwnsIP func(netip.Addr) bool,
) {
	if len(addresses) == 0 {
		return
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.initializing {
		mgr.queuePending(addresses, owner, deleted, endpointOwnsIP)
		return
	}

	txn := mgr.db.WriteTxn(mgr.table)
	defer txn.Abort()

	var err error
	if deleted {
		err = mgr.handleEndpointDeletion(txn, addresses, owner, endpointOwnsIP)
	} else {
		err = mgr.handleEndpointCreation(txn, addresses, owner)
	}
	if err != nil {
		mgr.logger.Error("Failed to handle endpoint event",
			logfields.Error, err,
			logfields.Addresses, addresses,
		)
		return
	}

	txn.Commit()
}

func endpointRulesOwner(ep *endpoint.Endpoint) string {
	if cniAttachmentID := ep.GetCNIAttachmentID(); cniAttachmentID != "" {
		return cniAttachmentID
	}
	return internalEndpointOwner
}

// queuePending records the latest desired owner for each address while the
// initial state is being restored. A deletion from an older owner must not
// overwrite a replacement endpoint that has already claimed the address.
func (mgr *endpointRulesManager) queuePending(
	addresses []netip.Addr,
	owner string,
	deleted bool,
	endpointOwnsIP func(netip.Addr) bool,
) {
	for _, address := range addresses {
		if deleted && endpointOwnsIP != nil && !endpointOwnsIP(address) {
			continue
		}
		current, found := mgr.pending[address]
		if deleted && found && current.owner != owner {
			continue
		}
		mgr.pending[address] = pendingEndpointRules{
			owner:   owner,
			deleted: deleted,
		}
	}
}

func (mgr *endpointRulesManager) handleEndpointCreation(txn statedb.WriteTxn, addresses []netip.Addr, owner string) error {
	for _, address := range addresses {
		current, _, found := mgr.table.Get(txn, endpointRulesAddressIndex.Query(address))
		if found && current.Owner == owner {
			// This endpoint already owns the desired state.
			continue
		}

		if _, _, err := mgr.table.Insert(txn, &EndpointRules{
			Address: address,
			Owner:   owner,
			Status:  statedbReconciler.StatusPending(),
		}); err != nil {
			return fmt.Errorf("failed to insert desired endpoint routing rules for %s: %w", address, err)
		}
	}
	return nil
}

func (mgr *endpointRulesManager) handleEndpointDeletion(
	txn statedb.WriteTxn,
	addresses []netip.Addr,
	owner string,
	endpointOwnsIP func(netip.Addr) bool,
) error {
	for _, address := range addresses {
		current, _, found := mgr.table.Get(txn, endpointRulesAddressIndex.Query(address))
		if !found || current.Owner != owner {
			continue
		}
		if endpointOwnsIP != nil && !endpointOwnsIP(address) {
			continue
		}
		if _, _, err := mgr.table.Delete(txn, current); err != nil {
			return fmt.Errorf("failed to delete desired endpoint routing rules for %s: %w", address, err)
		}
	}
	return nil
}

func endpointRulesRequired(ep *endpoint.Endpoint) bool {
	return !(ep.IsHost() ||
		ep.IsProperty(endpointTypes.PropertyFakeEndpoint) ||
		ep.DatapathConfiguration.ExternalIpam)
}

func endpointAddrs(ep *endpoint.Endpoint) []netip.Addr {
	addrs := make([]netip.Addr, 0, 2)
	if addr := ep.IPv4Address(); addr.IsValid() {
		addrs = append(addrs, addr)
	}
	if addr := ep.IPv6Address(); addr.IsValid() {
		addrs = append(addrs, addr)
	}
	return addrs
}
