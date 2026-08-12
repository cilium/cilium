// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

const internalEndpointOwner = "internal"

type endpointRulesManager struct {
	logger          *slog.Logger
	db              *statedb.DB
	table           statedb.RWTable[*EndpointRules]
	ipam            *ipam.IPAM
	endpointManager endpointmanager.EndpointManager
	restorer        promise.Promise[endpointstate.Restorer]
	initDone        func(statedb.WriteTxn)

	mu           lock.Mutex
	initializing bool
	// pending holds the latest owner-aware operation for each address while
	// endpoint and IPAM restoration are in progress.
	pending map[netip.Addr]pendingEndpointRules
}

type pendingEndpointRules struct {
	owner      string
	generation uint64
	deleted    bool
}

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
			err = mgr.handleEndpointDeletion(txn, []netip.Addr{address}, pending.owner, pending.generation)
		} else {
			err = mgr.handleEndpointCreation(txn, []netip.Addr{address}, pending.owner, pending.generation)
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
	if !endpointRulesRequired(ep) {
		return
	}

	mgr.handleEvent(endpointAddrs(ep), endpointRulesOwner(ep), ep.GetLifecycleGeneration(), false)
}

func (mgr *endpointRulesManager) EndpointDeleted(ep *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	mgr.handleEvent(endpointAddrs(ep), endpointRulesOwner(ep), ep.GetLifecycleGeneration(), true)
}

func (mgr *endpointRulesManager) EndpointRestored(ep *endpoint.Endpoint) {
	if !endpointRulesRequired(ep) {
		return
	}
	mgr.handleEvent(endpointAddrs(ep), endpointRulesOwner(ep), ep.GetLifecycleGeneration(), false)
}

func (mgr *endpointRulesManager) handleEvent(
	addresses []netip.Addr,
	owner string,
	generation uint64,
	deleted bool,
) {
	if len(addresses) == 0 {
		return
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.initializing {
		mgr.queuePending(addresses, owner, generation, deleted)
		return
	}

	txn := mgr.db.WriteTxn(mgr.table)
	defer txn.Abort()

	var err error
	if deleted {
		err = mgr.handleEndpointDeletion(txn, addresses, owner, generation)
	} else {
		err = mgr.handleEndpointCreation(txn, addresses, owner, generation)
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

// queuePending records the latest desired endpoint generation for each address
// while the initial state is being restored. A deletion from an older
// generation must not overwrite a replacement endpoint that has already
// claimed the address.
func (mgr *endpointRulesManager) queuePending(
	addresses []netip.Addr,
	owner string,
	generation uint64,
	deleted bool,
) {
	for _, address := range addresses {
		current, found := mgr.pending[address]
		// A different owner or generation means that a replacement endpoint
		// now owns this address, so ignore the delayed deletion for the old one.
		if deleted && found && (current.owner != owner || current.generation != generation) {
			continue
		}
		mgr.pending[address] = pendingEndpointRules{
			owner:      owner,
			generation: generation,
			deleted:    deleted,
		}
	}
}

func (mgr *endpointRulesManager) handleEndpointCreation(txn statedb.WriteTxn, addresses []netip.Addr, owner string, generation uint64) error {
	for _, address := range addresses {
		current, _, found := mgr.table.Get(txn, endpointRulesAddressIndex.Query(address))
		if found && current.Owner == owner && current.Generation == generation {
			// This endpoint already owns the desired state.
			continue
		}

		if _, _, err := mgr.table.Insert(txn, &EndpointRules{
			Address:    address,
			Owner:      owner,
			Generation: generation,
			Status:     statedbReconciler.StatusPending(),
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
	generation uint64,
) error {
	for _, address := range addresses {
		current, _, found := mgr.table.Get(txn, endpointRulesAddressIndex.Query(address))
		if !found {
			continue
		}
		// A different owner or generation means that a replacement endpoint
		// now owns this address, so ignore the delayed deletion for the old one.
		if current.Owner != owner || current.Generation != generation {
			continue
		}
		if _, _, err := mgr.table.Delete(txn, current); err != nil {
			return fmt.Errorf("failed to delete desired endpoint routing rules for %s: %w", address, err)
		}
	}
	return nil
}

func endpointRulesRequired(ep *endpoint.Endpoint) bool {
	if ep.IsHost() {
		return false
	}

	if ep.IsProperty(endpointTypes.PropertyFakeEndpoint) {
		return false
	}

	if ep.DatapathConfiguration.ExternalIpam {
		return false
	}

	return true
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

func endpointRulesOwner(ep *endpoint.Endpoint) string {
	if cniAttachmentID := ep.GetCNIAttachmentID(); cniAttachmentID != "" {
		return cniAttachmentID
	}
	return internalEndpointOwner
}
