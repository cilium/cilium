// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const internalEndpointOwner = "internal"

type endpointRulesManager struct {
	logger *slog.Logger
	db     *statedb.DB
	table  statedb.RWTable[*EndpointRules]
}

var _ endpointmanager.Subscriber = (*endpointRulesManager)(nil)

func newEndpointRulesManager(
	logger *slog.Logger,
	db *statedb.DB,
	table statedb.RWTable[*EndpointRules],
) *endpointRulesManager {
	return &endpointRulesManager{
		logger: logger,
		db:     db,
		table:  table,
	}
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
