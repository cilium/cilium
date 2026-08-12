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

type endpointRulesManager struct {
	logger *slog.Logger
	db     *statedb.DB
	table  statedb.RWTable[*EndpointRules]
}

const internalEndpointOwner = "internal"

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
