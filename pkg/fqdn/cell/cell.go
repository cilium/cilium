// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/fqdn/lookup"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/fqdn/rules"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Cell provides the FQDN proxy controlplane functionality
var Cell = cell.Module(
	"fqdn",
	"Cell provides the FQDN proxy controlplane functionality",

	// The FQDN NameManager stores DNS mappings.
	cell.ProvidePrivate(fqdnStateTables),
	cell.Provide(statedb.RWTable[fqdn.EndpointFQDNMapping].ToTable),
	cell.Invoke(registerEndpointFQDNStateCleanup),
	namemanager.Cell,

	lookup.Cell,

	// The FQDN bootstrap logic
	bootstrap.Cell,

	// The FQDN Message handler is responsible for handling DNS messages
	// (requests and responses) sent by the proxy and updating the DNS cache,
	// metrics and policy rules accordingly.
	messagehandler.Cell,

	// GRPC server for the standalone DNS proxy
	// This server is responsible for sending the DNS rules and IP cache updates
	// to the standalone DNS proxy. It also handles the DNS responses
	// from the standalone DNS proxy and updates the DNS rules and IP cache
	// accordingly using the DNSMessageHandler.
	service.Cell,

	cell.Provide(rules.NewDNSRulesService),
)

func fqdnStateTables(db *statedb.DB) (
	statedb.RWTable[fqdn.FQDNMapping],
	statedb.RWTable[fqdn.EndpointFQDNMapping],
	error,
) {
	global, err := fqdn.NewFQDNStateTable(db)
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := fqdn.NewEndpointFQDNStateTable(db)
	if err != nil {
		return nil, nil, err
	}
	return global, endpoint, nil
}

type endpointFQDNStateCleanup struct {
	db     *statedb.DB
	table  statedb.RWTable[fqdn.EndpointFQDNMapping]
	logger *slog.Logger
}

func registerEndpointFQDNStateCleanup(
	lifecycle cell.Lifecycle,
	endpoints endpointmanager.EndpointManager,
	db *statedb.DB,
	table statedb.RWTable[fqdn.EndpointFQDNMapping],
	logger *slog.Logger,
) {
	subscriber := &endpointFQDNStateCleanup{db: db, table: table, logger: logger}
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			endpoints.Subscribe(subscriber)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			endpoints.Unsubscribe(subscriber)
			return nil
		},
	})
}

// Clear any rows from an endpoint ID's previous owner before it can be reused.
func (s *endpointFQDNStateCleanup) EndpointCreated(ep *endpoint.Endpoint) {
	s.clear(ep.ID)
}

func (s *endpointFQDNStateCleanup) EndpointDeleted(ep *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	s.clear(ep.ID)
}

func (s *endpointFQDNStateCleanup) EndpointRestored(*endpoint.Endpoint) {}

func (s *endpointFQDNStateCleanup) clear(id uint16) {
	txn := s.db.WriteTxn(s.table)
	for _, row := range statedb.Collect(s.table.List(txn, fqdn.QueryEndpointFQDNByEndpoint(id))) {
		if _, _, err := s.table.Delete(txn, row); err != nil {
			s.logger.Warn("Unable to remove endpoint FQDN mapping", logfields.Error, err,
				logfields.EndpointID, id)
		}
	}
	txn.Commit()
}
