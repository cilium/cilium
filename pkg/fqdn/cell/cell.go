// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/fqdn/rules"
	"github.com/cilium/cilium/pkg/fqdn/service"
)

// Cell provides the FQDN proxy controlplane functionality
var Cell = cell.Module(
	"fqdn",
	"Cell provides the FQDN proxy controlplane functionality",

	// The FQDN NameManager stores DNS mappings.
	namemanager.Cell,

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
