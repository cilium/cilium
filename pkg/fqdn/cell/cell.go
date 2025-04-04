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

	// The FQDN Message handler
	messagehandler.Cell,

	// GRPC server for the standalone DNS proxy
	service.Cell,

	cell.Provide(rules.NewDNSRulesService),
)
