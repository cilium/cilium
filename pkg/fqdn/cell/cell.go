// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/fqdn/rules"
)

// Cell provides the FQDN proxy controlplane functionality
var Cell = cell.Module(
	"fqdn",
	"Cell provides the FQDN proxy controlplane functionality",

	// The FQDN NameManager stores DNS mappings.
	namemanager.Cell,

	// The FQDN bootstrap logic
	bootstrap.Cell,

	cell.Provide(rules.NewDNSRulesService),
)
