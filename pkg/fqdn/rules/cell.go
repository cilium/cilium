// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rules

import "github.com/cilium/hive/cell"

// Cell provides the DNSRulesService
var Cell = cell.Module(
	"fqdn-dns-rules-service",
	"Cell provides the DNSRulesService",

	cell.Provide(newDNSRulesService),
)
