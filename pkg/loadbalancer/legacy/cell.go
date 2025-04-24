// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package legacy

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/loadbalancer/legacy/redirectpolicy"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
)

var Cell = cell.Module(
	"loadbalancer-legacy",
	"Old load-balancing control-plane",

	// Redirect policy manages the Local Redirect Policies.
	redirectpolicy.Cell,

	// Service is a datapath service handler. Its main responsibility is to reflect
	// service-related changes into BPF maps used by datapath BPF programs.
	service.Cell,
)
