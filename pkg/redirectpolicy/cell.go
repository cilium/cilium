// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides access to the Local Redirect Policy Manager.
var Cell = cell.Module(
	"lrp-manager",
	"LRP Manager",

	cell.Provide(newLRPManager),
)

type lrpManagerParams struct {
	cell.In

	Svc service.ServiceManager
	Lpr agentK8s.LocalPodResource
}

func newLRPManager(params lrpManagerParams) *Manager {
	return NewRedirectPolicyManager(params.Svc, params.Lpr)
}
