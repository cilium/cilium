// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/cell"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
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

	Svc      service.ServiceManager
	SvcCache *k8s.ServiceCache
	Lpr      agentK8s.LocalPodResource
	Ep       endpointmanager.EndpointManager
}

func newLRPManager(params lrpManagerParams) *Manager {
	return NewRedirectPolicyManager(params.Svc, params.SvcCache, params.Lpr, params.Ep)
}
