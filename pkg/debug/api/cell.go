// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/cast"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/status"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Cell provides the Debug-Info API handler
var Cell = cell.Module(
	"debuginfo-api",
	"Debuginfo API handler",

	cell.Provide(newDebugAPIHandler),

	// Provide a read-only copy of the current daemon settings to be consumed
	// by the debuginfo API
	cell.ProvidePrivate(daemonSettings),
)

type debugAPIHandlerParams struct {
	cell.In

	DB              *statedb.DB
	Frontends       statedb.Table[*loadbalancer.Frontend]
	EndpointManager endpointmanager.EndpointManager
	PolicyRepo      policy.PolicyRepository
	WireguardAgent  wgTypes.WireguardAgent

	StatusCollector status.StatusCollector
	CellSettings    cellSettings
}

type debugAPIHandlerOut struct {
	cell.Out

	GetDebuginfoHandler restapi.GetDebuginfoHandler
}

func newDebugAPIHandler(params debugAPIHandlerParams) debugAPIHandlerOut {
	return debugAPIHandlerOut{
		GetDebuginfoHandler: &GetDebuginfoHandler{
			endpointManager: params.EndpointManager,
			policyRepo:      params.PolicyRepo,
			db:              params.DB,
			frontends:       params.Frontends,
			wireguardAgent:  params.WireguardAgent,
			statusCollector: params.StatusCollector,
			settings:        params.CellSettings,
		},
	}
}

type cellSettings map[string]string

func daemonSettings(settings cell.AllSettings) cellSettings {
	m := make(map[string]string, len(settings))
	for k, v := range settings {
		m[k] = cast.ToString(v)
	}
	return m
}
