// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/cast"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/status"
	wireguard "github.com/cilium/cilium/pkg/wireguard/agent"
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

	EndpointManager endpointmanager.EndpointManager
	PolicyRepo      policy.PolicyRepository
	ServiceManager  service.ServiceManager
	WireguardAgent  *wireguard.Agent

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
			serviceManager:  params.ServiceManager,
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
