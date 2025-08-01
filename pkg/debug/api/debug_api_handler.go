// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"os"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/version"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type GetDebuginfoHandler struct {
	endpointManager endpointmanager.EndpointManager
	policyRepo      policy.PolicyRepository
	db              *statedb.DB
	frontends       statedb.Table[*loadbalancer.Frontend]
	wireguardAgent  wgTypes.WireguardAgent

	statusCollector status.StatusCollector

	// read-only map of all the hive settings
	settings cellSettings
}

func (h *GetDebuginfoHandler) Handle(params restapi.GetDebuginfoParams) middleware.Responder {
	dr := models.DebugInfo{}

	dr.CiliumVersion = version.Version
	if kver, err := version.GetKernelVersion(); err != nil {
		dr.KernelVersion = fmt.Sprintf("Error: %s\n", err)
	} else {
		dr.KernelVersion = kver.String()
	}

	status := h.statusCollector.GetStatus(false, true)
	dr.CiliumStatus = &status

	dr.EndpointList = h.endpointManager.GetEndpointList(endpoint.GetEndpointParams{})
	dr.Policy = h.policyRepo.GetRulesList()
	dr.Subsystem = debug.CollectSubsystemStatus()
	dr.CiliumMemoryMap = memoryMap(os.Getpid())

	dr.EnvironmentVariables = []string{}
	for k, v := range h.settings {
		dr.EnvironmentVariables = append(dr.EnvironmentVariables, k+":"+v)
	}

	dr.ServiceList =
		statedb.Collect(
			statedb.Map(
				h.frontends.All(h.db.ReadTxn()),
				(*loadbalancer.Frontend).ToModel,
			),
		)

	dr.Encryption = &models.DebugInfoEncryption{}
	if h.wireguardAgent.Enabled() {
		if wgStatus, err := h.wireguardAgent.Status(true); err == nil {
			dr.Encryption.Wireguard = wgStatus
		}
	}

	return restapi.NewGetDebuginfoOK().WithPayload(&dr)
}

func memoryMap(pid int) string {
	m, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	return string(m)
}
