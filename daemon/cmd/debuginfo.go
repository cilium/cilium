// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

type getDebugInfo struct {
	daemon *Daemon
}

// NewGetDebugInfoHandler returns the debug info endpoint handler for the agent
func NewGetDebugInfoHandler(d *Daemon) restapi.GetDebuginfoHandler {
	return &getDebugInfo{daemon: d}
}

func (h *getDebugInfo) Handle(params restapi.GetDebuginfoParams) middleware.Responder {
	dr := models.DebugInfo{}
	d := h.daemon

	dr.CiliumVersion = version.Version
	if kver, err := version.GetKernelVersion(); err != nil {
		dr.KernelVersion = fmt.Sprintf("Error: %s\n", err)
	} else {
		dr.KernelVersion = fmt.Sprintf("%s", kver)
	}

	status := d.getStatus(false)
	dr.CiliumStatus = &status

	var p endpoint.GetEndpointParams

	dr.EndpointList = d.getEndpointList(p)
	dr.Policy = d.policy.GetRulesList()
	dr.Subsystem = debug.CollectSubsystemStatus()
	dr.CiliumMemoryMap = memoryMap(os.Getpid())

	dr.EnvironmentVariables = []string{}
	for _, k := range Vp.AllKeys() {
		// Assuming we are only getting strings
		v := fmt.Sprintf("%s:%s", k, Vp.GetString(k))
		dr.EnvironmentVariables = append(dr.EnvironmentVariables, v)
	}

	dr.ServiceList = getServiceList(d.svc)

	dr.Encryption = &models.DebugInfoEncryption{}
	if option.Config.EnableWireguard {
		if wgStatus, err := d.datapath.WireguardAgent().Status(true); err == nil {
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
