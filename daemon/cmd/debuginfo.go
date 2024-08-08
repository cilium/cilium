// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/cast"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/version"
)

func getDebugInfoHandler(d *Daemon, params restapi.GetDebuginfoParams) middleware.Responder {
	dr := models.DebugInfo{}

	dr.CiliumVersion = version.Version
	if kver, err := version.GetKernelVersion(); err != nil {
		dr.KernelVersion = fmt.Sprintf("Error: %s\n", err)
	} else {
		dr.KernelVersion = kver.String()
	}

	status := d.getStatus(false)
	dr.CiliumStatus = &status

	var p endpoint.GetEndpointParams

	dr.EndpointList = d.getEndpointList(p)
	dr.Policy = d.policy.GetRulesList()
	dr.Subsystem = debug.CollectSubsystemStatus()
	dr.CiliumMemoryMap = memoryMap(os.Getpid())

	dr.EnvironmentVariables = []string{}
	for k, v := range d.settings {
		dr.EnvironmentVariables = append(dr.EnvironmentVariables, k+":"+v)
	}

	dr.ServiceList = service.GetServiceModelList(d.svc)

	dr.Encryption = &models.DebugInfoEncryption{}
	if option.Config.EnableWireguard {
		if wgStatus, err := d.wireguardAgent.Status(true); err == nil {
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

type cellSettings map[string]string

func daemonSettings(settings cell.AllSettings) cellSettings {
	m := make(map[string]string, len(settings))
	for k, v := range settings {
		m[k] = cast.ToString(v)
	}
	return m
}
