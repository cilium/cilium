// Copyright 2017-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/version"

	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/viper"
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
	if kver, err := linux.GetKernelVersion(); err != nil {
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
	for _, k := range viper.AllKeys() {
		// Assuming we are only getting strings
		v := fmt.Sprintf("%s:%s", k, viper.GetString(k))
		dr.EnvironmentVariables = append(dr.EnvironmentVariables, v)
	}

	dr.ServiceList = getServiceList(d.svc)

	return restapi.NewGetDebuginfoOK().WithPayload(&dr)
}

func memoryMap(pid int) string {
	m, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	return string(m)
}
