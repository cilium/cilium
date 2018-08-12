// Copyright 2018 Authors of Cilium
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

package process

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/shirou/gopsutil/process"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "process")
)

type PID int32

type ProcessContext struct {
	HostPID      PID
	ContainerPID PID

	Binary string

	CmdLine string

	DockerContainerID string

	KernelCommand string

	connections map[string]ConnectContext

	endpoint *endpoint.Endpoint
}

func newProcessContext(hostPID PID) *ProcessContext {
	context := &ProcessContext{
		HostPID:     hostPID,
		connections: map[string]ConnectContext{},
	}

	context.readPIDProcFile()

	p, err := process.NewProcess(int32(hostPID))
	if err != nil {
		log.WithError(err).Debug("Unable to retrieve process information")
	} else {
		context.Binary, _ = p.Exe()
		context.CmdLine, _ = p.Cmdline()
	}

	if context.DockerContainerID != "" {
		context.endpoint = endpointmanager.LookupDockerID(context.DockerContainerID)
	}

	return context
}

func extractContainerID(s string) string {
	return path.Base(s)
}

func (p *ProcessContext) String() string {
	endpoint := "host"
	if p.endpoint != nil {
		endpoint = p.endpoint.StringID()
	}

	return fmt.Sprintf("%-5s %5d %5d %s %s %s",
		endpoint, p.HostPID, p.ContainerPID, p.DockerContainerID, p.Binary, p.CmdLine)
}

func (p *ProcessContext) readPIDProcFile() {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", p.HostPID)
	file, err := os.Open(cgroupPath)
	if err != nil {
		log.WithError(err).WithField("file", cgroupPath).Error("Unable to open cgroup file")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.Contains(s, "/docker") && strings.Contains(s, ":cpu") {
			p.DockerContainerID = extractContainerID(s)
		}
	}

	if err := scanner.Err(); err != nil {
		log.WithError(err).WithField("file", cgroupPath).Error("Unable to parse cgroup file")
	}
}
